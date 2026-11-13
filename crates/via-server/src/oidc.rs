//! Checking GitHub Actions' OIDC ID tokens.
//!
//! A workflow with `id-token: write` can ask GitHub for a short-lived JWT
//! that says which repository, ref and run it is, signed with a key GitHub
//! publishes. Accepting that instead of an API token means no secret is
//! stored in the repository, and none can leak from it.
//!
//! Keys are fetched from the issuer's JWKS and kept. A token signed with a key
//! we don't have makes us fetch again, at most once a minute, so GitHub can
//! rotate keys without a restart and a stream of made-up key ids can't make
//! us hammer it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// How long fetched keys are trusted before they are fetched again, so a key
/// GitHub withdraws stops working here too.
const KEYS_LAST: Duration = Duration::from_secs(3600);
/// The least time between two fetches prompted by an unknown key id.
const REFETCH_AFTER: Duration = Duration::from_secs(60);
/// Clocks on runners and here differ a little.
const LEEWAY_SECS: u64 = 60;

/// The claims of GitHub's token this server reads. GitHub sends more.
#[derive(Debug, Clone, Deserialize)]
pub struct GithubClaims {
    /// `owner/name`.
    pub repository: String,
    /// The repository's number, which a rename or a new repository under
    /// an old name doesn't keep.
    pub repository_id: String,
    /// e.g. `refs/heads/via` or `refs/tags/v3`.
    #[serde(rename = "ref")]
    pub git_ref: String,
    #[serde(default)]
    pub sha: String,
    #[serde(default)]
    pub run_id: String,
}

pub struct Verifier {
    issuer: String,
    jwks_url: String,
    http: reqwest::Client,
    keys: tokio::sync::Mutex<Keys>,
}

#[derive(Default)]
struct Keys {
    by_kid: HashMap<String, DecodingKey>,
    fetched: Option<Instant>,
}

impl Verifier {
    pub fn github() -> Self {
        Self::new(GITHUB_ISSUER, &format!("{GITHUB_ISSUER}/.well-known/jwks"))
    }

    pub fn new(issuer: &str, jwks_url: &str) -> Self {
        Self {
            issuer: issuer.into(),
            jwks_url: jwks_url.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            keys: Default::default(),
        }
    }

    /// The token's claims, if GitHub signed it for `audience` and it is
    /// current.
    pub async fn verify(&self, token: &str, audience: &str) -> Result<GithubClaims> {
        let header = jsonwebtoken::decode_header(token).context("not a JWT")?;
        // Only what GitHub signs with: never `none`, never an HMAC keyed with
        // a public key.
        if header.alg != Algorithm::RS256 {
            bail!("tokens must be RS256, not {:?}", header.alg);
        }
        let kid = header.kid.context("the token names no key")?;
        let key = self.key(&kid).await?;
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[&self.issuer]);
        v.set_audience(&[audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud"]);
        v.validate_nbf = true;
        v.leeway = LEEWAY_SECS;
        let data = jsonwebtoken::decode::<GithubClaims>(token, &key, &v)
            .map_err(|e| anyhow::anyhow!("the token was refused: {e}"))?;
        Ok(data.claims)
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey> {
        let mut keys = self.keys.lock().await;
        let age = keys.fetched.map(|t| t.elapsed());
        let stale = age.is_none_or(|a| a > KEYS_LAST);
        let unknown = !keys.by_kid.contains_key(kid) && age.is_none_or(|a| a > REFETCH_AFTER);
        if stale || unknown {
            match self.fetch().await {
                Ok(fresh) => {
                    keys.by_kid = fresh;
                    keys.fetched = Some(Instant::now());
                }
                // Keep what we had: a blip at GitHub shouldn't stop releases
                // signed with keys we already know.
                Err(e) => tracing::warn!("fetching {} failed: {e:#}", self.jwks_url),
            }
        }
        keys.by_kid
            .get(kid)
            .cloned()
            .with_context(|| format!("{kid:?} is not one of {}'s keys", self.issuer))
    }

    async fn fetch(&self) -> Result<HashMap<String, DecodingKey>> {
        let set: JwkSet = self
            .http
            .get(&self.jwks_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(set
            .keys
            .iter()
            .filter_map(|k| Some((k.common.key_id.clone()?, DecodingKey::from_jwk(k).ok()?)))
            .collect())
    }
}

/// Whether a bearer token is a JWT rather than one of ours, which are hex or
/// carry a prefix and never contain dots.
pub fn looks_like_jwt(token: &str) -> bool {
    token.starts_with("eyJ") && token.matches('.').count() == 2
}

#[cfg(test)]
pub mod testing {
    //! A key of our own and a JWKS server that publishes it, standing in for
    //! GitHub.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};
    use axum::Json;
    use axum::routing::get;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use serde_json::{Value, json};

    pub struct Issuer {
        pub url: String,
        pub key: aws_lc_rs::rsa::KeyPair,
        pub kid: String,
        /// How many times the JWKS was fetched.
        pub fetches: Arc<AtomicUsize>,
    }

    impl Issuer {
        pub async fn start() -> Self {
            let key = aws_lc_rs::rsa::KeyPair::generate(KeySize::Rsa2048).unwrap();
            let public = key.public_key();
            let jwk = json!({
                "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key",
                "n": B64.encode(public.modulus().big_endian_without_leading_zero()),
                "e": B64.encode(public.exponent().big_endian_without_leading_zero()),
            });
            let fetches = Arc::new(AtomicUsize::new(0));
            let counted = fetches.clone();
            let app = axum::Router::new().route(
                "/.well-known/jwks",
                get(move || {
                    counted.fetch_add(1, Ordering::SeqCst);
                    let jwk = jwk.clone();
                    async move { Json(json!({ "keys": [jwk] })) }
                }),
            );
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(l, app).await });
            Self {
                url,
                key,
                kid: "test-key".into(),
                fetches,
            }
        }

        pub fn verifier(&self) -> super::Verifier {
            super::Verifier::new(&self.url, &format!("{}/.well-known/jwks", self.url))
        }

        /// Claims as GitHub would send them for a push to `git_ref`.
        pub fn claims(&self, audience: &str, repo: &str, repo_id: &str, git_ref: &str) -> Value {
            let now = crate::db::now();
            json!({
                "iss": self.url, "aud": audience, "iat": now, "nbf": now - 5, "exp": now + 300,
                "sub": format!("repo:{repo}:ref:{git_ref}"),
                "repository": repo, "repository_id": repo_id,
                "repository_owner": repo.split('/').next().unwrap(),
                "ref": git_ref, "sha": "abc123", "run_id": "42", "event_name": "push",
            })
        }

        pub fn sign(&self, claims: &Value) -> String {
            self.sign_as(&self.kid, claims)
        }

        pub fn sign_as(&self, kid: &str, claims: &Value) -> String {
            let header = json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
            let input = format!(
                "{}.{}",
                B64.encode(header.to_string()),
                B64.encode(claims.to_string())
            );
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let mut sig = vec![0; self.key.public_modulus_len()];
            self.key
                .sign(&RSA_PKCS1_SHA256, &rng, input.as_bytes(), &mut sig)
                .unwrap();
            format!("{input}.{}", B64.encode(sig))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::testing::Issuer;
    use super::*;

    const AUD: &str = "https://via.example.com";

    #[tokio::test]
    async fn a_token_is_checked_against_the_issuers_keys() {
        let gh = Issuer::start().await;
        let v = gh.verifier();
        let good = gh.claims(AUD, "acme/app", "7", "refs/heads/via");
        let c = v.verify(&gh.sign(&good), AUD).await.unwrap();
        assert_eq!(
            (c.repository.as_str(), c.repository_id.as_str()),
            ("acme/app", "7")
        );
        assert_eq!(c.git_ref, "refs/heads/via");

        let refused = |claims: serde_json::Value| {
            let t = gh.sign(&claims);
            let v = &v;
            async move { v.verify(&t, AUD).await.unwrap_err().to_string() }
        };
        let mut wrong_aud = good.clone();
        wrong_aud["aud"] = "https://elsewhere.example.com".into();
        assert!(refused(wrong_aud).await.contains("InvalidAudience"));
        let mut wrong_iss = good.clone();
        wrong_iss["iss"] = "https://token.example.com".into();
        assert!(refused(wrong_iss).await.contains("InvalidIssuer"));
        let mut expired = good.clone();
        expired["exp"] = (crate::db::now() - 120).into();
        assert!(refused(expired).await.contains("ExpiredSignature"));
        let mut early = good.clone();
        early["nbf"] = (crate::db::now() + 600).into();
        assert!(refused(early).await.contains("ImmatureSignature"));

        // Within the leeway is fine.
        let mut just = good.clone();
        just["exp"] = (crate::db::now() - 10).into();
        v.verify(&gh.sign(&just), AUD).await.unwrap();

        // A signature that doesn't match its claims.
        let t = gh.sign(&good);
        let (front, sig) = t.rsplit_once('.').unwrap();
        let other = gh.sign(&gh.claims(AUD, "acme/other", "8", "refs/heads/via"));
        let forged = format!("{}.{sig}", other.rsplit_once('.').unwrap().0);
        assert!(v.verify(&forged, AUD).await.is_err());
        assert!(v.verify(&format!("{front}.AAAA"), AUD).await.is_err());
    }

    #[tokio::test]
    async fn keys_are_kept_and_an_unknown_one_is_fetched_once() {
        let gh = Issuer::start().await;
        let v = gh.verifier();
        let claims = gh.claims(AUD, "acme/app", "7", "refs/heads/via");
        for _ in 0..3 {
            v.verify(&gh.sign(&claims), AUD).await.unwrap();
        }
        assert_eq!(gh.fetches.load(Ordering::SeqCst), 1);
        // Unknown: GitHub may have rotated, so ask; but not on every request.
        for _ in 0..3 {
            let e = v
                .verify(&gh.sign_as("rotated", &claims), AUD)
                .await
                .unwrap_err();
            assert!(e.to_string().contains("not one of"), "{e}");
        }
        assert_eq!(gh.fetches.load(Ordering::SeqCst), 1);
        v.keys.lock().await.fetched = Some(Instant::now() - REFETCH_AFTER * 2);
        assert!(
            v.verify(&gh.sign_as("rotated", &claims), AUD)
                .await
                .is_err()
        );
        assert_eq!(gh.fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn only_rs256_is_accepted() {
        use base64::Engine;
        let gh = Issuer::start().await;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let claims = gh.claims(AUD, "acme/app", "7", "refs/heads/via");
        let unsigned = format!(
            "{}.{}.",
            b64.encode(r#"{"alg":"none","kid":"test-key"}"#),
            b64.encode(claims.to_string())
        );
        assert!(gh.verifier().verify(&unsigned, AUD).await.is_err());
        let hmac = format!(
            "{}.{}.AAAA",
            b64.encode(r#"{"alg":"HS256","kid":"test-key"}"#),
            b64.encode(claims.to_string())
        );
        let e = gh.verifier().verify(&hmac, AUD).await.unwrap_err();
        assert!(e.to_string().contains("RS256"), "{e}");
        assert!(looks_like_jwt(&gh.sign(&claims)));
        assert!(!looks_like_jwt("vis_abc"));
        assert!(!looks_like_jwt(&"a".repeat(64)));
    }
}
