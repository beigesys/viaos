//! The OAuth 2.1 server MCP clients sign in through, so connecting Claude
//! takes a browser and a GitHub account instead of a pasted token.
//!
//! In the order a client meets it:
//!
//! 1. `/mcp` answers 401 with a pointer to `/.well-known/…`, which says where
//!    the rest is.
//! 2. `/register`: a client registers itself. That grants nothing. It fixes
//!    where a code may later be sent.
//! 3. `/authorize` sends the browser to GitHub, every time. GitHub's answer
//!    says who this is and what they may do, as for the console.
//! 4. `/connect`, a page of the console, shows who is asking and where the
//!    answer goes. GitHub signs people in without asking twice, so without
//!    this a link could hand someone's access to whoever registered it.
//! 5. `/token` trades the code, with PKCE proof, for an access token good for
//!    an hour and on `/mcp` alone, and a refresh token.
//!
//! The GitHub token is kept, sealed, so every refresh can ask GitHub again:
//! someone removed from the organisation is out within the hour. A refresh
//! token spent twice was copied, so that ends the whole connection. An admin
//! can end one at any time with `revoke_connection`.
//!
//! Without GitHub sign-in none of this exists, and `/mcp` takes API tokens.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Query, State as AxState};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Json, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::State;
use crate::access::Access;
use crate::db::{OAuthRefresh, Role, hash};
use crate::github::{self, encode};

pub const ACCESS_PREFIX: &str = "viam_";
pub const ACCESS_SECS: i64 = 3600;
pub const REFRESH_SECS: i64 = 30 * 24 * 3600;
/// How long someone has from `/authorize` to answering the consent page.
pub const REQUEST_SECS: i64 = 600;
const CODE_SECS: i64 = 60;
pub const CONSENT_COOKIE: &str = "via_consent";
const MAX_REDIRECT_URIS: usize = 16;
const MAX_URI_LEN: usize = 1024;
const MAX_NAME_LEN: usize = 120;
const MAX_PARAM_LEN: usize = 1024;

/// Sealed GitHub tokens shouldn't sit in rows that have expired.
pub async fn tidy(s: Arc<State>) {
    let mut every = tokio::time::interval(std::time::Duration::from_secs(600));
    loop {
        every.tick().await;
        if let Err(e) = s.db.oauth_sweep() {
            tracing::warn!("tidying OAuth rows: {e:#}");
        }
    }
}

fn resource(s: &State) -> String {
    format!("{}/mcp", s.public_url)
}

/// What a 401 from `/mcp` says, so a client can find its way to sign in.
pub fn challenge(s: &State) -> Option<HeaderValue> {
    s.github.as_ref()?;
    HeaderValue::from_str(&format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
        s.public_url
    ))
    .ok()
}

pub async fn protected_resource(AxState(s): AxState<Arc<State>>) -> Response {
    if s.github.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(json!({
        "resource": resource(&s),
        "authorization_servers": [s.public_url],
        "bearer_methods_supported": ["header"],
    }))
    .into_response()
}

pub async fn authorization_server(AxState(s): AxState<Arc<State>>) -> Response {
    if s.github.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let base = &s.public_url;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "registration_endpoint": format!("{base}/register"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        // Every client is public: PKCE ties a code to it, not a secret it
        // would have to keep somewhere.
        "token_endpoint_auth_methods_supported": ["none"],
    }))
    .into_response()
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Where a code may go: anywhere over HTTPS, or to a program on the person's
/// own machine. Plain HTTP anywhere else puts it on the wire in the clear,
/// and any app can claim a custom scheme.
fn redirect_allowed(uri: &str) -> bool {
    let Ok(parsed) = uri.parse::<Uri>() else {
        return false;
    };
    let Some(host) = parsed.host() else {
        return false;
    };
    !uri.contains('#')
        && match parsed.scheme_str() {
            Some("https") => true,
            Some("http") => is_loopback(host),
            _ => false,
        }
}

/// An exact match, except that a loopback redirect may use any port: a
/// program binds whichever is free when it starts (RFC 8252 §7.3).
fn redirect_matches(registered: &str, presented: &str) -> bool {
    if registered == presented {
        return true;
    }
    let (Ok(a), Ok(b)) = (registered.parse::<Uri>(), presented.parse::<Uri>()) else {
        return false;
    };
    a.scheme_str() == Some("http")
        && b.scheme_str() == Some("http")
        && a.host().is_some_and(is_loopback)
        && a.host() == b.host()
        && a.path() == b.path()
        && a.query() == b.query()
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct Registration {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
}

/// RFC 7591, open to anyone. The id it hands back can do nothing until a
/// person consents to it, and goes away if nobody does.
pub async fn register(AxState(s): AxState<Arc<State>>, Json(r): Json<Registration>) -> Response {
    if s.github.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let uris = &r.redirect_uris;
    if uris.is_empty()
        || uris.len() > MAX_REDIRECT_URIS
        || uris
            .iter()
            .any(|u| u.len() > MAX_URI_LEN || !redirect_allowed(u))
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    }
    let name = r
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(|n| n.chars().take(MAX_NAME_LEN).collect::<String>());
    match s.db.oauth_add_client(name.as_deref(), uris) {
        Ok(id) => (
            StatusCode::CREATED,
            Json(json!({
                "client_id": id,
                "client_name": name,
                "redirect_uris": uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!("registering a client: {e:#}");
            oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
    }
}

#[derive(Deserialize)]
pub struct Authorize {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    resource: Option<String>,
}

fn with_query(base: &str, pairs: &[(&str, &str)]) -> String {
    let mut url = base.to_string();
    let mut sep = if base.contains('?') { '&' } else { '?' };
    for (k, v) in pairs {
        url.push(sep);
        url.push_str(k);
        url.push('=');
        url.push_str(&encode(v));
        sep = '&';
    }
    url
}

fn answer(redirect_uri: &str, key: &str, value: &str, state: Option<&str>) -> String {
    let mut pairs = vec![(key, value)];
    if let Some(state) = state {
        pairs.push(("state", state));
    }
    with_query(redirect_uri, &pairs)
}

pub async fn authorize(AxState(s): AxState<Arc<State>>, Query(q): Query<Authorize>) -> Response {
    let Some(g) = &s.github else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Nothing goes to a redirect the client didn't register. Anyone can
    // register one, so that is all this promises: the rest of the request is
    // refused there, as OAuth says to, and a code goes there only on a yes.
    let client = s.db.oauth_client(&q.client_id).ok().flatten();
    let Some(client) = client else {
        return (StatusCode::BAD_REQUEST, "Unknown client. Connect again.").into_response();
    };
    if !client
        .redirect_uris
        .iter()
        .any(|r| redirect_matches(r, &q.redirect_uri))
    {
        return (
            StatusCode::BAD_REQUEST,
            "This client did not register that redirect address.",
        )
            .into_response();
    }
    let refuse = |error: &str| {
        Redirect::to(&answer(&q.redirect_uri, "error", error, q.state.as_deref())).into_response()
    };
    if q.response_type != "code" {
        return refuse("unsupported_response_type");
    }
    if q.state.as_deref().is_some_and(|v| v.len() > MAX_PARAM_LEN)
        || q.code_challenge
            .as_deref()
            .is_some_and(|v| v.len() > MAX_PARAM_LEN)
    {
        return refuse("invalid_request");
    }
    let challenge = match (
        q.code_challenge.as_deref(),
        q.code_challenge_method.as_deref(),
    ) {
        (Some(c), Some("S256")) if !c.is_empty() => c,
        _ => return refuse("invalid_request"),
    };
    if q.resource
        .as_deref()
        .is_some_and(|r| r.trim_end_matches('/') != resource(&s))
    {
        return refuse("invalid_target");
    }
    let id = match s.db.oauth_begin(
        &q.client_id,
        &q.redirect_uri,
        q.state.as_deref(),
        challenge,
        REQUEST_SECS,
    ) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("starting a connection: {e:#}");
            return refuse("server_error");
        }
    };
    github::send_to_github(&s, g, &id)
}

/// What the consent page shows. The host is proven, because the code can go
/// nowhere else; the name is only what the client says it is.
pub async fn pending(AxState(s): AxState<Arc<State>>, headers: HeaderMap) -> Response {
    let Some(id) = github::cookie(&headers, CONSENT_COOKIE) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match s.db.oauth_pending(id) {
        Ok(Some(p)) => {
            let uri = p.redirect_uri.parse::<Uri>().ok();
            let host = uri.as_ref().and_then(|u| u.host()).unwrap_or_default();
            // With its port: https://claude.ai:8443 is someone else.
            let shown = uri
                .as_ref()
                .and_then(|u| u.authority())
                .map_or("", |a| a.as_str());
            (
                [(header::CACHE_CONTROL, "no-store")],
                Json(json!({
                    "request": hash(id),
                    "client": p.client_name,
                    "local": is_loopback(host),
                    "host": shown,
                    "who": p.caller.name,
                    "admin": p.caller.role == Role::Admin,
                })),
            )
                .into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
pub struct Decision {
    /// Which request the page showed. The cookie alone isn't enough: another
    /// sign-in can replace it behind a page still showing the first.
    request: String,
    allow: bool,
}

/// The cookie is Lax, so another site can't post this for someone, and the
/// JSON body means a form couldn't either.
pub async fn decide(
    AxState(s): AxState<Arc<State>>,
    headers: HeaderMap,
    Json(d): Json<Decision>,
) -> Response {
    if !crate::same_origin(&headers) {
        return (StatusCode::FORBIDDEN, "cross-origin request").into_response();
    }
    let Some(id) = github::cookie(&headers, CONSENT_COOKIE) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if hash(id) != d.request {
        return (StatusCode::CONFLICT, "another sign-in replaced this one").into_response();
    }
    let p = match s.db.oauth_pending(id) {
        Ok(Some(p)) => p,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let to = if d.allow {
        match s.db.oauth_approve(id, CODE_SECS) {
            Ok(code) => {
                s.db.audit(
                    &p.caller.name,
                    "connect_client",
                    &json!({ "client": p.client_name, "redirect_uri": p.redirect_uri }),
                    true,
                );
                answer(&p.redirect_uri, "code", &code, p.state.as_deref())
            }
            Err(e) => {
                tracing::error!("approving a connection: {e:#}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        let _ = s.db.oauth_forget(id);
        answer(
            &p.redirect_uri,
            "error",
            "access_denied",
            p.state.as_deref(),
        )
    };
    let clear = format!(
        "{CONSENT_COOKIE}=; Path=/oauth; HttpOnly; SameSite=Lax; Max-Age=0{}",
        github::secure(&s)
    );
    (
        [(header::SET_COOKIE, clear)],
        Json(json!({ "redirect": to })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    client_id: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge
}

fn tokens(access: String, refresh: String) -> Response {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_SECS,
            "refresh_token": refresh,
        })),
    )
        .into_response()
}

pub async fn token(AxState(s): AxState<Arc<State>>, Form(body): Form<TokenRequest>) -> Response {
    let Some(g) = &s.github else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(client_id) = body.client_id.as_deref().filter(|c| !c.is_empty()) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let invalid = || oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    let server_error = || oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    match body.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(verifier)) = (&body.code, &body.code_verifier) else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            // Taken first: a code gets one try, right or wrong.
            let Ok(Some(c)) = s.db.oauth_take_code(code) else {
                return invalid();
            };
            if c.client_id != client_id
                || body.redirect_uri.as_deref() != Some(c.redirect_uri.as_str())
                || !pkce_matches(verifier, &c.challenge)
            {
                tracing::warn!("a code was presented by something other than who asked for it");
                return invalid();
            }
            match s.db.oauth_grant(
                client_id,
                &c.caller,
                &c.github_token,
                ACCESS_SECS,
                REFRESH_SECS,
            ) {
                Ok((access, refresh)) => tokens(access, refresh),
                Err(e) => {
                    tracing::error!("issuing tokens: {e:#}");
                    server_error()
                }
            }
        }
        "refresh_token" => {
            let Some(refresh) = &body.refresh_token else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            let found = match s.db.oauth_find_refresh(refresh) {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("reading a refresh token: {e:#}");
                    return server_error();
                }
            };
            let grant = match found {
                OAuthRefresh::Unknown => return invalid(),
                OAuthRefresh::Reused(id) => {
                    tracing::warn!("a spent refresh token came back; ending that connection");
                    let _ = s.db.oauth_delete_grant(id);
                    return invalid();
                }
                OAuthRefresh::Live(grant) => grant,
            };
            if grant.client_id != client_id {
                return invalid();
            }
            let Ok(gh_token) = s.secrets.open_github(&grant.github_token) else {
                let _ = s.db.oauth_delete_grant(grant.id);
                return invalid();
            };
            let teams = match github::granted_teams(&s) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("reading grants: {e:#}");
                    return server_error();
                }
            };
            // GitHub being down isn't a verdict: the client can try again.
            let caller = match github::check(g, &gh_token, &teams).await {
                Ok((_, Ok(c))) if Access::load(&s.db, &c).is_ok_and(|a| a.any()) => c,
                Ok(_) => {
                    let _ = s.db.oauth_delete_grant(grant.id);
                    return invalid();
                }
                Err(e) => {
                    tracing::warn!("asking GitHub about a refresh: {e:#}");
                    return server_error();
                }
            };
            match s
                .db
                .oauth_rotate(grant.id, refresh, &caller, ACCESS_SECS, REFRESH_SECS)
            {
                Ok(Some((access, refresh))) => tokens(access, refresh),
                Ok(None) => invalid(),
                Err(e) => {
                    tracing::error!("issuing tokens: {e:#}");
                    server_error()
                }
            }
        }
        _ => oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_goes_over_https_or_to_this_machine() {
        assert!(redirect_allowed("https://claude.ai/api/mcp/auth_callback"));
        assert!(redirect_allowed("http://localhost:52341/callback"));
        assert!(redirect_allowed("http://127.0.0.1:8/cb"));
        assert!(redirect_allowed("http://[::1]:3000/cb"));
        assert!(!redirect_allowed("http://example.com/cb"));
        assert!(!redirect_allowed("http://localhost.evil.com/cb"));
        assert!(!redirect_allowed("claude://callback"));
        assert!(!redirect_allowed("javascript:alert(1)"));
        assert!(!redirect_allowed("/relative"));
        assert!(!redirect_allowed("https://claude.ai/cb#frag"));
    }

    #[test]
    fn a_loopback_redirect_may_change_port_and_nothing_else() {
        assert!(redirect_matches(
            "http://localhost:1/cb",
            "http://localhost:9/cb"
        ));
        assert!(!redirect_matches(
            "http://localhost:1/cb",
            "http://localhost:1/x"
        ));
        assert!(!redirect_matches(
            "http://localhost:1/cb",
            "http://127.0.0.1:1/cb"
        ));
        assert!(!redirect_matches(
            "https://c.test/cb",
            "https://c.test:8443/cb"
        ));
        assert!(!redirect_matches(
            "https://c.test/cb",
            "https://c.test/cb?x=1"
        ));
    }

    #[test]
    fn pkce_is_the_rfc_7636_vector() {
        assert!(pkce_matches(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_matches(
            "x",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }
}
