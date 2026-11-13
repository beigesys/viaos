//! Releases published from GitHub Actions, with no token stored anywhere.
//!
//! An admin names a repository as a publisher: which apps it may release and
//! from which refs. A workflow run then shows GitHub's OIDC token for this
//! server (see `oidc`), and if the token's repository, repository id and ref
//! match, it may upload releases of those apps and nothing else: not `/mcp`,
//! not deploys, not another app.
//!
//! The repository id is pinned when the publisher is added, or by the first
//! upload if the admin didn't give it. A repository that is deleted and made
//! again under the same name, or a name freed by a rename and taken by
//! someone else, has a new id and is refused.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::Json;
use axum::extract::{Extension, Path as UrlPath, Request, State as AxState};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rusqlite::params;
use serde::Serialize;
use serde_json::json;

use crate::State;
use crate::db::{Caller, Db, Role};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS publishers (
    repository     TEXT NOT NULL PRIMARY KEY,
    repository_id  TEXT,
    refs           TEXT NOT NULL,
    apps           TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    created_by     TEXT NOT NULL
);
";

/// A push to the `via` branch, or a tag like `v3`.
pub const DEFAULT_REFS: &[&str] = &["refs/heads/via", "refs/tags/v*"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Publisher {
    /// `owner/name`, lowercase: GitHub treats names without case.
    pub repository: String,
    /// GitHub's number for it. `None` until the first upload pins it.
    pub repository_id: Option<String>,
    /// Refs a run may publish from: exact, or with `*` for any run of
    /// characters, e.g. `refs/tags/v*`.
    pub refs: Vec<String>,
    pub apps: Vec<String>,
    pub created_at: i64,
    pub created_by: String,
}

impl Db {
    pub fn publishers(&self) -> Result<Vec<Publisher>> {
        let c = self.conn.lock().unwrap();
        let mut q = c.prepare(
            "SELECT repository, repository_id, refs, apps, created_at, created_by
             FROM publishers ORDER BY repository",
        )?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (repository, repository_id, refs, apps, created_at, created_by) = row?;
            out.push(Publisher {
                repository,
                repository_id,
                refs: serde_json::from_str(&refs).unwrap_or_default(),
                apps: serde_json::from_str(&apps).unwrap_or_default(),
                created_at,
                created_by,
            });
        }
        Ok(out)
    }

    /// Add a publisher, or replace what one may do.
    pub fn set_publisher(&self, p: &Publisher) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO publishers (repository, repository_id, refs, apps, created_at, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (repository) DO UPDATE SET
                 repository_id = excluded.repository_id, refs = excluded.refs, apps = excluded.apps",
            params![
                p.repository,
                p.repository_id,
                serde_json::to_string(&p.refs)?,
                serde_json::to_string(&p.apps)?,
                p.created_at,
                p.created_by,
            ],
        )?;
        Ok(())
    }

    pub fn delete_publisher(&self, repository: &str) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        Ok(c.execute(
            "DELETE FROM publishers WHERE repository = ?1",
            [repository.to_ascii_lowercase()],
        )? > 0)
    }

    /// Pin a publisher's repository id, if nothing pinned one first.
    fn pin_publisher(&self, repository: &str, id: &str) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "UPDATE publishers SET repository_id = ?2
             WHERE repository = ?1 AND repository_id IS NULL",
            params![repository, id],
        )?;
        Ok(())
    }

    fn publisher(&self, repository: &str) -> Result<Option<Publisher>> {
        Ok(self
            .publishers()?
            .into_iter()
            .find(|p| p.repository == repository))
    }
}

/// `owner/name` as GitHub allows it, lowercased.
pub fn check_repository(repo: &str) -> Result<String> {
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    match repo.trim().split_once('/') {
        Some((owner, name)) if ok(owner) && ok(name) => Ok(repo.trim().to_ascii_lowercase()),
        _ => bail!("{repo:?} is not a repository: give it as owner/name"),
    }
}

pub fn check_ref_pattern(pattern: &str) -> Result<()> {
    anyhow::ensure!(
        pattern.starts_with("refs/")
            && pattern.len() <= 200
            && !pattern.chars().any(|c| c.is_whitespace() || c.is_control()),
        "{pattern:?} is not a ref: give e.g. refs/heads/via or refs/tags/v*"
    );
    Ok(())
}

/// `*` stands for any run of characters, `/` included; the rest is exact.
pub fn ref_matches(pattern: &str, git_ref: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = git_ref.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for p in middle {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// What a verified run may do, attached to its request.
#[derive(Debug, Clone)]
pub struct Publishing {
    pub repository: String,
    pub apps: Vec<String>,
}

/// Whether `caller` may add a release of `app`: a run of a repository that
/// publishes it, or anyone who deploys to some fleet, since apps aren't any
/// one fleet's.
pub fn may_release(
    s: &State,
    caller: &Caller,
    publishing: Option<&Publishing>,
    app: &str,
) -> Result<()> {
    match publishing {
        Some(p) => anyhow::ensure!(
            p.apps.iter().any(|a| a == app),
            "{} may publish {}, not {app:?}",
            p.repository,
            p.apps.join(", ")
        ),
        None => anyhow::ensure!(
            crate::access::Access::load(&s.db, caller)?.anywhere(crate::access::Level::Developer),
            "uploading a release needs developer on some fleet"
        ),
    }
    Ok(())
}

/// Match a verified token to a publisher of `app`. The repository id is
/// pinned here if it wasn't already.
pub fn admit(db: &Db, c: &crate::oidc::GithubClaims, app: &str) -> Result<Publishing> {
    let repository = c.repository.to_ascii_lowercase();
    let p = db
        .publisher(&repository)?
        .with_context(|| format!("{} is not a publisher here", c.repository))?;
    match &p.repository_id {
        Some(id) if *id != c.repository_id => bail!(
            "{} is repository {}, not {id}: it was renamed or made again, so an admin \
             must add it again",
            c.repository,
            c.repository_id
        ),
        Some(_) => {}
        None => db.pin_publisher(&repository, &c.repository_id)?,
    }
    anyhow::ensure!(
        p.refs.iter().any(|r| ref_matches(r, &c.git_ref)),
        "{} may publish from {}, not {}",
        c.repository,
        p.refs.join(", "),
        c.git_ref
    );
    anyhow::ensure!(
        p.apps.iter().any(|a| a == app),
        "{} may publish {}, not {app:?}",
        c.repository,
        p.apps.join(", ")
    );
    Ok(Publishing {
        repository,
        apps: p.apps,
    })
}

/// The app a request adds a release of, if it is one a run may make:
/// `PUT /v1/releases/{app}/{release}/{arch}` or `POST /v1/releases/{app}`.
fn release_request(method: &Method, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.strip_prefix("/v1/releases/")?.split('/').collect();
    match (method, parts.as_slice()) {
        (&Method::PUT, [app, _, _]) | (&Method::POST, [app]) => Some(app.to_string()),
        _ => None,
    }
}

/// Authenticate a GitHub Actions token, for adding a release and nothing
/// else. Called by `require_caller` for bearer tokens that are JWTs.
pub async fn authenticate(s: &Arc<State>, mut req: Request, next: Next, token: &str) -> Response {
    let client = s.limiter.client(&req);
    let refused = |status: StatusCode, message: String| match s.limiter.take(client) {
        Ok(()) => (status, message).into_response(),
        Err(wait) => crate::limit::too_many(wait),
    };
    let Some(app) = release_request(req.method(), req.uri().path()) else {
        return refused(
            StatusCode::UNAUTHORIZED,
            "a GitHub Actions token can only upload releases".into(),
        );
    };
    let claims = match s.oidc.verify(token, &s.public_url).await {
        Ok(c) => c,
        Err(e) => return refused(StatusCode::UNAUTHORIZED, format!("{e:#}")),
    };
    let publishing = match admit(&s.db, &claims, &app) {
        Ok(p) => p,
        Err(e) => {
            let name = format!("github-actions:{}", claims.repository);
            s.db.audit(
                &name,
                "publish_refused",
                &json!({ "app": app, "ref": claims.git_ref, "run_id": claims.run_id, "why": format!("{e:#}") }),
                false,
            );
            return refused(StatusCode::FORBIDDEN, format!("{e:#}"));
        }
    };
    // Grants never name this, so it can do nothing a grant would allow.
    req.extensions_mut().insert(Caller {
        name: format!(
            "github-actions:{}@{}",
            publishing.repository, claims.git_ref
        ),
        role: Role::Member,
        subjects: Vec::new(),
    });
    req.extensions_mut().insert(publishing);
    next.run(req).await
}

/// The release number after the highest one `app` has, kept for the caller
/// by making its directory. Every call gets a new number, so a re-run of a
/// workflow makes a new release rather than meeting the old one.
pub fn next_release(root: &Path, app: &str) -> Result<u64> {
    static TAKING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    anyhow::ensure!(
        crate::releases::valid_app(app),
        "{app:?} is not an app name"
    );
    let _held = TAKING.lock().unwrap();
    let dir = root.join(app);
    std::fs::create_dir_all(&dir)?;
    let highest = std::fs::read_dir(&dir)?
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
        .max()
        .unwrap_or(0);
    let next = highest + 1;
    // Fails if it exists, which nothing but another server on the same
    // directory could cause.
    std::fs::create_dir(dir.join(next.to_string()))?;
    Ok(next)
}

/// `POST /v1/releases/{app}`: take the next release number.
pub async fn reserve(
    AxState(s): AxState<Arc<State>>,
    Extension(caller): Extension<Caller>,
    publishing: Option<Extension<Publishing>>,
    UrlPath(app): UrlPath<String>,
) -> Response {
    let result = may_release(&s, &caller, publishing.as_deref(), &app)
        .and_then(|()| next_release(&s.releases_dir(), &app));
    s.db.audit(
        &caller.name,
        "reserve_release",
        &json!({ "app": app, "release": result.as_ref().ok() }),
        result.is_ok(),
    );
    match result {
        Ok(n) => Json(json!({ "app": app, "release": n })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e:#}")).into_response(),
    }
}

/// The workflow file a repository adds, for the console and the docs.
pub fn workflow(server: &str, app: &str) -> String {
    format!(
        "name: via
on:
  push:
    branches: [via]
    tags: [\"v*\"]
permissions:
  id-token: write
  contents: read
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: beigesys/viaos/action@main
        with:
          server: {server}
          app: {app}
          arch: x86_64 aarch64
"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::testing::Issuer;

    #[test]
    fn refs_match_exactly_or_by_star() {
        for (p, r) in [
            ("refs/heads/via", "refs/heads/via"),
            ("refs/tags/v*", "refs/tags/v1"),
            ("refs/tags/v*", "refs/tags/v1.2/x"),
            ("refs/tags/v*", "refs/tags/v"),
            ("refs/*/via", "refs/heads/via"),
            ("*", "refs/pull/1/merge"),
        ] {
            assert!(ref_matches(p, r), "{p} {r}");
        }
        for (p, r) in [
            ("refs/heads/via", "refs/heads/via2"),
            ("refs/heads/via", "refs/heads/vi"),
            ("refs/tags/v*", "refs/heads/v1"),
            ("refs/tags/v*", "refs/tags/x1"),
            ("refs/*/via", "refs/heads/viax"),
        ] {
            assert!(!ref_matches(p, r), "{p} {r}");
        }
        check_ref_pattern("refs/tags/v*").unwrap();
        assert!(check_ref_pattern("main").is_err());
        assert_eq!(check_repository("Acme/App.js").unwrap(), "acme/app.js");
        assert!(check_repository("acme").is_err());
        assert!(check_repository("acme/a/b").is_err());
    }

    #[test]
    fn numbers_go_up_and_are_never_handed_out_twice() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(next_release(dir.path(), "web").unwrap(), 1);
        assert_eq!(next_release(dir.path(), "web").unwrap(), 2);
        std::fs::create_dir_all(dir.path().join("web/40")).unwrap();
        assert_eq!(next_release(dir.path(), "web").unwrap(), 41);
        assert_eq!(next_release(dir.path(), "api").unwrap(), 1);
        assert!(next_release(dir.path(), "../x").is_err());
    }

    fn publisher(id: Option<&str>) -> Publisher {
        Publisher {
            repository: "acme/app".into(),
            repository_id: id.map(Into::into),
            refs: DEFAULT_REFS.iter().map(|r| r.to_string()).collect(),
            apps: vec!["web".into()],
            created_at: 0,
            created_by: "admin".into(),
        }
    }

    #[tokio::test]
    async fn a_run_is_admitted_by_repository_id_ref_and_app() {
        let gh = Issuer::start().await;
        let v = gh.verifier();
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("via.db")).unwrap();
        let aud = "https://via.example.com";
        let claims = |repo: &str, id: &str, r: &str| {
            let t = gh.sign(&gh.claims(aud, repo, id, r));
            let v = &v;
            async move { v.verify(&t, aud).await.unwrap() }
        };

        let c = claims("acme/app", "7", "refs/heads/via").await;
        let e = admit(&db, &c, "web").unwrap_err();
        assert!(e.to_string().contains("not a publisher"), "{e}");

        db.set_publisher(&publisher(None)).unwrap();
        // GitHub's case, our lowercase.
        let c = claims("Acme/App", "7", "refs/heads/via").await;
        let p = admit(&db, &c, "web").unwrap();
        assert_eq!(p.apps, ["web"]);
        // The first run pinned the id.
        assert_eq!(
            db.publishers().unwrap()[0].repository_id.as_deref(),
            Some("7")
        );
        admit(&db, &claims("acme/app", "7", "refs/tags/v12").await, "web").unwrap();

        let e = admit(&db, &claims("acme/app", "8", "refs/heads/via").await, "web").unwrap_err();
        assert!(e.to_string().contains("renamed or made again"), "{e}");
        let e = admit(
            &db,
            &claims("acme/app", "7", "refs/heads/main").await,
            "web",
        )
        .unwrap_err();
        assert!(e.to_string().contains("not refs/heads/main"), "{e}");
        let e = admit(&db, &claims("acme/app", "7", "refs/heads/via").await, "api").unwrap_err();
        assert!(e.to_string().contains("not \"api\""), "{e}");
        let e = admit(
            &db,
            &claims("acme/other", "7", "refs/heads/via").await,
            "web",
        )
        .unwrap_err();
        assert!(e.to_string().contains("not a publisher"), "{e}");

        // An id given up front is held to from the first run.
        db.set_publisher(&publisher(Some("9"))).unwrap();
        assert!(admit(&db, &claims("acme/app", "7", "refs/heads/via").await, "web").is_err());
        assert!(db.delete_publisher("ACME/app").unwrap());
        assert!(db.publishers().unwrap().is_empty());
    }
}
