//! Signing in to the console with GitHub, limited to one organisation.
//!
//! Organisation owners are admins, and so is anyone on the configured admin
//! team. Other members get what grants give them (see [`crate::access`]):
//! as themselves, as members of a team a grant names, and as members of the
//! organisation. A member with no grant at all is turned away. GitHub's access token is used for those checks and then dropped.
//! Access lasts as long as the session, so someone removed from the
//! organisation loses it within [`SESSION_SECS`].

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::extract::{Query, State as AxState};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Json, Redirect, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::State;
use crate::db::{self, Caller, Role};

pub const SESSION_SECS: i64 = 12 * 3600;
const STATE_COOKIE: &str = "via_oauth_state";

#[derive(Clone)]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub org: String,
    pub admin_team: Option<String>,
    /// `https://github.com`, or a GitHub Enterprise Server address.
    pub url: String,
}

impl Config {
    fn api(&self) -> String {
        if self.url == "https://github.com" {
            "https://api.github.com".into()
        } else {
            format!("{}/api/v3", self.url)
        }
    }
}

/// Why a sign-in was refused, for the console to explain. Details go to the
/// server's log, not into a URL.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    NotMember,
    NoAccess,
    Restricted,
}

impl Refused {
    fn code(&self) -> &'static str {
        match self {
            Refused::NotMember => "not_member",
            Refused::NoAccess => "no_access",
            Refused::Restricted => "restricted",
        }
    }
}

fn back_to_console(code: &str) -> Response {
    Redirect::to(&format!("/?auth={code}")).into_response()
}

fn secure(s: &State) -> &'static str {
    if s.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    }
}

fn callback_url(s: &State) -> String {
    format!("{}/v1/auth/github/callback", s.public_url)
}

/// What the sign-in page can offer. Public: it is shown before signing in.
pub async fn options(AxState(s): AxState<Arc<State>>) -> Json<Value> {
    Json(json!({ "github": s.github.as_ref().map(|g| json!({ "org": g.org })) }))
}

/// Send the browser to GitHub.
pub async fn start(AxState(s): AxState<Arc<State>>) -> Response {
    let Some(g) = &s.github else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let state = db::random_secret();
    let url = format!(
        "{}/login/oauth/authorize?client_id={}&scope=read:org&state={state}&redirect_uri={}",
        g.url,
        encode(&g.client_id),
        encode(&callback_url(&s)),
    );
    // Lax, unlike the session: it has to arrive on GitHub's redirect back.
    let cookie = format!(
        "{STATE_COOKIE}={state}; Path=/v1/auth/github; HttpOnly; SameSite=Lax; Max-Age=600{}",
        secure(&s)
    );
    ([(header::SET_COOKIE, cookie)], Redirect::to(&url)).into_response()
}

/// Percent-encode a query value.
fn encode(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(name)?.strip_prefix('='))
}

/// GitHub sends the browser back here.
pub async fn callback(
    AxState(s): AxState<Arc<State>>,
    headers: HeaderMap,
    Query(q): Query<Callback>,
) -> Response {
    let Some(g) = &s.github else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // The state ties this redirect to the browser that started the sign-in,
    // so nobody can sign a victim in to the attacker's own session.
    if q.state.is_none() || q.state.as_deref() != cookie(&headers, STATE_COOKIE) {
        return back_to_console("state");
    }
    if q.error.is_some() {
        return back_to_console("denied");
    }
    let Some(code) = &q.code else {
        return back_to_console("failed");
    };
    // Only teams some grant names are worth asking GitHub about.
    let teams: Vec<String> = match s.db.grants() {
        Ok(g) => g
            .into_iter()
            .filter_map(|g| g.subject.strip_prefix("github-team:").map(String::from))
            .collect(),
        Err(e) => {
            tracing::error!("reading grants: {e:#}");
            return back_to_console("failed");
        }
    };
    let identified = identify(g, &callback_url(&s), code, &teams)
        .await
        .map(|(login, caller)| {
            let caller = caller.and_then(|c| match crate::access::Access::load(&s.db, &c) {
                Ok(a) if a.any() => Ok(c),
                _ => Err(Refused::NoAccess),
            });
            (login, caller)
        });
    let caller = match identified {
        Ok((_, Ok(caller))) => caller,
        Ok((login, Err(refused))) => {
            s.db.audit(
                &format!("github/{login}"),
                "sign_in",
                &json!({ "via": "github", "refused": refused.code() }),
                false,
            );
            return back_to_console(refused.code());
        }
        Err(e) => {
            tracing::warn!("GitHub sign-in failed: {e:#}");
            return back_to_console("failed");
        }
    };
    let name = caller.name.clone();
    let session = match s.db.create_session(&caller, SESSION_SECS) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("creating a session: {e:#}");
            return back_to_console("failed");
        }
    };
    s.db.audit(&name, "sign_in", &json!({ "via": "github" }), true);
    let secure = secure(&s);
    let mut res = Redirect::to("/").into_response();
    let cookies = res.headers_mut();
    for c in [
        format!(
            "{}={session}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECS}{secure}",
            crate::SESSION_COOKIE
        ),
        format!("{STATE_COOKIE}=; Path=/v1/auth/github; HttpOnly; SameSite=Lax; Max-Age=0{secure}"),
    ] {
        match HeaderValue::from_str(&c) {
            Ok(v) => {
                cookies.append(header::SET_COOKIE, v);
            }
            Err(_) => return back_to_console("failed"),
        }
    }
    res
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct User {
    login: String,
}

#[derive(Deserialize)]
struct Membership {
    state: String,
    role: Option<String>,
}

/// Turn the code into who this is and what they may do.
async fn identify(
    g: &Config,
    redirect_uri: &str,
    code: &str,
    teams: &[String],
) -> Result<(String, Result<Caller, Refused>)> {
    let http = reqwest::Client::builder()
        .user_agent("via-server")
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let reply: TokenReply = http
        .post(format!("{}/login/oauth/access_token", g.url))
        .header(header::ACCEPT, "application/json")
        .json(&json!({
            "client_id": g.client_id,
            "client_secret": g.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }))
        .send()
        .await
        .context("asking GitHub for a token")?
        .error_for_status()?
        .json()
        .await
        .context("reading GitHub's token reply")?;
    let Some(token) = reply.access_token else {
        bail!("GitHub gave no token: {}", reply.error.unwrap_or_default());
    };
    let api = g.api();
    let get = |url: String| {
        http.get(url)
            .bearer_auth(&token)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
    };

    let User { login } = get(format!("{api}/user"))
        .await?
        .error_for_status()?
        .json()
        .await
        .context("reading the GitHub user")?;

    let res = get(format!("{api}/user/memberships/orgs/{}", g.org)).await?;
    let membership: Membership = match res.status() {
        StatusCode::NOT_FOUND => return Ok((login, Err(Refused::NotMember))),
        // The organisation restricts OAuth apps and hasn't approved this one.
        StatusCode::FORBIDDEN => return Ok((login, Err(Refused::Restricted))),
        _ => res.error_for_status()?.json().await?,
    };
    if membership.state != "active" {
        return Ok((login, Err(Refused::NotMember)));
    }
    // Anything but a clear yes is a no.
    let on_team = |team: String| {
        let get = &get;
        let url = format!("{api}/orgs/{}/teams/{team}/memberships/{login}", g.org);
        async move {
            let res = get(url).await?;
            if !res.status().is_success() {
                return Ok::<_, anyhow::Error>(false);
            }
            let m: Membership = res.json().await?;
            Ok(m.state == "active")
        }
    };
    let mut admin = membership.role.as_deref() == Some("admin");
    if let (false, Some(team)) = (admin, &g.admin_team) {
        admin = on_team(team.clone()).await?;
    }
    let name = format!("github/{login}");
    if admin {
        return Ok((login, Ok(Caller::admin(&name))));
    }
    let mut subjects = vec![format!("github:{login}"), "github-org".to_string()];
    for team in teams {
        if on_team(team.clone()).await? {
            subjects.push(format!("github-team:{team}"));
        }
    }
    Ok((
        login,
        Ok(Caller {
            name,
            role: Role::Member,
            subjects,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use axum::Router;
    use axum::extract::Path;
    use axum::routing::{get, post};

    use super::*;

    /// A GitHub that knows one user per code.
    #[derive(Default)]
    struct Fake {
        /// login -> org role ("admin", "member", or "pending")
        members: HashMap<String, String>,
        /// team slug -> its active members
        teams: HashMap<String, Vec<String>>,
        restricted: bool,
        /// What the token exchange was sent.
        exchanged: Mutex<Vec<Value>>,
    }

    fn fake(fake: Arc<Fake>) -> Router {
        // The access token is the login, the code is `code-<login>`.
        fn who(h: &HeaderMap) -> String {
            h[header::AUTHORIZATION]
                .to_str()
                .unwrap()
                .strip_prefix("Bearer ")
                .unwrap()
                .into()
        }
        let (a, b, c, d) = (fake.clone(), fake.clone(), fake.clone(), fake);
        Router::new()
            .route(
                "/login/oauth/access_token",
                post(move |Json(v): Json<Value>| {
                    let a = a.clone();
                    async move {
                        a.exchanged.lock().unwrap().push(v.clone());
                        let code = v["code"].as_str().unwrap();
                        match code.strip_prefix("code-") {
                            Some(login) => Json(json!({ "access_token": login })),
                            None => Json(json!({ "error": "bad_verification_code" })),
                        }
                    }
                }),
            )
            .route(
                "/api/v3/user",
                get(move |h: HeaderMap| {
                    let _ = &b;
                    async move { Json(json!({ "login": who(&h) })) }
                }),
            )
            .route(
                "/api/v3/user/memberships/orgs/{org}",
                get(move |h: HeaderMap, Path(org): Path<String>| {
                    let c = c.clone();
                    async move {
                        assert_eq!(org, "beigesys");
                        if c.restricted {
                            return StatusCode::FORBIDDEN.into_response();
                        }
                        match c.members.get(&who(&h)).map(String::as_str) {
                            None => StatusCode::NOT_FOUND.into_response(),
                            Some("pending") => {
                                Json(json!({ "state": "pending", "role": "member" }))
                                    .into_response()
                            }
                            Some(role) => {
                                Json(json!({ "state": "active", "role": role })).into_response()
                            }
                        }
                    }
                }),
            )
            .route(
                "/api/v3/orgs/{org}/teams/{team}/memberships/{login}",
                get(
                    move |Path((_, team, login)): Path<(String, String, String)>| {
                        let d = d.clone();
                        async move {
                            if d.teams.get(&team).is_some_and(|m| m.contains(&login)) {
                                Json(json!({ "state": "active" })).into_response()
                            } else {
                                StatusCode::NOT_FOUND.into_response()
                            }
                        }
                    },
                ),
            )
    }

    struct Rig {
        url: String,
        http: reqwest::Client,
        gh: Arc<Fake>,
        state: Arc<crate::State>,
        _dir: tempfile::TempDir,
    }

    async fn serve(router: Router) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, router).await });
        url
    }

    async fn rig(gh: Fake) -> Rig {
        let gh = Arc::new(gh);
        let github = serve(fake(gh.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let state = crate::test_state(
            dir.path(),
            &url,
            Some(Config {
                client_id: "id".into(),
                client_secret: "shh".into(),
                org: "beigesys".into(),
                admin_team: Some("ops".into()),
                url: github,
            }),
        );
        let db = state.clone();
        let router = crate::router(state);
        tokio::spawn(async move { axum::serve(l, router).await });
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Rig {
            url,
            http,
            gh,
            state: db,
            _dir: dir,
        }
    }

    fn set_cookies(res: &reqwest::Response) -> Vec<String> {
        res.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    fn location(res: &reqwest::Response) -> String {
        res.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string()
    }

    impl Rig {
        /// Walk the flow as `login`; returns the callback's response.
        async fn sign_in(&self, login: &str) -> reqwest::Response {
            let start = self
                .http
                .get(format!("{}/v1/auth/github", self.url))
                .send()
                .await
                .unwrap();
            assert_eq!(start.status(), StatusCode::SEE_OTHER);
            let to = location(&start);
            assert!(
                to.contains("/login/oauth/authorize?client_id=id&scope=read:org"),
                "{to}"
            );
            let state = to
                .split("state=")
                .nth(1)
                .unwrap()
                .split('&')
                .next()
                .unwrap()
                .to_string();
            let set = set_cookies(&start).join(";");
            assert!(
                set.contains("HttpOnly") && set.contains("SameSite=Lax"),
                "{set}"
            );
            self.http
                .get(format!(
                    "{}/v1/auth/github/callback?code=code-{login}&state={state}",
                    self.url
                ))
                .header(header::COOKIE, format!("{STATE_COOKIE}={state}"))
                .send()
                .await
                .unwrap()
        }

        fn session(res: &reqwest::Response) -> String {
            let all = set_cookies(res);
            let c = all
                .iter()
                .find(|c| c.starts_with("via_session="))
                .expect("session cookie");
            assert!(
                c.contains("HttpOnly") && c.contains("SameSite=Strict"),
                "{c}"
            );
            c.split(';').next().unwrap().to_string()
        }

        async fn whoami(&self, cookie: &str) -> reqwest::Response {
            self.http
                .get(format!("{}/v1/session", self.url))
                .header(header::COOKIE, cookie)
                .send()
                .await
                .unwrap()
        }

        /// Sign in as `login` and return who the session says that is.
        async fn caller_of(&self, login: &str) -> Caller {
            let res = self.sign_in(login).await;
            assert_eq!(location(&res), "/", "{login}");
            let cookie = Self::session(&res);
            let token = cookie.strip_prefix("via_session=").unwrap();
            self.state.db.session_caller(token).unwrap().unwrap()
        }

        async fn role_of(&self, login: &str) -> (String, String) {
            let res = self.sign_in(login).await;
            assert_eq!(location(&res), "/");
            let v: Value = self
                .whoami(&Self::session(&res))
                .await
                .json()
                .await
                .unwrap();
            (
                v["name"].as_str().unwrap().into(),
                v["role"].as_str().unwrap().into(),
            )
        }
    }

    fn org() -> Fake {
        Fake {
            members: HashMap::from([
                ("owner".into(), "admin".into()),
                ("opsy".into(), "member".into()),
                ("plain".into(), "member".into()),
                ("liner".into(), "member".into()),
                ("invited".into(), "pending".into()),
            ]),
            teams: HashMap::from([
                ("ops".into(), vec!["opsy".into()]),
                ("line".into(), vec!["liner".into(), "invited".into()]),
            ]),
            ..Fake::default()
        }
    }

    #[tokio::test]
    async fn membership_decides_the_role() {
        let r = rig(org()).await;
        assert_eq!(
            r.role_of("owner").await,
            ("github/owner".into(), "admin".into())
        );
        assert_eq!(
            r.role_of("opsy").await,
            ("github/opsy".into(), "admin".into())
        );
        // Every member observes every fleet, as viewers did before grants.
        assert_eq!(
            r.role_of("plain").await,
            ("github/plain".into(), "member".into())
        );
        // The secret went to GitHub with the redirect the app registered.
        let sent = r.gh.exchanged.lock().unwrap();
        assert_eq!(sent[0]["client_secret"], "shh");
        assert_eq!(
            sent[0]["redirect_uri"],
            format!("{}/v1/auth/github/callback", r.url)
        );
    }

    #[tokio::test]
    async fn outsiders_get_no_session() {
        let r = rig(org()).await;
        for (login, code) in [("stranger", "not_member"), ("invited", "not_member")] {
            let res = r.sign_in(login).await;
            assert_eq!(location(&res), format!("/?auth={code}"), "{login}");
            assert!(
                !set_cookies(&res)
                    .iter()
                    .any(|c| c.starts_with("via_session"))
            );
        }
    }

    #[tokio::test]
    async fn grants_decide_who_else_gets_in() {
        use crate::access::Level;
        let r = rig(org()).await;
        let db = &r.state.db;
        db.delete_grant("github-org", None).unwrap();
        db.create_fleet("line-07").unwrap();
        db.set_grant("github-team:line", Some("line-07"), Level::Developer)
            .unwrap();
        db.set_grant("github:plain", None, Level::Observer).unwrap();
        // The team grant is found by asking GitHub about that team.
        let liner = r.caller_of("liner").await;
        assert!(liner.subjects.contains(&"github-team:line".to_string()));
        let a = crate::access::Access::load(db, &liner).unwrap();
        assert_eq!(a.level("line-07"), Some(Level::Developer));
        assert!(
            r.caller_of("plain")
                .await
                .subjects
                .contains(&"github:plain".to_string())
        );
        // Admins need no grant.
        assert_eq!(r.role_of("owner").await.1, "admin");
        assert_eq!(r.role_of("opsy").await.1, "admin");
        // A member nobody granted anything is turned away, and the grants
        // let no outsider in.
        db.delete_grant("github:plain", None).unwrap();
        for (login, code) in [
            ("plain", "no_access"),
            ("invited", "not_member"),
            ("stranger", "not_member"),
        ] {
            let res = r.sign_in(login).await;
            assert_eq!(location(&res), format!("/?auth={code}"), "{login}");
            assert!(
                !set_cookies(&res)
                    .iter()
                    .any(|c| c.starts_with("via_session"))
            );
        }
    }

    #[tokio::test]
    async fn an_org_that_blocks_the_app_is_explained() {
        let r = rig(Fake {
            restricted: true,
            ..org()
        })
        .await;
        assert_eq!(location(&r.sign_in("owner").await), "/?auth=restricted");
    }

    #[tokio::test]
    async fn the_callback_needs_this_browsers_state() {
        let r = rig(org()).await;
        for cookie in [format!("{STATE_COOKIE}=other"), String::new()] {
            let res = r
                .http
                .get(format!(
                    "{}/v1/auth/github/callback?code=code-owner&state=mine",
                    r.url
                ))
                .header(header::COOKIE, cookie)
                .send()
                .await
                .unwrap();
            assert_eq!(location(&res), "/?auth=state");
        }
        assert!(r.gh.exchanged.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_session_only_works_as_a_same_origin_cookie_until_sign_out() {
        let r = rig(org()).await;
        let cookie = Rig::session(&r.sign_in("owner").await);
        let token = cookie.strip_prefix("via_session=").unwrap();
        assert_eq!(r.whoami(&cookie).await.status(), StatusCode::OK);

        // Not usable as an API token.
        let bearer = r
            .http
            .get(format!("{}/v1/session", r.url))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(bearer.status(), StatusCode::UNAUTHORIZED);

        // Not from another site's script.
        let cross = r
            .http
            .get(format!("{}/v1/session", r.url))
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, "https://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(cross.status(), StatusCode::FORBIDDEN);

        // Signing out ends it on the server, not just in this browser.
        let out = r
            .http
            .delete(format!("{}/v1/session", r.url))
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), StatusCode::NO_CONTENT);
        assert_eq!(r.whoami(&cookie).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_sign_in_page_learns_what_is_on_offer() {
        let r = rig(org()).await;
        let v: Value = r
            .http
            .get(format!("{}/v1/auth", r.url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(v["github"]["org"], "beigesys");
    }
}
