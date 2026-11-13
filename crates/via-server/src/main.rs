//! `via-server` -- the viaos control plane.
//!
//! Devices connect out to it over one WebSocket each; people and Claude reach
//! it over MCP, or through the web console this binary also serves.
//!
//! Routes:
//!
//! - `POST /v1/enroll`        a device spends its enrollment token
//! - `GET  /v1/connect`       a device's management connection (WebSocket)
//! - `GET  /v1/images/{id}`   download a provisioning image
//! - `GET  /v1/os/{arch}/{version}/{file}`  OS update files, for devices
//! - `PUT  /v1/os/{arch}/{version}/{file}`  upload OS update files (admin)
//! - `PUT  /v1/base/{name}`   upload the base image provisioning starts from, for a
//!   device type or a whole architecture (admin)
//! - `PUT  /v1/releases/{app}/{release}/{arch}`  upload a bundle (admin)
//! - `GET  /v1/releases/{app}/{release}/{arch}`  fetch a bundle (devices)
//! - `GET  /v1/devices/{device}/tunnel/{port}`  a TCP stream to a port on a
//!   device, over its connection (WebSocket, admin)
//! - `/mcp`                   fleet MCP, Streamable HTTP, bearer token
//! - `/authorize`, `/token`, `/register`  how an MCP client signs in with
//!   GitHub (see `oauth`)
//!
//! People authenticate with API tokens made by `via-server token create`.
//! Admins may do everything; anyone else what grants give them, fleet by
//! fleet (see `access`).

mod access;
mod db;
mod fetch;
mod github;
mod hub;
mod image;
mod limit;
mod mcp;
mod oauth;
mod os;
mod os_track;
mod provisioning;
mod releases;
mod secrets;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request, State as AxState, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use clap::Parser;
use serde::Deserialize;
use serde_json::json;

use db::Db;
use hub::Hub;

#[derive(Parser)]
#[command(name = "via-server", version, about = "viaos control plane")]
struct Cli {
    /// Database and generated images live here.
    #[arg(
        long,
        env = "VIA_DATA_DIR",
        default_value = "/var/lib/via-server",
        global = true
    )]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    serve: Serve,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Run the control plane (the default).
    Serve,
    /// Manage the API tokens people and Claude use.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Manage the hardware the console offers images for.
    #[command(subcommand, name = "device-type")]
    DeviceType(DeviceTypeCommand),
}

#[derive(clap::Subcommand)]
enum DeviceTypeCommand {
    /// Add a device type, or change one. It uses `viaos-<id>.raw` if that was
    /// uploaded, and otherwise the base image for its architecture.
    Set {
        /// e.g. `rock-5b`
        id: String,
        /// What people see, e.g. `Rock 5B`.
        #[arg(long)]
        name: String,
        /// As `uname -m` spells it.
        #[arg(long)]
        arch: String,
        #[arg(long, default_value = "")]
        detail: String,
    },
    List,
    Remove {
        id: String,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum TokenRole {
    Admin,
    Developer,
    Operator,
    Observer,
}

#[derive(clap::Subcommand)]
enum TokenCommand {
    /// Create a token and print it. It is shown only this once.
    Create {
        /// Who it is for, e.g. `ana` or `ci`.
        name: String,
        /// `admin`, or a role on `--fleet` (every fleet without it).
        #[arg(long, value_enum, default_value = "admin")]
        role: TokenRole,
        #[arg(long)]
        fleet: Option<String>,
    },
    /// List tokens: name, role, and when each was last used.
    List,
    /// Revoke a token at once.
    Revoke { name: String },
}

#[derive(clap::Args)]
struct Serve {
    #[arg(long, env = "VIA_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    /// Base viaos images, named `viaos-<arch>.raw`.
    #[arg(long, env = "VIA_IMAGES_DIR")]
    images_dir: Option<PathBuf>,
    /// Where to fetch a base image from when there is none for an
    /// architecture: `<source>/viaos-<arch>.raw.zst`. Defaults to the latest
    /// viaos release on GitHub; `none` turns it off.
    #[arg(long, env = "VIA_IMAGE_SOURCE", default_value = fetch::DEFAULT_SOURCE)]
    image_source: String,
    /// OS updates, as `<arch>/<version>/` holding `nix build .#updates.<arch>`.
    #[arg(long, env = "VIA_OS_DIR")]
    os_dir: Option<PathBuf>,
    /// The address devices and people use to reach this server, e.g.
    /// `https://via.example.com`. Written into provisioning images.
    #[arg(long, env = "VIA_PUBLIC_URL")]
    public_url: Option<String>,
    /// An admin token that needs no database entry, for bootstrapping and
    /// for deployments that keep the secret elsewhere. Audited as `admin`.
    #[arg(long, env = "VIA_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
    /// Public keys (hex, from `via keygen`) that devices require OS updates
    /// and app releases to be signed by. Written into every provisioning
    /// image. Comma-separated.
    #[arg(long, env = "VIA_TRUSTED_KEYS", value_delimiter = ',')]
    trusted_keys: Vec<String>,
    /// Key that encrypts secrets at rest, 64 hex digits. Defaults to
    /// `secret.key` in the data directory, made on first start.
    #[arg(long, env = "VIA_SECRET_KEY", hide_env_values = true)]
    secret_key: Option<String>,
    /// Let people sign in to the console with GitHub: the OAuth app's client
    /// ID. Needs the secret and the organisation too.
    #[arg(long, env = "VIA_GITHUB_CLIENT_ID")]
    github_client_id: Option<String>,
    #[arg(long, env = "VIA_GITHUB_CLIENT_SECRET", hide_env_values = true)]
    github_client_secret: Option<String>,
    /// Only members of this organisation can sign in. Its owners are admins;
    /// other members get what grants give them.
    #[arg(long, env = "VIA_GITHUB_ORG")]
    github_org: Option<String>,
    /// Slug of a team in the organisation whose members are also admins.
    #[arg(long, env = "VIA_GITHUB_ADMIN_TEAM")]
    github_admin_team: Option<String>,
    /// A GitHub Enterprise Server's address.
    #[arg(long, env = "VIA_GITHUB_URL", default_value = "https://github.com")]
    github_url: String,
    /// How many proxies in front of this server add to X-Forwarded-For: 1
    /// behind one nginx or load balancer, 2 on Railway (its edge adds itself
    /// after the client). Requests from people not signed in are limited per
    /// address; at 0 the address is the peer's.
    #[arg(long, env = "VIA_TRUST_PROXY", default_value_t = 0)]
    trust_proxy: usize,
}

pub struct State {
    pub db: Db,
    pub hub: Hub,
    pub data_dir: PathBuf,
    pub images_dir: PathBuf,
    pub os_dir: PathBuf,
    pub public_url: String,
    /// `public_url` with its scheme switched to WebSocket.
    pub device_url: String,
    pub trusted_keys: Vec<String>,
    admin_token_hash: Option<String>,
    pub secrets: secrets::Secrets,
    pub github: Option<github::Config>,
    pub limiter: limit::Limiter,
}

impl State {
    pub fn out_dir(&self) -> PathBuf {
        self.data_dir.join("images")
    }

    pub fn releases_dir(&self) -> PathBuf {
        self.data_dir.join("releases")
    }

    /// Delete a provisioning image once its token can enroll nothing more:
    /// it is gigabytes.
    pub fn delete_image(&self, id: &str) {
        for ext in ["raw.zst", "name", "fleet"] {
            let _ = std::fs::remove_file(self.out_dir().join(format!("{id}.{ext}")));
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rmcp=warn".into()),
        )
        .init();
    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.data_dir)?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(cli.serve, cli.data_dir).await,
        Command::Token(t) => {
            let db = Db::open(&cli.data_dir.join("via.db"))?;
            match t {
                TokenCommand::Create { name, role, fleet } => {
                    let level = match role {
                        TokenRole::Admin => None,
                        TokenRole::Developer => Some(access::Level::Developer),
                        TokenRole::Operator => Some(access::Level::Operator),
                        TokenRole::Observer => Some(access::Level::Observer),
                    };
                    println!(
                        "{}",
                        access::create_token(&db, &name, level, fleet.as_deref())?
                    )
                }
                TokenCommand::List => {
                    println!("{}", serde_json::to_string_pretty(&db.api_tokens()?)?)
                }
                TokenCommand::Revoke { name } => db.revoke_api_token(&name)?,
            }
            Ok(())
        }
        Command::DeviceType(t) => {
            let db = Db::open(&cli.data_dir.join("via.db"))?;
            match t {
                DeviceTypeCommand::Set {
                    id,
                    name,
                    arch,
                    detail,
                } => db.set_device_type(&db::DeviceType {
                    id,
                    name,
                    arch,
                    detail,
                })?,
                DeviceTypeCommand::List => {
                    println!("{}", serde_json::to_string_pretty(&db.device_types()?)?)
                }
                DeviceTypeCommand::Remove { id } => db.delete_device_type(&id)?,
            }
            Ok(())
        }
    }
}

async fn serve(cli: Serve, data_dir: PathBuf) -> Result<()> {
    if let Some(t) = &cli.admin_token {
        anyhow::ensure!(
            t.len() >= 16,
            "VIA_ADMIN_TOKEN must be at least 16 characters"
        );
    }
    for k in &cli.trusted_keys {
        via_bundle::PublicKey::from_hex(k)
            .with_context(|| format!("VIA_TRUSTED_KEYS: {k:?} is not a public key"))?;
    }
    let public_url = cli
        .public_url
        .context("VIA_PUBLIC_URL is required: the address devices reach this server at")?
        .trim_end_matches('/')
        .to_string();
    let device_url = if let Some(rest) = public_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = public_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        anyhow::bail!("VIA_PUBLIC_URL must start with http:// or https://");
    };
    let github = match (
        cli.github_client_id,
        cli.github_client_secret,
        cli.github_org,
    ) {
        (None, None, None) => None,
        (Some(client_id), Some(client_secret), Some(org)) => Some(github::Config {
            client_id,
            client_secret,
            org,
            admin_team: cli.github_admin_team,
            url: cli.github_url.trim_end_matches('/').to_string(),
        }),
        _ => anyhow::bail!(
            "GitHub sign-in needs VIA_GITHUB_CLIENT_ID, VIA_GITHUB_CLIENT_SECRET and VIA_GITHUB_ORG together"
        ),
    };
    let db = Db::open(&data_dir.join("via.db"))?;
    let secrets = secrets::Secrets::open(&data_dir, cli.secret_key.as_deref())?;
    if cli.admin_token.is_none() && db.api_tokens()?.is_empty() {
        tracing::warn!("no API tokens yet: create one with `via-server token create <name>`");
    }
    let state = Arc::new(State {
        db,
        hub: Hub::default(),
        images_dir: cli.images_dir.unwrap_or_else(|| data_dir.join("base")),
        os_dir: cli.os_dir.unwrap_or_else(|| data_dir.join("os")),
        data_dir,
        public_url,
        device_url,
        trusted_keys: cli.trusted_keys,
        admin_token_hash: cli.admin_token.as_deref().map(db::hash),
        secrets,
        github,
        limiter: limit::Limiter::new(cli.trust_proxy),
    });
    tokio::spawn(os_track::run(state.clone()));
    tokio::spawn(oauth::tidy(state.clone()));
    if cli.image_source != "none" {
        tokio::spawn(fetch::run(state.clone(), cli.image_source.clone()));
    }
    let app = router(state.clone());

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    tracing::info!("listening on {} as {}", cli.listen, state.public_url);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server stopped")
}

fn router(state: Arc<State>) -> Router {
    // MCP checks access per tool, and these per fleet; what's below them is
    // admin-only.
    let people = Router::new()
        .nest_service("/mcp", mcp::service(state.clone()))
        .route("/v1/session", get(whoami))
        .route(
            "/v1/releases/{app}/{release}/{arch}",
            axum::routing::put(upload_release),
        )
        .route("/v1/devices/{device}/tunnel/{port}", get(tunnel))
        .route("/v1/devices/{device}/shell", get(shell))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_caller,
        ));
    let admin = Router::new()
        .route(
            "/v1/os/{arch}/{version}/{file}",
            axum::routing::put(upload_os_file),
        )
        .route("/v1/base/{arch}", axum::routing::put(upload_base))
        .with_state(state.clone())
        .layer(middleware::from_fn(require_admin))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_caller,
        ));
    // Nobody is signed in here, so each request spends from its address's
    // budget.
    let anonymous = Router::new()
        .route("/v1/session", post(sign_in))
        .route("/v1/auth/github", get(github::start))
        .route("/v1/auth/github/callback", get(github::callback))
        .route("/register", post(oauth::register))
        .route("/authorize", get(oauth::authorize))
        .route("/token", post(oauth::token))
        .route("/oauth/request", get(oauth::pending))
        .route("/oauth/decide", post(oauth::decide))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), limit::every));
    let enrolling = Router::new()
        .route("/v1/enroll", post(enroll))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            limit::failures,
        ));
    Router::new()
        .route("/v1/connect", get(connect))
        .route("/v1/images/{id}", get(download))
        .route("/v1/os/{arch}/{version}/{file}", get(os_file))
        .route("/v1/releases/{app}/{release}/{arch}", get(release_bundle))
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/session", axum::routing::delete(sign_out))
        .route("/v1/auth", get(github::options))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(oauth::protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::authorization_server),
        )
        .fallback(web::serve)
        .with_state(state.clone())
        .merge(anonymous)
        .merge(enrolling)
        .merge(people)
        .merge(admin)
}

#[cfg(test)]
fn test_state(
    dir: &std::path::Path,
    public_url: &str,
    github: Option<github::Config>,
) -> Arc<State> {
    Arc::new(State {
        db: Db::open(&dir.join("via.db")).unwrap(),
        hub: Hub::default(),
        images_dir: dir.join("base"),
        os_dir: dir.join("os"),
        data_dir: dir.to_path_buf(),
        public_url: public_url.into(),
        device_url: public_url.replacen("http", "ws", 1),
        trusted_keys: Vec::new(),
        admin_token_hash: None,
        secrets: secrets::Secrets::open(dir, None).unwrap(),
        github,
        limiter: limit::Limiter::new(0),
    })
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Authenticate an API token and attach the [`db::Caller`] to the request.
async fn require_caller(AxState(s): AxState<Arc<State>>, mut req: Request, next: Next) -> Response {
    let by_cookie = bearer(req.headers()).is_none();
    let mcp = req.uri().path() == "/mcp";
    let unauthorized = |message: &'static str| {
        let mut res = (StatusCode::UNAUTHORIZED, message).into_response();
        if let (true, Some(v)) = (mcp, oauth::challenge(&s)) {
            res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
        res
    };
    let Some(token) = bearer(req.headers()).or_else(|| session_cookie(req.headers())) else {
        // Every MCP client asks once without a token to find out how to sign
        // in, so this spends from the budget like any anonymous request.
        return match s.limiter.take(s.limiter.client(&req)) {
            Ok(()) => unauthorized("API token required"),
            Err(wait) => limit::too_many(wait),
        };
    };
    // A browser sends its cookie wherever a page asks it to, so a cookie only
    // counts from our own pages.
    if by_cookie && !same_origin(req.headers()) {
        return (StatusCode::FORBIDDEN, "cross-origin request").into_response();
    }
    let caller = if s.admin_token_hash.as_deref() == Some(db::hash(token).as_str()) {
        Some(db::Caller::admin("admin"))
    } else if by_cookie && token.starts_with(db::SESSION_PREFIX) {
        s.db.session_caller(token).ok().flatten()
    } else if token.starts_with(oauth::ACCESS_PREFIX) {
        // Issued for /mcp, and good for nothing else.
        mcp.then(|| s.db.oauth_caller(token).ok().flatten())
            .flatten()
    } else {
        s.db.api_caller(token).ok().flatten()
    };
    match caller {
        Some(c) => {
            req.extensions_mut().insert(c);
            next.run(req).await
        }
        None => match s.limiter.take(s.limiter.client(&req)) {
            Ok(()) => unauthorized("unknown API token"),
            Err(wait) => limit::too_many(wait),
        },
    }
}

pub const SESSION_COOKIE: &str = "via_session";

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix("via_session="))
}

/// Requests with no Origin are not from a page's script: navigation, curl.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|o| o.to_str().ok()) else {
        return true;
    };
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    origin.split_once("://").map(|(_, h)| h) == host
}

#[derive(Deserialize)]
struct SignIn {
    token: String,
}

/// Exchange an API token for a cookie scripts cannot read. The cookie holds
/// the token, so revoking the token ends the session.
async fn sign_in(
    AxState(s): AxState<Arc<State>>,
    headers: HeaderMap,
    Json(body): Json<SignIn>,
) -> Response {
    let token = body.token.trim();
    let caller = if s.admin_token_hash.as_deref() == Some(db::hash(token).as_str()) {
        Some(db::Caller::admin("admin"))
    } else {
        s.db.api_caller(token).ok().flatten()
    };
    let Some(caller) = caller else {
        return (StatusCode::UNAUTHORIZED, "unknown token").into_response();
    };
    if !same_origin(&headers) {
        return (StatusCode::FORBIDDEN, "cross-origin request").into_response();
    }
    s.db.audit(&caller.name, "sign_in", &json!({}), true);
    let secure = if s.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000{secure}"
    );
    ([(header::SET_COOKIE, cookie)], Json(caller)).into_response()
}

async fn sign_out(AxState(s): AxState<Arc<State>>, headers: HeaderMap) -> Response {
    if let Some(session) = session_cookie(&headers).filter(|_| same_origin(&headers)) {
        if let Err(e) = s.db.delete_session(session) {
            tracing::error!("ending a session: {e:#}");
        }
    }
    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    ([(header::SET_COOKIE, cookie)], StatusCode::NO_CONTENT).into_response()
}

async fn whoami(Extension(caller): Extension<db::Caller>) -> Json<db::Caller> {
    Json(caller)
}

async fn require_admin(req: Request, next: Next) -> Response {
    match req.extensions().get::<db::Caller>() {
        Some(c) if c.role == db::Role::Admin => next.run(req).await,
        _ => (StatusCode::FORBIDDEN, "admin role required").into_response(),
    }
}

async fn enroll(AxState(s): AxState<Arc<State>>, Json(e): Json<db::Enrollment>) -> Response {
    match s.db.enroll(&e) {
        Ok((device, credential, image)) => {
            tracing::info!(device = %device.id, name = %device.name, fleet = %device.fleet, "enrolled");
            // The image held a token that is now spent.
            if let Some(id) = image {
                s.delete_image(&id);
            }
            Json(json!({ "device": device, "credential": credential })).into_response()
        }
        Err(err) => {
            tracing::warn!(hostname = %e.hostname, "enrollment refused: {err}");
            (StatusCode::FORBIDDEN, err.to_string()).into_response()
        }
    }
}

#[derive(Deserialize)]
struct ConnectQuery {
    os_version: Option<String>,
    agent_version: Option<String>,
}

async fn connect(
    AxState(s): AxState<Arc<State>>,
    headers: HeaderMap,
    Query(q): Query<ConnectQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let device = match bearer(&headers).map(|c| s.db.authenticate(c)) {
        Some(Ok(Some(id))) => id,
        _ => return (StatusCode::UNAUTHORIZED, "unknown device credential").into_response(),
    };
    if let Err(e) =
        s.db.seen(&device, q.os_version.as_deref(), q.agent_version.as_deref())
    {
        tracing::warn!("recording last-seen failed: {e}");
    }
    ws.on_upgrade(move |socket| async move {
        // A device that was offline catches up on what changed.
        let sync = {
            let (s, device) = (s.clone(), device.clone());
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                if let Ok(Some(d)) = s.db.device(&device)
                    && let Err(e) = secrets::push(&s, &d).await
                {
                    tracing::warn!(device = %d.name, "sending variables failed: {e:#}");
                }
            })
        };
        s.hub.attach(device.clone(), socket).await;
        sync.abort();
        let _ = s.db.seen(&device, None, None);
    })
}

/// Update files are served to enrolled devices only. Names are checked
/// against the version's manifest, so no path from a request reaches the
/// filesystem unvetted.
async fn os_file(
    AxState(s): AxState<Arc<State>>,
    headers: HeaderMap,
    Path((arch, version, file)): Path<(String, String, String)>,
) -> Response {
    if !matches!(
        bearer(&headers).map(|c| s.db.authenticate(c)),
        Some(Ok(Some(_)))
    ) {
        return (StatusCode::UNAUTHORIZED, "unknown device credential").into_response();
    }
    let Ok(release) = os::find(&s.os_dir, &arch, &version) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let known = file == "manifest.json"
        || file == "manifest.json.sig"
        || release.files.iter().any(|f| f == &file);
    if !known {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_file(&release.dir.join(&file), &file, "application/octet-stream").await
}

/// Stream a request body to `path`, hashing it on the way, and only then
/// make it visible: a half-uploaded file is never offered to anyone.
async fn save_body(path: &std::path::Path, body: Body) -> Result<String> {
    use futures_util::StreamExt;
    use sha2::Digest;
    use tokio::io::AsyncWriteExt;

    tokio::fs::create_dir_all(path.parent().context("no parent directory")?).await?;
    let tmp = path.with_extension("part");
    let mut file = tokio::fs::File::create(&tmp).await?;
    let mut hash = sha2::Sha256::new();
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        hash.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.sync_all().await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(hex::encode(hash.finalize()))
}

fn uploaded(result: Result<serde_json::Value>) -> Response {
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e:#}")).into_response(),
    }
}

async fn upload_release(
    AxState(s): AxState<Arc<State>>,
    Extension(caller): Extension<db::Caller>,
    Path((app, release, arch)): Path<(String, u64, String)>,
    body: Body,
) -> Response {
    let result = async {
        // Apps aren't any fleet's, so whoever deploys to some fleet may add one.
        anyhow::ensure!(
            access::Access::load(&s.db, &caller)?.anywhere(access::Level::Developer),
            "uploading a release needs developer on some fleet"
        );
        let path = releases::bundle_path(&s.releases_dir(), &app, release, &arch)?;
        anyhow::ensure!(
            !path.exists(),
            "{app} release {release} for {arch} already exists; releases are immutable"
        );
        let digest = save_body(&path.with_extension("upload"), body).await?;
        tokio::fs::write(path.with_extension("sha256"), &digest).await?;
        tokio::fs::rename(path.with_extension("upload"), &path).await?;
        // A bundle this cannot read is the device's to refuse, as it always
        // was; `list_variables` just has nothing to say about it.
        let (root, name) = (s.releases_dir(), app.clone());
        let recorded = tokio::task::spawn_blocking(move || {
            releases::record_schema(&root, &name, release, &path)
        })
        .await?;
        if let Err(e) = recorded {
            tracing::warn!(%app, release, %arch, "reading its variables failed: {e:#}");
        }
        Ok(json!({ "app": app, "release": release, "arch": arch, "sha256": digest }))
    }
    .await;
    s.db.audit(
        &caller.name,
        "upload_release",
        &json!({ "app": app, "release": release, "arch": arch }),
        result.is_ok(),
    );
    uploaded(result)
}

/// Upload one file of an OS version. `manifest.json` goes last: it is what
/// makes the version exist, so it is accepted only once every file it names
/// is present at the size it states.
async fn upload_os_file(
    AxState(s): AxState<Arc<State>>,
    Extension(caller): Extension<db::Caller>,
    Path((arch, version, file)): Path<(String, String, String)>,
    body: Body,
) -> Response {
    let result = async {
        let dir = os::upload_dir(&s.os_dir, &arch, &version, &file)?;
        if file == "manifest.json" {
            let staged = dir.join("manifest.json.upload");
            save_body(&staged, body).await?;
            if let Err(e) = os::check_signature(&dir, &staged, &s.trusted_keys) {
                let _ = tokio::fs::remove_file(&staged).await;
                return Err(e);
            }
            if let Err(e) = os::check_complete(&dir, &staged, &arch, &version) {
                let _ = tokio::fs::remove_file(&staged).await;
                return Err(e);
            }
            tokio::fs::rename(&staged, dir.join("manifest.json")).await?;
            Ok(json!({ "arch": arch, "version": version, "published": true }))
        } else {
            let digest = save_body(&dir.join(&file), body).await?;
            Ok(json!({ "file": file, "sha256": digest }))
        }
    }
    .await;
    if file == "manifest.json" {
        s.db.audit(
            &caller.name,
            "upload_os",
            &json!({ "arch": arch, "version": version }),
            result.is_ok(),
        );
    }
    uploaded(result)
}

/// Replace the base image provisioning images are made from. The body is
/// the zstd-compressed raw image, as `via base-image` sends it.
async fn upload_base(
    AxState(s): AxState<Arc<State>>,
    Extension(caller): Extension<db::Caller>,
    Path(arch): Path<String>,
    body: Body,
) -> Response {
    let result = async {
        // Named for a device type, or an architecture to share among its types.
        let known = s.db.device_types()?;
        anyhow::ensure!(
            known.iter().any(|t| t.id == arch || t.arch == arch),
            "{arch:?} is not a device type or the architecture of one"
        );
        let compressed = s.images_dir.join(format!("viaos-{arch}.raw.zst"));
        let digest = save_body(&compressed, body).await?;
        let raw = s.images_dir.join(format!("viaos-{arch}.raw"));
        let c = compressed.clone();
        tokio::task::spawn_blocking(move || image::decompress(&c, &raw)).await??;
        let _ = tokio::fs::remove_file(&compressed).await;
        Ok(json!({ "arch": arch, "sha256_compressed": digest }))
    }
    .await;
    s.db.audit(
        &caller.name,
        "upload_base",
        &json!({ "arch": arch }),
        result.is_ok(),
    );
    uploaded(result)
}

/// The device, if the caller is a developer on its fleet. Someone who can't
/// see it at all is told it doesn't exist.
fn developer_on(
    s: &State,
    caller: &db::Caller,
    device: &str,
    what: &str,
) -> anyhow::Result<db::Device> {
    let d = s.db.resolve(device)?;
    let a = access::Access::load(&s.db, caller)?;
    if !a.sees(&d.fleet) {
        anyhow::bail!("no device named {device:?}");
    }
    a.require(&d.fleet, access::Level::Developer, what)?;
    anyhow::ensure!(!d.waiting, "{} is waiting to enroll", d.name);
    Ok(d)
}

/// A TCP stream to `port` on a device, carried over the device's own
/// connection: SSH to a device behind NAT is `ssh -o ProxyCommand='via
/// tunnel %h 22'`. The WebSocket's binary messages are the stream's bytes.
async fn tunnel(
    AxState(s): AxState<Arc<State>>,
    Extension(caller): Extension<db::Caller>,
    Path((device, port)): Path<(String, u16)>,
    ws: WebSocketUpgrade,
) -> Response {
    let opened = developer_on(&s, &caller, &device, "a tunnel")
        .and_then(|d| s.hub.open(&d.id, &format!("tcp:{port}")));
    s.db.audit(
        &caller.name,
        "tunnel",
        &json!({ "device": device, "port": port }),
        opened.is_ok(),
    );
    match opened {
        Ok(stream) => ws.on_upgrade(move |socket| bridge(socket, stream)),
        Err(e) => (StatusCode::NOT_FOUND, format!("{e:#}")).into_response(),
    }
}

#[derive(Deserialize)]
struct ShellQuery {
    container: Option<String>,
}

/// A terminal for a person in a browser. Audited like the tunnel; what is
/// typed in it is not recorded.
async fn shell(
    AxState(s): AxState<Arc<State>>,
    Extension(caller): Extension<db::Caller>,
    Path(device): Path<String>,
    Query(q): Query<ShellQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let service = match &q.container {
        Some(c) => format!("shell:{c}"),
        None => "shell".to_string(),
    };
    let opened =
        developer_on(&s, &caller, &device, "a terminal").and_then(|d| s.hub.open(&d.id, &service));
    s.db.audit(
        &caller.name,
        "shell",
        &json!({ "device": device, "container": q.container }),
        opened.is_ok(),
    );
    match opened {
        Ok(stream) => ws.on_upgrade(move |socket| terminal(socket, stream)),
        Err(e) => (StatusCode::NOT_FOUND, format!("{e:#}")).into_response(),
    }
}

/// Binary frames are keystrokes and text frames are `{"cols":n,"rows":n}`;
/// both go on framed as crates/via-agent/src/shell.rs reads them.
async fn terminal(socket: axum::extract::ws::WebSocket, stream: tokio::io::DuplexStream) {
    use axum::extract::ws::Message;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Deserialize)]
    struct Size {
        cols: u16,
        rows: u16,
    }
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut r, mut w) = tokio::io::split(stream);
    let up = async {
        while let Some(Ok(m)) = ws_rx.next().await {
            let sent = match m {
                Message::Binary(b) => {
                    let mut ok = true;
                    for chunk in b.chunks(u16::MAX as usize) {
                        let mut frame = vec![0];
                        frame.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                        frame.extend_from_slice(chunk);
                        ok = w.write_all(&frame).await.is_ok();
                    }
                    ok
                }
                Message::Text(t) => match serde_json::from_str::<Size>(&t) {
                    Ok(sz) => {
                        let mut frame = vec![1];
                        frame.extend_from_slice(&sz.cols.to_be_bytes());
                        frame.extend_from_slice(&sz.rows.to_be_bytes());
                        w.write_all(&frame).await.is_ok()
                    }
                    Err(_) => true,
                },
                Message::Close(_) => false,
                _ => true,
            };
            if !sent {
                break;
            }
        }
        let _ = w.shutdown().await;
    };
    let down = async {
        let mut buf = vec![0u8; 32 * 1024];
        while let Ok(n) = r.read(&mut buf).await {
            if n == 0
                || ws_tx
                    .send(Message::Binary(buf[..n].to_vec().into()))
                    .await
                    .is_err()
            {
                break;
            }
        }
        let _ = ws_tx.send(Message::Close(None)).await;
    };
    tokio::select! {
        () = up => {}
        () = down => {}
    }
}

async fn bridge(socket: axum::extract::ws::WebSocket, stream: tokio::io::DuplexStream) {
    use axum::extract::ws::Message;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut r, mut w) = tokio::io::split(stream);
    let up = async {
        while let Some(Ok(m)) = ws_rx.next().await {
            match m {
                Message::Binary(b) => {
                    if w.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = w.shutdown().await;
    };
    let down = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = ws_tx.send(Message::Close(None)).await;
    };
    tokio::join!(up, down);
}

async fn release_bundle(
    AxState(s): AxState<Arc<State>>,
    headers: HeaderMap,
    Path((app, release, arch)): Path<(String, u64, String)>,
) -> Response {
    if !matches!(
        bearer(&headers).map(|c| s.db.authenticate(c)),
        Some(Ok(Some(_)))
    ) {
        return (StatusCode::UNAUTHORIZED, "unknown device credential").into_response();
    }
    match releases::bundle_path(&s.releases_dir(), &app, release, &arch) {
        Ok(p) => {
            serve_file(
                &p,
                &format!("{app}-{release}-{arch}.bundle"),
                "application/octet-stream",
            )
            .await
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve_file(path: &std::path::Path, name: &str, content_type: &str) -> Response {
    let Ok(file) = tokio::fs::File::open(path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(file));
    (
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CONTENT_LENGTH, len.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        body,
    )
        .into_response()
}

/// The id is 96 random bits and the only way to name the file, so the link
/// itself is the credential. It is shown to whoever asked for the image.
async fn download(AxState(s): AxState<Arc<State>>, Path(id): Path<String>) -> Response {
    if id.len() != 24 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let name = std::fs::read_to_string(s.out_dir().join(format!("{id}.name")))
        .unwrap_or_else(|_| "viaos.raw.zst".into());
    serve_file(
        &s.out_dir().join(format!("{id}.raw.zst")),
        &name,
        "application/zstd",
    )
    .await
}
