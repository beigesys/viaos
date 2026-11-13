//! Publishing from GitHub Actions and fleets that follow an app, end to end:
//! a fake GitHub signs tokens, fake devices answer over real connections.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ServerCapabilities,
    ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use via_link::{Incoming, Mux, Side};

use crate::access::{self, Level};
use crate::db::Enrollment;
use crate::oidc::testing::Issuer;

/// Fleets `line` and `other`; devices `press` (x86_64), `arm` (aarch64)
/// and `late` (x86_64) in line, `far` (x86_64) in other.
struct Rig {
    url: String,
    state: Arc<crate::State>,
    gh: Issuer,
    http: reqwest::Client,
    credentials: std::collections::HashMap<String, String>,
    _dir: tempfile::TempDir,
}

async fn rig() -> Rig {
    let gh = Issuer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let mut state = crate::test_state(dir.path(), &url, None);
    Arc::get_mut(&mut state).unwrap().oidc = gh.verifier();
    let db = &state.db;
    db.create_fleet("line").unwrap();
    db.create_fleet("other").unwrap();
    let mut credentials = std::collections::HashMap::new();
    for (fleet, name, arch) in [
        ("line", "press", "x86_64"),
        ("line", "arm", "aarch64"),
        ("line", "late", "x86_64"),
        ("other", "far", "x86_64"),
    ] {
        let token = db.mint_token(fleet, Some(name), "", 60, None).unwrap();
        let (_, credential, _) = db
            .enroll(&Enrollment {
                token,
                hostname: name.into(),
                arch: Some(arch.into()),
                os_version: Some("1".into()),
                agent_version: None,
            })
            .unwrap();
        credentials.insert(name.to_string(), credential);
    }
    let router = crate::router(state.clone());
    tokio::spawn(async move {
        axum::serve(
            l,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });
    Rig {
        url,
        state,
        gh,
        http: reqwest::Client::new(),
        credentials,
        _dir: dir,
    }
}

impl Rig {
    /// A token GitHub would give a run of `repo` on `git_ref`, for us.
    fn run(&self, repo: &str, id: &str, git_ref: &str) -> String {
        self.gh.sign(&self.gh.claims(&self.url, repo, id, git_ref))
    }

    async fn reserve(&self, token: &str, app: &str) -> (u16, Value) {
        let r = self
            .http
            .post(format!("{}/v1/releases/{app}", self.url))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let text = r.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    async fn upload(&self, token: &str, app: &str, release: u64, arch: &str) -> (u16, Value) {
        let r = self
            .http
            .put(format!("{}/v1/releases/{app}/{release}/{arch}", self.url))
            .bearer_auth(token)
            .body("not a bundle")
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let text = r.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    /// Call a tool; `Ok` with its result, or `Err` with what it said.
    async fn call(&self, token: &str, tool: &str, args: Value) -> Result<Value, String> {
        let res = self
            .http
            .post(format!("{}/mcp", self.url))
            .bearer_auth(token)
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", tool)
            .json(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {
                    "name": tool, "arguments": args,
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" },
                        "io.modelcontextprotocol/clientCapabilities": {},
                    },
                },
            }))
            .send()
            .await
            .unwrap();
        if !res.status().is_success() {
            return Err(format!("{} {}", res.status(), res.text().await.unwrap()));
        }
        let body: Value = res.json().await.unwrap();
        if let Some(e) = body.get("error") {
            return Err(e["message"].as_str().unwrap_or_default().to_string());
        }
        let r = &body["result"];
        let text = r["content"][0]["text"].as_str().unwrap_or_default();
        if r["isError"] == json!(true) {
            Err(text.to_string())
        } else {
            Ok(r["structuredContent"].clone())
        }
    }

    /// Connect a device that answers every tool and remembers what it was
    /// asked to deploy.
    async fn connect(&self, name: &str) -> Device {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let url = format!("{}/v1/connect", self.url.replacen("http", "ws", 1));
        let mut req = url.into_client_request().unwrap();
        req.headers_mut().insert(
            "authorization",
            format!("Bearer {}", self.credentials[name])
                .parse()
                .unwrap(),
        );
        let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let (mux, mut outgoing, mut incoming) = Mux::new(Side::Device);
        let (mut tx, mut rx) = ws.split();
        let send = tokio::spawn(async move {
            while let Some(frame) = outgoing.recv().await {
                if tx.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
        });
        let receive = tokio::spawn(async move {
            while let Some(Ok(Message::Binary(b))) = rx.next().await {
                mux.receive(&b);
            }
        });
        let agent = FakeAgent(calls.clone());
        let serve = tokio::spawn(async move {
            while let Some(Incoming { stream, .. }) = incoming.recv().await {
                let agent = agent.clone();
                tokio::spawn(async move {
                    if let Ok(running) = agent.serve(stream).await {
                        let _ = running.waiting().await;
                    }
                });
            }
        });
        let id = self.state.db.resolve(name).unwrap().id;
        eventually(|| self.state.hub.is_online(&id)).await;
        Device {
            calls,
            tasks: vec![send, receive, serve],
            id,
        }
    }
}

struct Device {
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    id: String,
}

impl Device {
    /// The releases it was told to deploy, in order.
    fn deployed(&self) -> Vec<u64> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(tool, _)| tool == "deploy")
            .map(|(_, a)| a["release"].as_u64().unwrap())
            .collect()
    }

    fn last_deploy(&self) -> Value {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(tool, _)| tool == "deploy")
            .map(|(_, a)| a.clone())
            .unwrap_or_default()
    }

    async fn disconnect(self, state: &crate::State) {
        for t in self.tasks {
            t.abort();
        }
        eventually(|| !state.hub.is_online(&self.id)).await;
    }
}

#[derive(Clone)]
struct FakeAgent(Arc<Mutex<Vec<(String, Value)>>>);

impl ServerHandler for FakeAgent {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.0.lock().unwrap().push((
            request.name.to_string(),
            Value::Object(request.arguments.unwrap_or_default()),
        ));
        Ok(CallToolResult::success(vec![ContentBlock::text("ok")]).into())
    }

    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

async fn eventually(mut done: impl FnMut() -> bool) {
    for _ in 0..100 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out");
}

#[tokio::test]
async fn a_run_releases_its_own_apps_and_does_nothing_else() {
    let r = rig().await;
    let admin = access::create_token(&r.state.db, "boss", None, None).unwrap();
    let dev = access::create_token(&r.state.db, "dev", Some(Level::Developer), None).unwrap();

    // Only an admin names publishers.
    let e = r
        .call(
            &dev,
            "add_publisher",
            json!({ "repository": "acme/app", "apps": ["web"] }),
        )
        .await
        .unwrap_err();
    assert!(e.contains("needs an admin"), "{e}");
    let added = r
        .call(
            &admin,
            "add_publisher",
            json!({ "repository": "Acme/App", "apps": ["web"] }),
        )
        .await
        .unwrap();
    assert_eq!(
        added["publisher"]["refs"],
        json!(["refs/heads/via", "refs/tags/v*"])
    );
    assert!(
        added["workflow"]
            .as_str()
            .unwrap()
            .contains("id-token: write")
    );

    let run = r.run("acme/App", "7", "refs/heads/via");
    let (status, v) = r.reserve(&run, "web").await;
    assert_eq!((status, v["release"].as_u64()), (200, Some(1)));
    let (status, _) = r.upload(&run, "web", 1, "x86_64").await;
    assert_eq!(status, 200);
    // Immutable: the same again is refused, and a re-run gets a new number.
    let (status, v) = r.upload(&run, "web", 1, "x86_64").await;
    assert_eq!(status, 400, "{v}");
    assert!(v.as_str().unwrap().contains("immutable"));
    assert_eq!(r.reserve(&run, "web").await.1["release"], 2);
    // People's numbers carry on from the same count.
    assert_eq!(r.reserve(&dev, "web").await.1["release"], 3);

    // Not another app.
    let (status, v) = r.upload(&run, "api", 1, "x86_64").await;
    assert_eq!(status, 403, "{v}");
    assert_eq!(r.reserve(&run, "api").await.0, 403);
    // Not from another ref, another repository, or for another server.
    let (status, v) = r
        .upload(
            &r.run("acme/app", "7", "refs/heads/main"),
            "web",
            5,
            "x86_64",
        )
        .await;
    assert_eq!(status, 403);
    assert!(v.as_str().unwrap().contains("not refs/heads/main"), "{v}");
    let (status, _) = r
        .upload(
            &r.run("acme/app", "8", "refs/heads/via"),
            "web",
            5,
            "x86_64",
        )
        .await;
    assert_eq!(status, 403);
    let (status, _) = r
        .upload(
            &r.run("evil/app", "9", "refs/heads/via"),
            "web",
            5,
            "x86_64",
        )
        .await;
    assert_eq!(status, 403);
    let elsewhere = r.gh.sign(&r.gh.claims(
        "https://other.example.com",
        "acme/app",
        "7",
        "refs/heads/via",
    ));
    assert_eq!(r.upload(&elsewhere, "web", 5, "x86_64").await.0, 401);

    // Nothing but releases: not MCP, not the session, not OS updates.
    let e = r.call(&run, "list_releases", json!({})).await.unwrap_err();
    assert!(e.starts_with("401"), "{e}");
    for (method, path) in [
        (reqwest::Method::GET, "/v1/session"),
        (reqwest::Method::PUT, "/v1/os/x86_64/2/manifest.json"),
        (reqwest::Method::GET, "/v1/devices/press/shell"),
    ] {
        let res = r
            .http
            .request(method, format!("{}{path}", r.url))
            .bearer_auth(&run)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401, "{path}");
    }

    let log = r.call(&admin, "audit_log", json!({})).await.unwrap();
    let entries = log["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["tool"] == "upload_release"
        && e["actor"] == "github-actions:acme/app@refs/heads/via"
        && e["ok"] == true));
    assert!(entries.iter().any(|e| e["tool"] == "publish_refused"));

    // Removed: refused at once.
    r.call(
        &admin,
        "remove_publisher",
        json!({ "repository": "acme/app" }),
    )
    .await
    .unwrap();
    assert_eq!(r.reserve(&run, "web").await.0, 403);
}

#[tokio::test]
async fn a_following_fleet_gets_each_new_release() {
    let r = rig().await;
    r.state
        .db
        .set_publisher(&crate::publish::Publisher {
            repository: "acme/app".into(),
            repository_id: Some("7".into()),
            refs: vec!["refs/heads/via".into()],
            apps: vec!["web".into()],
            created_at: 0,
            created_by: "t".into(),
        })
        .unwrap();
    let run = r.run("acme/app", "7", "refs/heads/via");
    // Release 1 is there before anyone follows.
    r.upload(&run, "web", 1, "x86_64").await;

    let dev =
        access::create_token(&r.state.db, "dev", Some(Level::Developer), Some("line")).unwrap();
    let obs =
        access::create_token(&r.state.db, "obs", Some(Level::Observer), Some("line")).unwrap();
    let e = r
        .call(&obs, "follow_app", json!({ "fleet": "line", "app": "web" }))
        .await
        .unwrap_err();
    assert!(e.contains("is an observer on"), "{e}");
    let e = r
        .call(
            &dev,
            "follow_app",
            json!({ "fleet": "other", "app": "web" }),
        )
        .await
        .unwrap_err();
    assert!(e.starts_with("no fleet named"), "{e}");
    let f = r
        .call(&dev, "follow_app", json!({ "fleet": "line", "app": "web" }))
        .await
        .unwrap();
    assert_eq!(f["since"], 1);
    let listed = r.call(&obs, "list_follows", json!({})).await.unwrap();
    assert_eq!(listed["follows"][0]["fleet"], "line");

    let press = r.connect("press").await;
    let arm = r.connect("arm").await;
    let far = r.connect("far").await;
    // Connecting sends nothing it already had or that came before following.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(press.deployed().is_empty());

    let (status, v) = r.upload(&run, "web", 2, "x86_64").await;
    assert_eq!(status, 200, "{v}");
    let sent = &v["auto_deploy"][0];
    assert_eq!(sent["fleet"], "line");
    let devices: Vec<&str> = sent["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["device"].as_str().unwrap())
        .collect();
    assert_eq!(devices, ["late", "press"]);
    assert_eq!(
        sent["devices"][0]["skipped"].as_str().unwrap()[..7],
        *"offline"
    );
    assert_eq!(press.deployed(), [2]);
    let d = press.last_deploy();
    assert_eq!(d["app"], "web");
    assert_eq!(d["source"], format!("{}/v1/releases/web/2/x86_64", r.url));
    assert_eq!(d["sha256"].as_str().unwrap().len(), 64);
    // Only its arch, and only following fleets.
    assert!(arm.deployed().is_empty());
    assert!(far.deployed().is_empty());
    r.upload(&run, "web", 2, "aarch64").await;
    assert_eq!(arm.deployed(), [2]);
    assert!(far.deployed().is_empty());

    // Offline at the time: it catches up when it connects, once.
    let late = r.connect("late").await;
    eventually(|| late.deployed() == [2]).await;
    late.disconnect(&r.state).await;
    let late = r.connect("late").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(late.deployed().is_empty());

    let admin = access::create_token(&r.state.db, "boss", None, None).unwrap();
    let log = r.call(&admin, "audit_log", json!({})).await.unwrap();
    let auto: Vec<&Value> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["tool"] == "auto_deploy")
        .collect();
    assert_eq!(auto.len(), 3, "{auto:?}");
    assert!(auto.iter().any(|e| e["actor"] == "auto-deploy"));
    assert!(
        auto.iter()
            .any(|e| e["actor"] == "github-actions:acme/app@refs/heads/via")
    );

    // Stopped: the next release goes nowhere.
    r.call(
        &dev,
        "follow_app",
        json!({ "fleet": "line", "app": "web", "follow": false }),
    )
    .await
    .unwrap();
    let (_, v) = r.upload(&run, "web", 3, "x86_64").await;
    assert_eq!(v["auto_deploy"], json!([]));
    assert_eq!(press.deployed(), [2]);
}
