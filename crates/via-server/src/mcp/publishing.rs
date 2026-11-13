//! Tools for publishing from GitHub and for fleets that follow an app. Kept
//! beside the rest of the fleet's tools; `Fleet::new` joins the two routers.

use super::*;
use crate::publish::{self, Publisher};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PublisherArgs {
    /// `owner/name` on GitHub.
    pub repository: String,
    /// The apps its workflow runs may release.
    pub apps: Vec<String>,
    /// Refs a run may publish from, exact or with `*`. Omit for
    /// `refs/heads/via` and `refs/tags/v*`.
    #[serde(default)]
    pub refs: Vec<String>,
    /// GitHub's number for the repository, so one made again under the same
    /// name is refused. Omit to pin whatever the first upload shows.
    #[serde(default)]
    pub repository_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RepositoryArg {
    /// `owner/name` on GitHub.
    pub repository: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FollowArgs {
    pub fleet: String,
    /// Application name, from `list_releases`.
    pub app: String,
    /// False stops following.
    #[serde(default = "yes")]
    pub follow: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ListFollowsArgs {
    /// Only this fleet. Omit for every fleet you can see.
    #[serde(default)]
    pub fleet: Option<String>,
}

#[tool_router(router = publishing_router, vis = "pub(super)")]
impl Fleet {
    #[tool(
        name = "list_publishers",
        description = "GitHub repositories whose Actions runs may upload releases, with the \
                       apps and refs each may publish and the workflow file it uses. They sign \
                       in with GitHub's OIDC token, so no API token is stored in them. Reads \
                       only.",
        annotations(
            title = "List publishers",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_publishers(&self) -> Result<CallToolResult, ErrorData> {
        self.audited("list_publishers", json!({}), async {
            let publishers: Vec<Value> = self
                .state
                .db
                .publishers()?
                .into_iter()
                .map(|p| {
                    let workflow = publish::workflow(&self.state.public_url, &p.apps[0]);
                    let mut v = json!(p);
                    v["workflow"] = json!(workflow);
                    v
                })
                .collect();
            Ok(rendered(json!({ "publishers": publishers })))
        })
        .await
    }

    #[tool(
        name = "add_publisher",
        description = "Let a GitHub repository's Actions runs upload releases of some apps, \
                       from some refs, with no token: they show GitHub's OIDC token instead. \
                       Replaces what it could do if it was already one. Returns the workflow \
                       file the repository adds. A run can upload releases of its apps and \
                       nothing else.",
        annotations(
            title = "Add publisher",
            read_only_hint = false,
            destructive_hint = false
        )
    )]
    async fn add_publisher(
        &self,
        Parameters(a): Parameters<PublisherArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let args = json!({ "repository": a.repository, "apps": a.apps, "refs": a.refs, "repository_id": a.repository_id });
        self.audited("add_publisher", args, async {
            let repository = publish::check_repository(&a.repository)?;
            anyhow::ensure!(!a.apps.is_empty(), "name at least one app");
            for app in &a.apps {
                anyhow::ensure!(
                    crate::releases::valid_app(app),
                    "{app:?} is not an app name: lowercase letters, digits and dashes"
                );
            }
            let refs: Vec<String> = if a.refs.is_empty() {
                publish::DEFAULT_REFS
                    .iter()
                    .map(|r| r.to_string())
                    .collect()
            } else {
                a.refs.clone()
            };
            for r in &refs {
                publish::check_ref_pattern(r)?;
            }
            if let Some(id) = &a.repository_id {
                anyhow::ensure!(
                    !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit()),
                    "{id:?} is not a repository id: GitHub's is a number"
                );
            }
            let caller = CALLER.try_with(|c| c.name.clone()).unwrap_or_default();
            let p = Publisher {
                repository,
                repository_id: a.repository_id.clone(),
                refs,
                apps: a.apps.clone(),
                created_at: crate::db::now(),
                created_by: caller,
            };
            self.state.db.set_publisher(&p)?;
            Ok(rendered(json!({
                "publisher": p,
                "workflow": publish::workflow(&self.state.public_url, &p.apps[0]),
                "next": "Add the workflow as .github/workflows/via.yml in the repository. \
                         Each push to a matching ref uploads a release.",
            })))
        })
        .await
    }

    #[tool(
        name = "remove_publisher",
        description = "Stop a GitHub repository's runs uploading releases, at once.",
        annotations(
            title = "Remove publisher",
            read_only_hint = false,
            destructive_hint = true
        )
    )]
    async fn remove_publisher(
        &self,
        Parameters(a): Parameters<RepositoryArg>,
    ) -> Result<CallToolResult, ErrorData> {
        self.audited(
            "remove_publisher",
            json!({ "repository": a.repository }),
            async {
                anyhow::ensure!(
                    self.state.db.delete_publisher(a.repository.trim())?,
                    "{} is not a publisher; `list_publishers` shows them",
                    a.repository
                );
                Ok(rendered(json!({ "removed": a.repository })))
            },
        )
        .await
    }

    #[tool(
        name = "list_follows",
        description = "Which fleets follow which apps: each new release of the app is deployed \
                       to the fleet, and the fleets under it, as it is uploaded. Reads only.",
        annotations(title = "List follows", read_only_hint = true, open_world_hint = false)
    )]
    async fn list_follows(
        &self,
        Parameters(a): Parameters<ListFollowsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.audited("list_follows", json!({ "fleet": a.fleet }), async {
            if let Some(f) = &a.fleet {
                self.fleet_for(f, Level::Observer, "listing what it follows")?;
            }
            let access = self.access()?;
            let follows: Vec<_> = self
                .state
                .db
                .follows()?
                .into_iter()
                .filter(|f| access.sees(&f.fleet))
                .filter(|f| a.fleet.as_ref().is_none_or(|x| *x == f.fleet))
                .collect();
            Ok(rendered(json!({ "follows": follows })))
        })
        .await
    }

    #[tool(
        name = "follow_app",
        description = "Make a fleet follow an app: every release of it uploaded from now on is \
                       deployed to the fleet's devices, and those of the fleets under it, as \
                       each architecture's build arrives. Each device holds it to the health \
                       gate and rolls back by itself, as with `deploy`; an offline device gets \
                       the newest when it reconnects. `follow: false` stops it. Nothing is \
                       deployed until the next release.",
        annotations(title = "Follow app", read_only_hint = false, destructive_hint = true)
    )]
    async fn follow_app(
        &self,
        Parameters(a): Parameters<FollowArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let args = json!({ "fleet": a.fleet, "app": a.app, "follow": a.follow });
        self.audited("follow_app", args, async {
            self.fleet_for(&a.fleet, Level::Developer, "following an app")?;
            anyhow::ensure!(
                crate::releases::valid_app(&a.app),
                "{:?} is not an app name",
                a.app
            );
            if !a.follow {
                anyhow::ensure!(
                    self.state.db.delete_follow(&a.fleet, &a.app)?,
                    "{} doesn't follow {}",
                    a.fleet,
                    a.app
                );
                return Ok(rendered(
                    json!({ "fleet": a.fleet, "app": a.app, "following": false }),
                ));
            }
            let since = crate::follow::newest(&self.state, &a.app);
            let caller = CALLER.try_with(|c| c.name.clone()).unwrap_or_default();
            self.state
                .db
                .set_follow(&a.fleet, &a.app, since, &caller)?;
            // Already following keeps the release it started from.
            let since = self
                .state
                .db
                .follows()?
                .into_iter()
                .find(|f| f.fleet == a.fleet && f.app == a.app)
                .map_or(since, |f| f.since);
            Ok(rendered(json!({
                "fleet": a.fleet,
                "app": a.app,
                "following": true,
                "since": since,
                "next": format!("Releases of {} after {since} deploy to {} as they are uploaded.", a.app, a.fleet),
            })))
        })
        .await
    }
}
