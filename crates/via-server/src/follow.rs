//! Fleets that follow an app: each release of it uploaded after the fleet
//! started following is deployed to the fleet's devices, and the fleets
//! under it, as soon as their architecture's build arrives.
//!
//! It is the same deploy a person starts: the device holds the release to its
//! health gate and puts the previous one back if it fails. A device that was
//! offline gets the newest release when it reconnects. What each device was
//! sent is kept, so a release that failed its gate isn't sent again on every
//! reconnect, and a device someone deployed an older release to by hand
//! keeps it until the next release.

use anyhow::{Context, Result};
use rmcp::model::JsonObject;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::State;
use crate::db::{Db, Device, now};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS follows (
    fleet_id    INTEGER NOT NULL REFERENCES fleets(id) ON DELETE CASCADE,
    app         TEXT NOT NULL,
    since       INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    created_by  TEXT NOT NULL,
    PRIMARY KEY (fleet_id, app)
);
CREATE TABLE IF NOT EXISTS follow_sent (
    device_id  TEXT NOT NULL,
    app        TEXT NOT NULL,
    release    INTEGER NOT NULL,
    PRIMARY KEY (device_id, app)
);
";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Follow {
    pub fleet: String,
    pub app: String,
    /// The newest release when it started following. Only later ones are
    /// sent.
    pub since: u64,
    pub created_at: i64,
    pub created_by: String,
}

impl Db {
    pub fn follows(&self) -> Result<Vec<Follow>> {
        let c = self.conn.lock().unwrap();
        let mut q = c.prepare(
            "SELECT f.name, w.app, w.since, w.created_at, w.created_by
             FROM follows w JOIN fleets f ON f.id = w.fleet_id ORDER BY f.name, w.app",
        )?;
        let rows = q.query_map([], |r| {
            Ok(Follow {
                fleet: r.get(0)?,
                app: r.get(1)?,
                since: r.get::<_, i64>(2)? as u64,
                created_at: r.get(3)?,
                created_by: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Start following. Already following leaves it as it was.
    pub fn set_follow(&self, fleet: &str, app: &str, since: u64, by: &str) -> Result<()> {
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "INSERT INTO follows (fleet_id, app, since, created_at, created_by)
             SELECT id, ?2, ?3, ?4, ?5 FROM fleets WHERE name = ?1
             ON CONFLICT (fleet_id, app) DO NOTHING",
            params![fleet, app, since as i64, now(), by],
        )?;
        anyhow::ensure!(
            n > 0 || following(&c, fleet, app)?,
            "no fleet named {fleet:?}"
        );
        Ok(())
    }

    pub fn delete_follow(&self, fleet: &str, app: &str) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        Ok(c.execute(
            "DELETE FROM follows WHERE app = ?2
             AND fleet_id = (SELECT id FROM fleets WHERE name = ?1)",
            params![fleet, app],
        )? > 0)
    }

    /// Mark `release` as sent to a device, unless it or a later one was.
    /// Gives what was marked before, to put back if sending fails.
    fn claim_send(&self, device: &str, app: &str, release: u64) -> Result<Option<Option<u64>>> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let before: Option<i64> = tx
            .query_row(
                "SELECT release FROM follow_sent WHERE device_id = ?1 AND app = ?2",
                params![device, app],
                |r| r.get(0),
            )
            .optional()?;
        if before.is_some_and(|b| b as u64 >= release) {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO follow_sent (device_id, app, release) VALUES (?1, ?2, ?3)
             ON CONFLICT (device_id, app) DO UPDATE SET release = excluded.release",
            params![device, app, release as i64],
        )?;
        tx.commit()?;
        Ok(Some(before.map(|b| b as u64)))
    }

    fn unclaim_send(&self, device: &str, app: &str, before: Option<u64>) -> Result<()> {
        let c = self.conn.lock().unwrap();
        match before {
            Some(b) => c.execute(
                "UPDATE follow_sent SET release = ?3 WHERE device_id = ?1 AND app = ?2",
                params![device, app, b as i64],
            )?,
            None => c.execute(
                "DELETE FROM follow_sent WHERE device_id = ?1 AND app = ?2",
                params![device, app],
            )?,
        };
        Ok(())
    }
}

fn following(c: &rusqlite::Connection, fleet: &str, app: &str) -> Result<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM follows w JOIN fleets f ON f.id = w.fleet_id
         WHERE f.name = ?1 AND w.app = ?2",
        params![fleet, app],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

/// The highest release number `app` has a build of, or 0.
pub fn newest(s: &State, app: &str) -> u64 {
    crate::releases::list(&s.releases_dir(), Some(app))
        .first()
        .map_or(0, |r| r.release)
}

/// A release's build for `arch` was just uploaded: deploy it to the devices
/// of that arch in every fleet that follows the app. One entry per fleet.
pub async fn released(s: &State, actor: &str, app: &str, release: u64, arch: &str) -> Vec<Value> {
    let follows = match s.db.follows() {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("reading follows failed: {e:#}");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for f in follows
        .into_iter()
        .filter(|f| f.app == app && release > f.since)
    {
        let devices: Vec<Device> =
            s.db.devices(Some(&f.fleet))
                .unwrap_or_default()
                .into_iter()
                .filter(|d| d.arch.as_deref() == Some(arch))
                .collect();
        let results =
            futures_util::future::join_all(devices.iter().map(|d| send(s, d, app, release))).await;
        let ok = results.iter().all(|r| r.get("error").is_none());
        let entry = json!({ "fleet": f.fleet, "app": app, "release": release, "arch": arch, "devices": results });
        s.db.audit(actor, "auto_deploy", &entry, ok);
        out.push(entry);
    }
    out
}

/// A device just connected: send it the newest release of each app its
/// fleets follow, if it missed one while it was away.
pub async fn catch_up(s: &State, d: &Device) {
    let (Ok(lineage), Ok(follows)) = (s.db.fleet_lineage(&d.fleet), s.db.follows()) else {
        return;
    };
    let mut apps: Vec<(&str, u64, &str)> = Vec::new();
    for f in follows.iter().filter(|f| lineage.contains(&f.fleet)) {
        match apps.iter_mut().find(|(a, _, _)| *a == f.app) {
            Some(seen) if f.since < seen.1 => *seen = (&f.app, f.since, &f.fleet),
            Some(_) => {}
            None => apps.push((&f.app, f.since, &f.fleet)),
        }
    }
    let arch = d.arch.as_deref().unwrap_or_default();
    for (app, since, fleet) in apps {
        let Some(release) = crate::releases::list(&s.releases_dir(), Some(app))
            .into_iter()
            .find(|r| r.artifacts.iter().any(|a| a.arch == arch))
            .map(|r| r.release)
            .filter(|r| *r > since)
        else {
            continue;
        };
        let r = send(s, d, app, release).await;
        if r.get("skipped").is_none() {
            let ok = r.get("error").is_none();
            let entry = json!({ "fleet": fleet, "app": app, "release": release, "arch": arch, "devices": [r], "reconnected": true });
            s.db.audit("auto-deploy", "auto_deploy", &entry, ok);
        }
    }
}

/// Deploy to one device unless it was already sent this release or a later
/// one. Offline devices are left for `catch_up`.
async fn send(s: &State, d: &Device, app: &str, release: u64) -> Value {
    let mut r = json!({ "device": d.name, "id": d.id });
    if !s.hub.is_online(&d.id) {
        r["skipped"] = json!("offline; it gets the release when it reconnects");
        return r;
    }
    let before = match s.db.claim_send(&d.id, app, release) {
        Ok(Some(before)) => before,
        Ok(None) => {
            r["skipped"] = json!("already sent this release or a later one");
            return r;
        }
        Err(e) => {
            r["error"] = json!(format!("{e:#}"));
            return r;
        }
    };
    match deploy(s, d, app, release).await {
        Ok(()) => r["started"] = json!(true),
        Err(e) => {
            // Not sent after all, so the next upload or reconnect tries again.
            let _ = s.db.unclaim_send(&d.id, app, before);
            r["error"] = json!(format!("{e:#}"));
        }
    }
    r
}

/// What the `deploy` tool does for one device.
async fn deploy(s: &State, d: &Device, app: &str, release: u64) -> Result<()> {
    let arch = d.arch.clone().unwrap_or_default();
    let art = crate::releases::artifact(&s.releases_dir(), app, release, &arch)?;
    if let Err(e) = crate::secrets::push(s, d).await {
        tracing::warn!(device = %d.name, "sending variables failed: {e:#}");
    }
    let mut args = JsonObject::new();
    args.insert("app".into(), json!(app));
    args.insert("release".into(), json!(release));
    args.insert(
        "source".into(),
        json!(format!(
            "{}/v1/releases/{app}/{release}/{arch}",
            s.public_url
        )),
    );
    args.insert("sha256".into(), json!(art.sha256));
    let res = s
        .hub
        .call(&d.id, "deploy", args)
        .await
        .context("calling the device")?;
    anyhow::ensure!(
        res.is_error != Some(true),
        "{}",
        res.content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect::<Vec<_>>()
            .join(" ")
    );
    Ok(())
}
