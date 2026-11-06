//! The registry: fleets, devices, enrollment tokens, API tokens, and the
//! audit log.
//!
//! One SQLite file, one connection behind a mutex. A control plane for a few
//! thousand devices does a handful of writes a second at most; a pool would
//! be machinery for a load that does not exist.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS fleets (
    id    INTEGER PRIMARY KEY,
    name  TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS devices (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    fleet_id        INTEGER NOT NULL REFERENCES fleets(id),
    credential_hash TEXT NOT NULL UNIQUE,
    arch            TEXT,
    os_version      TEXT,
    agent_version   TEXT,
    enrolled_at     INTEGER NOT NULL,
    last_seen       INTEGER
);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash  TEXT PRIMARY KEY,
    fleet_id    INTEGER NOT NULL REFERENCES fleets(id),
    hostname    TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_by     TEXT,
    image_id    TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY,
    at     INTEGER NOT NULL,
    tool   TEXT NOT NULL,
    args   TEXT NOT NULL,
    ok     INTEGER NOT NULL
);
-- Variables and secrets for apps. `scope` is 'fleet' (target: its name) or
-- 'device' (target: its id). A secret's value is ciphertext; see secrets.rs.
-- `service` is one service of the app, or NULL for every service that declares
-- the name; VARIABLES_IDENTITY makes a row unique.
CREATE TABLE IF NOT EXISTS variables (
    scope TEXT NOT NULL,
    target TEXT NOT NULL,
    app TEXT NOT NULL,
    service TEXT,
    key TEXT NOT NULL,
    value BLOB NOT NULL,
    secret INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    name        TEXT PRIMARY KEY,
    role        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    last_used   INTEGER
);
CREATE TABLE IF NOT EXISTS os_updates (
    device_id     TEXT PRIMARY KEY,
    version       TEXT NOT NULL,
    from_version  TEXT,
    started_at    INTEGER NOT NULL,
    finished_at   INTEGER,
    state         TEXT NOT NULL,
    progress      INTEGER,
    detail        TEXT,
    offline_since INTEGER
);
CREATE TABLE IF NOT EXISTS fleet_tags (
    fleet_id  INTEGER NOT NULL REFERENCES fleets(id),
    tag       TEXT NOT NULL,
    PRIMARY KEY (fleet_id, tag)
);
CREATE TABLE IF NOT EXISTS device_tags (
    device_id TEXT NOT NULL REFERENCES devices(id),
    tag       TEXT NOT NULL,
    PRIMARY KEY (device_id, tag)
);
CREATE TABLE IF NOT EXISTS device_types (
    id      TEXT PRIMARY KEY,
    name    TEXT NOT NULL,
    arch    TEXT NOT NULL,
    detail  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    role        TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
);
";

/// Grants: a role (see access::Level, stored as its rank) for a subject on a
/// fleet, or on every fleet when `fleet_id` is NULL. Made by the first start
/// that has it, so the migration can carry what viewers could do across.
const GRANTS: &str = "
CREATE TABLE grants (
    subject     TEXT NOT NULL,
    fleet_id    INTEGER REFERENCES fleets(id),
    level       INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX grants_identity ON grants (subject, IFNULL(fleet_id, 0));
";

/// How a console session's token starts, so it is never looked up as an API
/// token and an API token is never looked up as a session.
pub const SESSION_PREFIX: &str = "vis_";

/// What a person (or their Claude) may do through the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Everything: every fleet, uploads, tokens, grants, device types.
    Admin,
    /// What their grants give them; see [`crate::access`].
    Member,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Role::Admin),
            // Viewers became members with a grant to observe every fleet.
            "member" | "viewer" => Some(Role::Member),
            _ => None,
        }
    }
}

/// Whoever an API request authenticated as.
#[derive(Debug, Clone, Serialize)]
pub struct Caller {
    pub name: String,
    pub role: Role,
    /// What grants can name it by; see [`crate::access::check_subject`].
    pub subjects: Vec<String>,
}

impl Caller {
    pub fn admin(name: &str) -> Self {
        Self {
            name: name.into(),
            role: Role::Admin,
            subjects: Vec::new(),
        }
    }

    fn token(name: String, role: Role) -> Self {
        Self {
            subjects: vec![format!("token:{name}")],
            name,
            role,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Grant {
    pub subject: String,
    /// `None`: every fleet.
    pub fleet: Option<String>,
    pub level: crate::access::Level,
}

/// Hardware the server can make images for. Its base image is
/// `viaos-<id>.raw`, or the one for its architecture if it has none of its
/// own, so a board can be added without building anything new.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceType {
    pub id: String,
    pub name: String,
    pub arch: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiToken {
    pub name: String,
    pub role: Role,
    pub created_at: i64,
    pub last_used: Option<i64>,
}

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Fleet {
    pub name: String,
    /// The fleet this one sits under, if any.
    pub parent: Option<String>,
    pub tags: Vec<String>,
    /// Devices directly in this fleet, not those in fleets under it.
    pub devices: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub fleet: String,
    pub arch: Option<String>,
    pub os_version: Option<String>,
    pub agent_version: Option<String>,
    pub enrolled_at: i64,
    pub last_seen: Option<i64>,
    /// Its own. See [`check_tag`].
    pub tags: Vec<String>,
}

/// What a device reports about itself when it enrolls.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Enrollment {
    pub token: String,
    pub hostname: String,
    pub arch: Option<String>,
    pub os_version: Option<String>,
    pub agent_version: Option<String>,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Secrets are stored as their SHA-256. They are 256 random bits, so a slow
/// hash would add nothing.
pub fn hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

pub fn random_secret() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        let nested = conn
            .prepare("SELECT 1 FROM pragma_table_info('fleets') WHERE name = 'parent_id'")?
            .exists([])?;
        if !nested {
            conn.execute_batch(
                "ALTER TABLE fleets ADD COLUMN parent_id INTEGER REFERENCES fleets(id)",
            )?;
        }
        // What a new server can image from the OS builds in this repository.
        // The arm64 image carries both Pi firmware and a UEFI loader.
        let types: i64 = conn.query_row("SELECT count(*) FROM device_types", [], |r| r.get(0))?;
        if types == 0 {
            conn.execute_batch(
                "INSERT INTO device_types (id, name, arch, detail) VALUES
                 ('pc', 'PC', 'x86_64', 'Industrial boxes, NUCs, anything with UEFI'),
                 ('raspberry-pi', 'Raspberry Pi', 'aarch64', 'Pi 4, 400, CM4'),
                 ('arm64-uefi', 'Generic ARM64', 'aarch64', 'Boards and VMs with UEFI firmware');",
            )?;
        }
        // Added after the first release of the schema.
        let has_actor: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('audit') WHERE name = 'actor'")?
            .exists([])?;
        if !has_actor {
            conn.execute_batch("ALTER TABLE audit ADD COLUMN actor TEXT")?;
        }
        // The first `variables` had (scope, target, app, key) as its primary
        // key, which no ALTER can widen, and that would allow only one value
        // per name. Rows move across unchanged, so sealed values still open.
        let has_service: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('variables') WHERE name = 'service'")?
            .exists([])?;
        if !has_service {
            conn.execute_batch(
                "BEGIN;
                 ALTER TABLE variables RENAME TO variables_before_service;
                 CREATE TABLE variables (
                     scope TEXT NOT NULL,
                     target TEXT NOT NULL,
                     app TEXT NOT NULL,
                     service TEXT,
                     key TEXT NOT NULL,
                     value BLOB NOT NULL,
                     secret INTEGER NOT NULL,
                     updated_at INTEGER NOT NULL,
                     updated_by TEXT NOT NULL
                 );
                 INSERT INTO variables
                     (scope, target, app, service, key, value, secret, updated_at, updated_by)
                     SELECT scope, target, app, NULL, key, value, secret, updated_at, updated_by
                     FROM variables_before_service;
                 DROP TABLE variables_before_service;
                 COMMIT;",
            )?;
        }
        conn.execute_batch(VARIABLES_IDENTITY)?;
        let has_grants = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'grants'")?
            .exists([])?;
        if !has_grants {
            // Everyone who could look still can: viewer tokens, and every
            // member of the GitHub organisation. Their sessions end, since
            // they say nothing of who they answer to.
            conn.execute_batch(&format!(
                "BEGIN;
                 {GRANTS}
                 INSERT INTO grants (subject, fleet_id, level, created_at)
                     SELECT 'token:' || name, NULL, 1, unixepoch() FROM api_tokens
                     WHERE role = 'viewer';
                 UPDATE api_tokens SET role = 'member' WHERE role = 'viewer';
                 INSERT INTO grants (subject, fleet_id, level, created_at)
                     VALUES ('github-org', NULL, 1, unixepoch());
                 DELETE FROM sessions WHERE role != 'admin';
                 ALTER TABLE sessions ADD COLUMN subjects TEXT NOT NULL DEFAULT '';
                 COMMIT;"
            ))?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn create_fleet(&self, name: &str) -> Result<()> {
        valid_name(name)?;
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO fleets (name) VALUES (?1) ON CONFLICT DO NOTHING",
            [name],
        )?;
        Ok(())
    }

    pub fn fleets(&self) -> Result<Vec<Fleet>> {
        let c = self.conn.lock().unwrap();
        let mut q = c.prepare(
            "SELECT f.name, p.name, COUNT(d.id),
                    (SELECT group_concat(tag, char(10)) FROM
                       (SELECT tag FROM fleet_tags WHERE fleet_id = f.id ORDER BY tag))
             FROM fleets f
             LEFT JOIN fleets p ON p.id = f.parent_id
             LEFT JOIN devices d ON d.fleet_id = f.id GROUP BY f.id ORDER BY f.name",
        )?;
        let rows = q.query_map([], |r| {
            let tags: Option<String> = r.get(3)?;
            Ok(Fleet {
                name: r.get(0)?,
                parent: r.get(1)?,
                devices: r.get::<_, i64>(2)? as u64,
                tags: tags
                    .map(|t| t.split('\n').map(String::from).collect())
                    .unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The start of a device's update. Each device keeps only its latest.
    pub fn begin_os_update(
        &self,
        device_id: &str,
        version: &str,
        from: Option<&str>,
    ) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO os_updates (device_id, version, from_version, started_at, state)
             VALUES (?1, ?2, ?3, ?4, 'started')",
            params![device_id, version, from, now()],
        )?;
        Ok(())
    }

    pub fn save_os_update(&self, u: &crate::os_track::OsUpdate) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE os_updates SET finished_at = ?2, state = ?3, progress = ?4, detail = ?5,
             offline_since = ?6 WHERE device_id = ?1",
            params![
                u.device_id,
                u.finished_at,
                u.state,
                u.progress,
                u.detail,
                u.offline_since
            ],
        )?;
        Ok(())
    }

    fn os_updates_where(&self, clause: &str) -> Result<Vec<crate::os_track::OsUpdate>> {
        let c = self.conn.lock().unwrap();
        let mut q = c.prepare(&format!(
            "SELECT device_id, version, from_version, started_at, finished_at, state, progress,
                    detail, offline_since FROM os_updates {clause}"
        ))?;
        let rows = q.query_map([], |r| {
            Ok(crate::os_track::OsUpdate {
                device_id: r.get(0)?,
                version: r.get(1)?,
                from_version: r.get(2)?,
                started_at: r.get(3)?,
                finished_at: r.get(4)?,
                state: r.get(5)?,
                progress: r.get(6)?,
                detail: r.get(7)?,
                offline_since: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn active_os_updates(&self) -> Result<Vec<crate::os_track::OsUpdate>> {
        self.os_updates_where("WHERE finished_at IS NULL")
    }

    pub fn os_updates(&self) -> Result<Vec<crate::os_track::OsUpdate>> {
        self.os_updates_where("")
    }

    /// Delete a fleet that holds nothing. Unused enrollment tokens go with it,
    /// so an image made for it can no longer join.
    pub fn delete_fleet(&self, name: &str) -> Result<()> {
        let mut c = self.conn.lock().unwrap();
        let id = fleet_id(&c, name)?;
        let devices: i64 = c.query_row(
            "SELECT COUNT(*) FROM devices WHERE fleet_id = ?1",
            [id],
            |r| r.get(0),
        )?;
        anyhow::ensure!(devices == 0, "{name:?} still has devices");
        let children: i64 = c.query_row(
            "SELECT COUNT(*) FROM fleets WHERE parent_id = ?1",
            [id],
            |r| r.get(0),
        )?;
        anyhow::ensure!(children == 0, "{name:?} still has fleets under it");
        let tx = c.transaction()?;
        tx.execute("DELETE FROM fleet_tags WHERE fleet_id = ?1", [id])?;
        tx.execute("DELETE FROM grants WHERE fleet_id = ?1", [id])?;
        tx.execute("DELETE FROM enrollment_tokens WHERE fleet_id = ?1", [id])?;
        tx.execute(
            "DELETE FROM variables WHERE scope = 'fleet' AND target = ?1",
            [name],
        )?;
        tx.execute("DELETE FROM fleets WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    /// A fleet and the fleets above it, outermost first.
    pub fn fleet_lineage(&self, name: &str) -> Result<Vec<String>> {
        let c = self.conn.lock().unwrap();
        let mut q = c.prepare(
            "WITH RECURSIVE up(id, name, parent_id, depth) AS (
               SELECT id, name, parent_id, 0 FROM fleets WHERE name = ?1
               UNION ALL
               SELECT f.id, f.name, f.parent_id, up.depth + 1 FROM fleets f JOIN up ON f.id = up.parent_id
             ) SELECT name FROM up ORDER BY depth DESC",
        )?;
        let rows = q.query_map([name], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// A fleet and every fleet under it.
    pub fn fleets_under(&self, name: &str) -> Result<Vec<String>> {
        let c = self.conn.lock().unwrap();
        let mut q = c.prepare(&format!(
            "SELECT name FROM fleets WHERE id IN ({FLEET_TREE})"
        ))?;
        let rows = q.query_map([name], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Move a fleet under another, or to the top with `None`. Devices stay in
    /// it, and from then on inherit from where it now sits.
    pub fn set_fleet_parent(&self, name: &str, parent: Option<&str>) -> Result<()> {
        if let Some(p) = parent {
            anyhow::ensure!(
                !self.fleet_lineage(p)?.iter().any(|f| f == name),
                "{name:?} can't go under {p:?}: {p:?} is inside it"
            );
        }
        let c = self.conn.lock().unwrap();
        let id = fleet_id(&c, name)?;
        let parent = parent.map(|p| fleet_id(&c, p)).transpose()?;
        c.execute(
            "UPDATE fleets SET parent_id = ?2 WHERE id = ?1",
            params![id, parent],
        )?;
        Ok(())
    }

    /// Replace a device's own tags. It also has its fleets', which aren't these.
    pub fn set_device_tags(&self, id: &str, tags: &[String]) -> Result<()> {
        for t in tags {
            check_tag(t)?;
        }
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        tx.execute("DELETE FROM device_tags WHERE device_id = ?1", [id])?;
        for t in tags {
            tx.execute(
                "INSERT OR IGNORE INTO device_tags (device_id, tag) VALUES (?1, ?2)",
                params![id, t],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_fleet_tags(&self, name: &str, tags: &[String]) -> Result<()> {
        for t in tags {
            check_tag(t)?;
        }
        let mut c = self.conn.lock().unwrap();
        let id = fleet_id(&c, name)?;
        let tx = c.transaction()?;
        tx.execute("DELETE FROM fleet_tags WHERE fleet_id = ?1", [id])?;
        for t in tags {
            tx.execute(
                "INSERT OR IGNORE INTO fleet_tags (fleet_id, tag) VALUES (?1, ?2)",
                params![id, t],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Mint a single-use token for `fleet`. The caller must put the token
    /// where the device will find it and nowhere else.
    pub fn mint_token(
        &self,
        fleet: &str,
        hostname: Option<&str>,
        ttl_secs: i64,
        image_id: Option<&str>,
    ) -> Result<String> {
        let c = self.conn.lock().unwrap();
        let fleet_id = fleet_id(&c, fleet)?;
        let token = random_secret();
        c.execute(
            "INSERT INTO enrollment_tokens (token_hash, fleet_id, hostname, created_at, expires_at, image_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![hash(&token), fleet_id, hostname, now(), now() + ttl_secs, image_id],
        )?;
        Ok(token)
    }

    /// Spend an enrollment token and register the device. Returns the device,
    /// its long-lived credential, and the provisioning image the token was
    /// written into, which has now served its purpose.
    ///
    /// A token is single-use, so the same image written to two cards enrolls
    /// one device. The second is refused, rather than silently becoming the
    /// first.
    pub fn enroll(&self, e: &Enrollment) -> Result<(Device, String, Option<String>)> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let row: Option<(i64, Option<String>, i64, Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT fleet_id, hostname, expires_at, used_by, image_id FROM enrollment_tokens
                 WHERE token_hash = ?1",
                [hash(&e.token)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((fleet_id, name, expires_at, used_by, image_id)) = row else {
            bail!("unknown token")
        };
        if used_by.is_some() {
            bail!("token already used");
        }
        if expires_at < now() {
            bail!("token expired");
        }
        let id = random_secret()[..16].to_string();
        let name = name.unwrap_or_else(|| e.hostname.clone());
        let credential = random_secret();
        tx.execute(
            "INSERT INTO devices (id, name, fleet_id, credential_hash, arch, os_version,
                                  agent_version, enrolled_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                name,
                fleet_id,
                hash(&credential),
                e.arch,
                e.os_version,
                e.agent_version,
                now()
            ],
        )?;
        tx.execute(
            "UPDATE enrollment_tokens SET used_by = ?1 WHERE token_hash = ?2",
            params![id, hash(&e.token)],
        )?;
        tx.commit()?;
        drop(c);
        Ok((
            self.device(&id)?.expect("just inserted"),
            credential,
            image_id,
        ))
    }

    pub fn authenticate(&self, credential: &str) -> Result<Option<String>> {
        let c = self.conn.lock().unwrap();
        Ok(c.query_row(
            "SELECT id FROM devices WHERE credential_hash = ?1",
            [hash(credential)],
            |r| r.get(0),
        )
        .optional()?)
    }

    pub fn seen(
        &self,
        id: &str,
        os_version: Option<&str>,
        agent_version: Option<&str>,
    ) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "UPDATE devices SET last_seen = ?2,
                    os_version = COALESCE(?3, os_version),
                    agent_version = COALESCE(?4, agent_version)
             WHERE id = ?1",
            params![id, now(), os_version, agent_version],
        )?;
        Ok(())
    }

    /// Every device, or those in a fleet and the fleets under it.
    pub fn devices(&self, fleet: Option<&str>) -> Result<Vec<Device>> {
        let c = self.conn.lock().unwrap();
        let mut q = c.prepare(&format!(
            "{DEVICE_SELECT} WHERE (?1 IS NULL OR d.fleet_id IN ({FLEET_TREE})) ORDER BY f.name, d.name"
        ))?;
        let rows = q.query_map([fleet], device_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn device(&self, id: &str) -> Result<Option<Device>> {
        let c = self.conn.lock().unwrap();
        Ok(c.query_row(
            &format!("{DEVICE_SELECT} WHERE d.id = ?1"),
            [id],
            device_row,
        )
        .optional()?)
    }

    /// Find a device by id or by name. A name shared by two devices is
    /// ambiguous and refused, so a tool never acts on the wrong one.
    pub fn resolve(&self, key: &str) -> Result<Device> {
        if let Some(d) = self.device(key)? {
            return Ok(d);
        }
        let c = self.conn.lock().unwrap();
        let mut q = c.prepare(&format!("{DEVICE_SELECT} WHERE d.name = ?1"))?;
        let found: Vec<Device> = q.query_map([key], device_row)?.collect::<Result<_, _>>()?;
        match found.len() {
            1 => Ok(found.into_iter().next().unwrap()),
            0 => bail!("no device named {key:?}; `list_devices` shows them"),
            n => bail!("{n} devices are named {key:?}; use the device id"),
        }
    }

    /// Create an API token and return it. It is shown once, here, and
    /// stored only as a hash.
    pub fn create_api_token(&self, name: &str, role: Role) -> Result<String> {
        valid_name(name)?;
        let token = format!("via_{}", random_secret());
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "INSERT INTO api_tokens (name, role, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO NOTHING",
            params![name, role.as_str(), hash(&token), now()],
        )?;
        anyhow::ensure!(n == 1, "a token named {name:?} exists; revoke it first");
        Ok(token)
    }

    pub fn api_tokens(&self) -> Result<Vec<ApiToken>> {
        let c = self.conn.lock().unwrap();
        let mut q =
            c.prepare("SELECT name, role, created_at, last_used FROM api_tokens ORDER BY name")?;
        let rows = q.query_map([], |r| {
            let role: String = r.get(1)?;
            Ok(ApiToken {
                name: r.get(0)?,
                role: Role::parse(&role).unwrap_or(Role::Member),
                created_at: r.get(2)?,
                last_used: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn revoke_api_token(&self, name: &str) -> Result<()> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let n = tx.execute("DELETE FROM api_tokens WHERE name = ?1", [name])?;
        anyhow::ensure!(n == 1, "no token named {name:?}");
        tx.execute(
            "DELETE FROM grants WHERE subject = ?1",
            [format!("token:{name}")],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn grants(&self) -> Result<Vec<Grant>> {
        let c = self.conn.lock().unwrap();
        let mut q = c.prepare(
            "SELECT g.subject, f.name, g.level FROM grants g
             LEFT JOIN fleets f ON f.id = g.fleet_id
             ORDER BY g.subject, f.name IS NOT NULL, f.name",
        )?;
        let rows = q.query_map([], |r| {
            let level: i64 = r.get(2)?;
            Ok(Grant {
                subject: r.get(0)?,
                fleet: r.get(1)?,
                level: crate::access::Level::from_rank(level)
                    .unwrap_or(crate::access::Level::Observer),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Give `subject` a role on `fleet`, or on every fleet, replacing the one
    /// it had there.
    pub fn set_grant(
        &self,
        subject: &str,
        fleet: Option<&str>,
        level: crate::access::Level,
    ) -> Result<()> {
        crate::access::check_subject(subject)?;
        let c = self.conn.lock().unwrap();
        if let Some(name) = subject.strip_prefix("token:") {
            let known = c
                .prepare("SELECT 1 FROM api_tokens WHERE name = ?1")?
                .exists([name])?;
            anyhow::ensure!(known, "no token named {name:?}");
        }
        let fleet = fleet.map(|f| fleet_id(&c, f)).transpose()?;
        c.execute(
            "DELETE FROM grants WHERE subject = ?1 AND IFNULL(fleet_id, 0) = IFNULL(?2, 0)",
            params![subject, fleet],
        )?;
        c.execute(
            "INSERT INTO grants (subject, fleet_id, level, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![subject, fleet, level.rank(), now()],
        )?;
        Ok(())
    }

    pub fn delete_grant(&self, subject: &str, fleet: Option<&str>) -> Result<()> {
        let c = self.conn.lock().unwrap();
        let fleet = fleet.map(|f| fleet_id(&c, f)).transpose()?;
        let n = c.execute(
            "DELETE FROM grants WHERE subject = ?1 AND IFNULL(fleet_id, 0) = IFNULL(?2, 0)",
            params![subject, fleet],
        )?;
        anyhow::ensure!(n > 0, "{subject} has no grant there");
        Ok(())
    }

    pub fn device_types(&self) -> Result<Vec<DeviceType>> {
        let c = self.conn.lock().unwrap();
        let mut q =
            c.prepare("SELECT id, name, arch, detail FROM device_types ORDER BY arch DESC, name")?;
        let rows = q.query_map([], |r| {
            Ok(DeviceType {
                id: r.get(0)?,
                name: r.get(1)?,
                arch: r.get(2)?,
                detail: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Add a device type, or change one.
    pub fn set_device_type(&self, t: &DeviceType) -> Result<()> {
        valid_name(&t.id)?;
        anyhow::ensure!(!t.name.trim().is_empty(), "a device type needs a name");
        anyhow::ensure!(
            crate::image::ARCHES.contains(&t.arch.as_str()),
            "arch is one of {}",
            crate::image::ARCHES.join(", ")
        );
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO device_types (id, name, arch, detail) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (id) DO UPDATE SET name = ?2, arch = ?3, detail = ?4",
            params![t.id, t.name.trim(), t.arch, t.detail.trim()],
        )?;
        Ok(())
    }

    pub fn delete_device_type(&self, id: &str) -> Result<()> {
        let c = self.conn.lock().unwrap();
        let n = c.execute("DELETE FROM device_types WHERE id = ?1", [id])?;
        anyhow::ensure!(n == 1, "no device type {id:?}");
        Ok(())
    }

    /// Start a console session for someone an outside provider vouched for.
    pub fn create_session(&self, caller: &Caller, ttl_secs: i64) -> Result<String> {
        let token = format!("{SESSION_PREFIX}{}", random_secret());
        let c = self.conn.lock().unwrap();
        c.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now()])?;
        c.execute(
            "INSERT INTO sessions (token_hash, name, role, expires_at, subjects)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                hash(&token),
                caller.name,
                caller.role.as_str(),
                now() + ttl_secs,
                caller.subjects.join("\n")
            ],
        )?;
        Ok(token)
    }

    /// Who a console session belongs to, while it lasts.
    pub fn session_caller(&self, token: &str) -> Result<Option<Caller>> {
        let c = self.conn.lock().unwrap();
        let row: Option<(String, String, String)> = c
            .query_row(
                "SELECT name, role, subjects FROM sessions
                 WHERE token_hash = ?1 AND expires_at > ?2",
                params![hash(token), now()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(row.and_then(|(name, role, subjects)| {
            Some(Caller {
                name,
                role: Role::parse(&role)?,
                subjects: subjects
                    .split('\n')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect(),
            })
        }))
    }

    pub fn delete_session(&self, token: &str) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute("DELETE FROM sessions WHERE token_hash = ?1", [hash(token)])?;
        Ok(())
    }

    /// Who an API token belongs to, if anyone.
    pub fn api_caller(&self, token: &str) -> Result<Option<Caller>> {
        let c = self.conn.lock().unwrap();
        let row: Option<(String, String)> = c
            .query_row(
                "UPDATE api_tokens SET last_used = ?2 WHERE token_hash = ?1 RETURNING name, role",
                params![hash(token), now()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(name, role)| Some(Caller::token(name, Role::parse(&role)?))))
    }

    pub fn audit(&self, actor: &str, tool: &str, args: &serde_json::Value, ok: bool) {
        let c = self.conn.lock().unwrap();
        if let Err(e) = c.execute(
            "INSERT INTO audit (at, actor, tool, args, ok) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now(), actor, tool, args.to_string(), ok],
        ) {
            tracing::error!("audit write failed: {e}");
        }
    }
}

/// A row is one name at one place for one service. NULLs count as different in
/// a plain unique index, and "every service" must only exist once.
const VARIABLES_IDENTITY: &str = "CREATE UNIQUE INDEX IF NOT EXISTS variables_identity
    ON variables (scope, target, app, key, IFNULL(service, ''));";

/// One stored variable. A secret's `value` is ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    pub scope: String,
    pub target: String,
    pub app: String,
    /// One service of the app, or every service that declares the name.
    pub service: Option<String>,
    pub key: String,
    pub value: Vec<u8>,
    pub secret: bool,
    pub updated_at: i64,
    pub updated_by: String,
}

impl Db {
    pub fn set_variable(&self, v: &Variable) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO variables
                 (scope, target, app, key, value, secret, updated_at, updated_by, service)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (scope, target, app, key, IFNULL(service, '')) DO UPDATE SET
               value = ?5, secret = ?6, updated_at = ?7, updated_by = ?8",
            params![
                v.scope,
                v.target,
                v.app,
                v.key,
                v.value,
                v.secret,
                v.updated_at,
                v.updated_by,
                v.service
            ],
        )?;
        Ok(())
    }

    /// Whether anything was there to delete.
    pub fn delete_variable(
        &self,
        scope: &str,
        target: &str,
        app: &str,
        service: Option<&str>,
        key: &str,
    ) -> Result<bool> {
        let n = self.conn.lock().unwrap().execute(
            "DELETE FROM variables WHERE scope = ?1 AND target = ?2 AND app = ?3 AND key = ?4
             AND service IS ?5",
            params![scope, target, app, key, service],
        )?;
        Ok(n > 0)
    }

    pub fn variables(&self) -> Result<Vec<Variable>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT scope, target, app, key, value, secret, updated_at, updated_by, service
             FROM variables ORDER BY app, key, scope, target, service",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Variable {
                scope: r.get(0)?,
                target: r.get(1)?,
                app: r.get(2)?,
                key: r.get(3)?,
                value: r.get(4)?,
                secret: r.get(5)?,
                updated_at: r.get(6)?,
                updated_by: r.get(7)?,
                service: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The newest audit entries, newest first.
    pub fn audit_log(&self, limit: u32) -> Result<Vec<serde_json::Value>> {
        let c = self.conn.lock().unwrap();
        let mut stmt =
            c.prepare("SELECT at, actor, tool, args, ok FROM audit ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit], |r| {
            let args: String = r.get(3)?;
            Ok(serde_json::json!({
                "at": r.get::<_, i64>(0)?,
                "actor": r.get::<_, Option<String>>(1)?,
                "tool": r.get::<_, String>(2)?,
                "args": serde_json::from_str::<serde_json::Value>(&args).unwrap_or_default(),
                "ok": r.get::<_, bool>(4)?,
            }))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

const DEVICE_SELECT: &str = "
    SELECT d.id, d.name, f.name, d.arch, d.os_version, d.agent_version, d.enrolled_at, d.last_seen,
           (SELECT group_concat(tag, char(10)) FROM
              (SELECT tag FROM device_tags WHERE device_id = d.id ORDER BY tag))
    FROM devices d JOIN fleets f ON f.id = d.fleet_id";

/// A tag is `key` or `key=value`, on a fleet or a device. The key is a plain
/// name; the value can be anything on one line, like a site's name.
fn check_tag(tag: &str) -> Result<()> {
    let (key, value) = match tag.split_once('=') {
        Some((key, value)) => (key, Some(value)),
        None => (tag, None),
    };
    let key_ok = !key.is_empty()
        && key.len() <= 63
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_:./".contains(c));
    let value_ok = value.is_none_or(|v| {
        !v.is_empty() && v.len() <= 200 && v.trim() == v && !v.chars().any(char::is_control)
    });
    anyhow::ensure!(
        key_ok && value_ok,
        "{tag:?} isn't a tag: use key or key=value, where the key is 1-63 letters, digits, or - _ : . /"
    );
    Ok(())
}

fn device_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: r.get(0)?,
        name: r.get(1)?,
        fleet: r.get(2)?,
        arch: r.get(3)?,
        os_version: r.get(4)?,
        agent_version: r.get(5)?,
        enrolled_at: r.get(6)?,
        last_seen: r.get(7)?,
        tags: r
            .get::<_, Option<String>>(8)?
            .map(|t| t.split('\n').map(String::from).collect())
            .unwrap_or_default(),
    })
}

/// The ids of the fleet named by `?1` and every fleet under it.
const FLEET_TREE: &str = "WITH RECURSIVE tree(id) AS (
       SELECT id FROM fleets WHERE name = ?1
       UNION ALL SELECT f.id FROM fleets f JOIN tree ON f.parent_id = tree.id
     ) SELECT id FROM tree";

fn fleet_id(c: &Connection, name: &str) -> Result<i64> {
    c.query_row("SELECT id FROM fleets WHERE name = ?1", [name], |r| {
        r.get(0)
    })
    .optional()?
    .with_context(|| format!("no fleet named {name:?}; `list_fleets` shows them"))
}

fn valid_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    anyhow::ensure!(ok, "names are 1-63 letters, digits, '-' or '_'");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variable(service: Option<&str>, value: &str) -> Variable {
        Variable {
            scope: "fleet".into(),
            target: "lab".into(),
            app: "hello".into(),
            service: service.map(Into::into),
            key: "TOKEN".into(),
            value: value.as_bytes().to_vec(),
            secret: false,
            updated_at: 0,
            updated_by: "t".into(),
        }
    }

    #[test]
    fn a_name_has_one_value_per_service_and_one_for_all() {
        let (_d, db) = db();
        db.set_variable(&variable(None, "a")).unwrap();
        db.set_variable(&variable(None, "b")).unwrap();
        db.set_variable(&variable(Some("web"), "c")).unwrap();
        db.set_variable(&variable(Some("web"), "d")).unwrap();
        db.set_variable(&variable(Some("db"), "e")).unwrap();
        let held: Vec<(Option<String>, Vec<u8>)> = db
            .variables()
            .unwrap()
            .into_iter()
            .map(|v| (v.service, v.value))
            .collect();
        assert_eq!(
            held,
            [
                (None, b"b".to_vec()),
                (Some("db".to_string()), b"e".to_vec()),
                (Some("web".to_string()), b"d".to_vec()),
            ]
        );

        assert!(
            db.delete_variable("fleet", "lab", "hello", Some("web"), "TOKEN")
                .unwrap()
        );
        assert!(
            !db.delete_variable("fleet", "lab", "hello", Some("web"), "TOKEN")
                .unwrap(),
            "already gone"
        );
        assert_eq!(db.variables().unwrap().len(), 2, "the others stay");
        assert!(
            db.delete_variable("fleet", "lab", "hello", None, "TOKEN")
                .unwrap()
        );
        assert_eq!(db.variables().unwrap()[0].service.as_deref(), Some("db"));
    }

    #[test]
    fn a_database_from_before_services_keeps_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("via.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE variables (
                     scope TEXT NOT NULL, target TEXT NOT NULL, app TEXT NOT NULL,
                     key TEXT NOT NULL, value BLOB NOT NULL, secret INTEGER NOT NULL,
                     updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL,
                     PRIMARY KEY (scope, target, app, key)
                 );
                 INSERT INTO variables VALUES
                     ('fleet', 'lab', 'hello', 'TOKEN', x'0102', 1, 5, 'admin');",
            )
            .unwrap();
        }
        // Twice: the migration must be safe to meet again on every start.
        for _ in 0..2 {
            let db = Db::open(&path).unwrap();
            let vars = db.variables().unwrap();
            assert_eq!(vars.len(), 1);
            let v = &vars[0];
            assert_eq!(v.service, None);
            assert_eq!(v.key, "TOKEN");
            assert_eq!(v.value, vec![1, 2]);
            assert!(v.secret);
            assert_eq!((v.updated_at, v.updated_by.as_str()), (5, "admin"));
        }
        // And the old identity is gone, so a service can have its own value.
        let db = Db::open(&path).unwrap();
        db.set_variable(&variable(Some("web"), "x")).unwrap();
        assert_eq!(db.variables().unwrap().len(), 2);
    }

    fn db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("via.db")).unwrap();
        (dir, db)
    }

    fn enrollment(token: &str) -> Enrollment {
        Enrollment {
            token: token.into(),
            hostname: "viaos".into(),
            arch: Some("x86_64".into()),
            os_version: Some("1".into()),
            agent_version: None,
        }
    }

    #[test]
    fn fleets_nest_to_any_depth_and_never_in_a_loop() {
        let (_d, db) = db();
        for f in ["acme", "site", "house", "other"] {
            db.create_fleet(f).unwrap();
        }
        db.set_fleet_parent("site", Some("acme")).unwrap();
        db.set_fleet_parent("house", Some("site")).unwrap();
        assert_eq!(
            db.fleet_lineage("house").unwrap(),
            ["acme", "site", "house"]
        );
        let mut under = db.fleets_under("acme").unwrap();
        under.sort();
        assert_eq!(under, ["acme", "house", "site"]);

        assert!(db.set_fleet_parent("acme", Some("house")).is_err());
        assert!(db.set_fleet_parent("acme", Some("acme")).is_err());
        assert!(db.set_fleet_parent("house", Some("nope")).is_err());

        let token = db.mint_token("house", None, 60, None).unwrap();
        let (device, _, _) = db.enroll(&enrollment(&token)).unwrap();
        assert_eq!(db.devices(Some("acme")).unwrap()[0].id, device.id);
        assert!(db.devices(Some("other")).unwrap().is_empty());

        // Move it out, and it's no longer under its old parent.
        db.set_fleet_parent("house", None).unwrap();
        assert!(db.devices(Some("acme")).unwrap().is_empty());
        assert_eq!(db.fleet_lineage("house").unwrap(), ["house"]);
    }

    #[test]
    fn an_os_update_is_kept_until_the_next_one() {
        let (_d, db) = db();
        db.begin_os_update("d1", "2", Some("1")).unwrap();
        let mut u = db.active_os_updates().unwrap().remove(0);
        assert_eq!(
            (u.state.as_str(), u.from_version.as_deref()),
            ("started", Some("1"))
        );
        u.state = "done".into();
        u.finished_at = Some(5);
        db.save_os_update(&u).unwrap();
        assert!(db.active_os_updates().unwrap().is_empty());
        assert_eq!(db.os_updates().unwrap()[0].state, "done");
        db.begin_os_update("d1", "3", Some("2")).unwrap();
        let all = db.os_updates().unwrap();
        assert_eq!(
            (all.len(), all[0].version.as_str(), all[0].finished_at),
            (1, "3", None)
        );
    }

    #[test]
    fn only_an_empty_fleet_can_be_deleted() {
        let (_d, db) = db();
        for f in ["acme", "site"] {
            db.create_fleet(f).unwrap();
        }
        db.set_fleet_parent("site", Some("acme")).unwrap();
        db.set_fleet_tags("site", &["x".into()]).unwrap();
        assert!(
            db.delete_fleet("acme")
                .unwrap_err()
                .to_string()
                .contains("under it")
        );
        let token = db.mint_token("site", None, 60, None).unwrap();
        db.delete_fleet("site").unwrap();
        assert!(
            db.enroll(&enrollment(&token)).is_err(),
            "its images can't join"
        );
        db.delete_fleet("acme").unwrap();
        assert!(db.fleets().unwrap().is_empty());
        assert!(db.delete_fleet("acme").is_err());

        db.create_fleet("full").unwrap();
        let token = db.mint_token("full", None, 60, None).unwrap();
        db.enroll(&enrollment(&token)).unwrap();
        assert!(
            db.delete_fleet("full")
                .unwrap_err()
                .to_string()
                .contains("devices")
        );
    }

    #[test]
    fn tags_are_a_key_and_maybe_a_value() {
        for good in [
            "eu",
            "customer:acme",
            "site=Dallas North",
            "type=rock-5b",
            "a=b=c",
        ] {
            assert!(check_tag(good).is_ok(), "{good}");
        }
        for bad in ["", "=x", "has space", "k=", "k= x", "k=a\nb", "k =v"] {
            assert!(check_tag(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn fleets_carry_tags() {
        let (_d, db) = db();
        db.create_fleet("acme").unwrap();
        db.set_fleet_tags("acme", &["customer:acme".into(), "eu".into(), "eu".into()])
            .unwrap();
        let f = db.fleets().unwrap();
        assert_eq!(f[0].tags, ["customer:acme", "eu"]);
        assert_eq!(f[0].parent, None);
        db.set_fleet_tags("acme", &[]).unwrap();
        assert!(db.fleets().unwrap()[0].tags.is_empty());
        assert!(db.set_fleet_tags("acme", &["has space".into()]).is_err());
    }

    #[test]
    fn device_types_can_be_added_and_seeds_stay_removed() {
        let (d, db) = db();
        assert_eq!(db.device_types().unwrap().len(), 3);
        let t = DeviceType {
            id: "rock-5b".into(),
            name: "Rock 5B".into(),
            arch: "aarch64".into(),
            detail: String::new(),
        };
        db.set_device_type(&t).unwrap();
        assert!(db.device_types().unwrap().contains(&t));
        assert!(
            db.set_device_type(&DeviceType {
                arch: "sparc".into(),
                ..t.clone()
            })
            .is_err()
        );
        db.delete_device_type("pc").unwrap();
        drop(db);
        let db = Db::open(&d.path().join("via.db")).unwrap();
        assert!(!db.device_types().unwrap().iter().any(|t| t.id == "pc"));
    }

    #[test]
    fn a_session_ends_when_it_expires() {
        let (_d, db) = db();
        let a = Caller {
            name: "github/a".into(),
            role: Role::Member,
            subjects: vec!["github:a".into(), "github-org".into()],
        };
        let live = db.create_session(&a, 60).unwrap();
        let dead = db.create_session(&Caller::admin("github/b"), -1).unwrap();
        let back = db.session_caller(&live).unwrap().unwrap();
        assert_eq!(
            (back.name, back.role, back.subjects),
            (a.name, a.role, a.subjects)
        );
        assert!(db.session_caller(&dead).unwrap().is_none());
        // A session is not an API token, and the other way round.
        assert!(db.api_caller(&live).unwrap().is_none());
        let api = db.create_api_token("ana", Role::Admin).unwrap();
        assert!(db.session_caller(&api).unwrap().is_none());
    }

    #[test]
    fn token_enrolls_once() {
        let (_d, db) = db();
        db.create_fleet("line").unwrap();
        let token = db
            .mint_token("line", Some("line-07"), 3600, Some("img"))
            .unwrap();
        let (device, cred, image) = db.enroll(&enrollment(&token)).unwrap();
        assert_eq!(image.as_deref(), Some("img"));
        assert_eq!(device.name, "line-07");
        assert_eq!(device.fleet, "line");
        assert_eq!(db.authenticate(&cred).unwrap(), Some(device.id.clone()));
        assert!(db.enroll(&enrollment(&token)).is_err());
        assert_eq!(db.fleets().unwrap()[0].devices, 1);
    }

    #[test]
    fn expired_and_unknown_tokens_are_refused() {
        let (_d, db) = db();
        db.create_fleet("line").unwrap();
        let token = db.mint_token("line", None, -1, None).unwrap();
        assert!(db.enroll(&enrollment(&token)).is_err());
        assert!(db.enroll(&enrollment("nope")).is_err());
    }

    #[test]
    fn ambiguous_names_are_refused() {
        let (_d, db) = db();
        db.create_fleet("line").unwrap();
        for _ in 0..2 {
            let t = db.mint_token("line", Some("dup"), 60, None).unwrap();
            db.enroll(&enrollment(&t)).unwrap();
        }
        assert!(db.resolve("dup").is_err());
    }

    #[test]
    fn api_tokens_authenticate_until_revoked() {
        let (_d, db) = db();
        let token = db.create_api_token("ana", Role::Member).unwrap();
        assert!(db.create_api_token("ana", Role::Admin).is_err());
        let caller = db.api_caller(&token).unwrap().unwrap();
        assert_eq!((caller.name.as_str(), caller.role), ("ana", Role::Member));
        assert_eq!(caller.subjects, ["token:ana"]);
        assert!(db.api_tokens().unwrap()[0].last_used.is_some());
        assert!(db.api_caller("via_nope").unwrap().is_none());
        db.set_grant("token:ana", None, crate::access::Level::Observer)
            .unwrap();
        db.revoke_api_token("ana").unwrap();
        assert!(db.api_caller(&token).unwrap().is_none());
        // Its grants go with it, so a new token by that name starts with none.
        assert!(
            !db.grants()
                .unwrap()
                .iter()
                .any(|g| g.subject == "token:ana")
        );
        assert!(
            db.set_grant("token:ana", None, crate::access::Level::Observer)
                .is_err()
        );
    }

    #[test]
    fn viewers_keep_what_they_could_do() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("via.db");
        {
            // A database from before grants.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.execute_batch(
                "INSERT INTO api_tokens (name, role, token_hash, created_at)
                     VALUES ('ana', 'viewer', 'h1', 0), ('ci', 'admin', 'h2', 0);
                 INSERT INTO sessions VALUES ('s1', 'github/bob', 'viewer', 9999999999),
                                             ('s2', 'github/root', 'admin', 9999999999);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let g: Vec<_> = db
            .grants()
            .unwrap()
            .into_iter()
            .map(|g| (g.subject, g.fleet, g.level))
            .collect();
        use crate::access::Level::Observer;
        assert_eq!(
            g,
            [
                ("github-org".into(), None, Observer),
                ("token:ana".into(), None, Observer)
            ]
        );
        let roles: Vec<_> = db
            .api_tokens()
            .unwrap()
            .into_iter()
            .map(|t| t.role)
            .collect();
        assert_eq!(roles, [Role::Member, Role::Admin]);
        let c = db.conn.lock().unwrap();
        let left: Vec<String> = c
            .prepare("SELECT name FROM sessions")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(left, ["github/root"]);
        drop(c);
        // Opening again changes nothing.
        drop(db);
        assert_eq!(Db::open(&path).unwrap().grants().unwrap().len(), 2);
    }

    #[test]
    fn a_fleet_takes_its_grants_with_it() {
        let (_d, db) = db();
        db.create_fleet("line").unwrap();
        db.set_grant("github:bob", Some("line"), crate::access::Level::Developer)
            .unwrap();
        db.set_grant("github:bob", Some("line"), crate::access::Level::Operator)
            .unwrap();
        let mine = |db: &Db| {
            db.grants()
                .unwrap()
                .into_iter()
                .filter(|g| g.subject == "github:bob")
                .map(|g| g.level)
                .collect::<Vec<_>>()
        };
        assert_eq!(mine(&db), [crate::access::Level::Operator]);
        db.delete_fleet("line").unwrap();
        assert!(mine(&db).is_empty());
    }

    #[test]
    fn audit_records_the_actor() {
        let (_d, db) = db();
        db.audit("ana", "list_fleets", &serde_json::json!({}), true);
        let c = db.conn.lock().unwrap();
        let actor: String = c
            .query_row("SELECT actor FROM audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(actor, "ana");
    }
}
