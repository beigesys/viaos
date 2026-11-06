//! Who may do what, fleet by fleet.
//!
//! An admin may do everything. Anyone else may do only what grants give
//! them: a role on a fleet, which covers every fleet under it, or on every
//! fleet at once. A grant names a subject: an API token, a GitHub user, a
//! GitHub team, or every member of the GitHub organisation. A caller is all
//! the subjects it answers to, and gets the strongest role any of them has.

use std::collections::HashMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::db::{Caller, Db, Role};

/// What a grant lets someone do on a fleet. Each includes the ones before it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Look: devices, health, logs, releases, variables. Change nothing.
    Observer,
    /// Look after devices: their tags and their own variables.
    Operator,
    /// Run the fleet: deploy, update the OS, set the fleet's variables, run
    /// commands and terminals on its devices, enroll devices, add fleets
    /// under it.
    Developer,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Observer => "observer",
            Level::Operator => "operator",
            Level::Developer => "developer",
        }
    }

    pub fn rank(self) -> i64 {
        match self {
            Level::Observer => 1,
            Level::Operator => 2,
            Level::Developer => 3,
        }
    }

    pub fn from_rank(n: i64) -> Option<Self> {
        match n {
            1 => Some(Level::Observer),
            2 => Some(Level::Operator),
            3 => Some(Level::Developer),
            _ => None,
        }
    }
}

/// What a subject is. `token:<name>`, `github:<login>`, `github-team:<slug>`,
/// or `github-org`.
pub fn check_subject(subject: &str) -> Result<()> {
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    match subject.split_once(':') {
        Some(("token" | "github" | "github-team", rest)) if ok(rest) => Ok(()),
        None if subject == "github-org" => Ok(()),
        _ => bail!(
            "{subject:?} is not a subject: use token:<name>, github:<login>, \
             github-team:<slug> or github-org"
        ),
    }
}

/// Make an API token: an admin's with no `level`, otherwise one holding that
/// role on `fleet`, or on every fleet.
pub fn create_token(
    db: &Db,
    name: &str,
    level: Option<Level>,
    fleet: Option<&str>,
) -> Result<String> {
    let Some(level) = level else {
        anyhow::ensure!(fleet.is_none(), "an admin token is for every fleet");
        return db.create_api_token(name, Role::Admin);
    };
    if let Some(f) = fleet {
        anyhow::ensure!(
            db.fleets()?.iter().any(|x| x.name == f),
            "no fleet named {f:?}"
        );
    }
    let token = db.create_api_token(name, Role::Member)?;
    if let Err(e) = db.set_grant(&format!("token:{name}"), fleet, level) {
        let _ = db.revoke_api_token(name);
        return Err(e);
    }
    Ok(token)
}

/// One caller's rights, worked out once per request.
pub struct Access {
    admin: bool,
    everywhere: Option<Level>,
    at: HashMap<String, Level>,
    parents: HashMap<String, Option<String>>,
    name: String,
}

impl Access {
    pub fn load(db: &Db, caller: &Caller) -> Result<Self> {
        let mut everywhere = None;
        let mut at: HashMap<String, Level> = HashMap::new();
        if caller.role != Role::Admin {
            for g in db.grants()? {
                if !caller.subjects.contains(&g.subject) {
                    continue;
                }
                match g.fleet {
                    None => everywhere = everywhere.max(Some(g.level)),
                    Some(f) => {
                        let l = at.entry(f).or_insert(g.level);
                        *l = (*l).max(g.level);
                    }
                }
            }
        }
        let parents = db
            .fleets()?
            .into_iter()
            .map(|f| (f.name, f.parent))
            .collect();
        Ok(Self {
            admin: caller.role == Role::Admin,
            everywhere,
            at,
            parents,
            name: caller.name.clone(),
        })
    }

    /// The strongest role on `fleet`, from a grant on it, on a fleet above
    /// it, or on every fleet.
    pub fn level(&self, fleet: &str) -> Option<Level> {
        if self.admin {
            return Some(Level::Developer);
        }
        let mut best = self.everywhere;
        let mut here = Some(fleet.to_string());
        // A cycle can't be stored, but a bound costs nothing.
        for _ in 0..64 {
            let Some(f) = here else { break };
            best = best.max(self.at.get(&f).copied());
            here = self.parents.get(&f).cloned().flatten();
        }
        best
    }

    pub fn can(&self, fleet: &str, need: Level) -> bool {
        self.level(fleet).is_some_and(|l| l >= need)
    }

    pub fn sees(&self, fleet: &str) -> bool {
        self.level(fleet).is_some()
    }

    /// Has `need` on at least one fleet.
    pub fn anywhere(&self, need: Level) -> bool {
        self.admin
            || self.everywhere.is_some_and(|l| l >= need)
            || self.at.values().any(|l| *l >= need)
    }

    /// Whether this caller has any access at all.
    pub fn any(&self) -> bool {
        self.admin || self.everywhere.is_some() || !self.at.is_empty()
    }

    pub fn require(&self, fleet: &str, need: Level, what: &str) -> Result<()> {
        if self.can(fleet, need) {
            return Ok(());
        }
        match self.level(fleet) {
            // Someone who can't see a fleet learns nothing about it.
            None => bail!("no fleet named {fleet:?}"),
            Some(has) => bail!(
                "{} is {} {} on {fleet:?}; {what} needs {}",
                self.name,
                article(has),
                has.as_str(),
                need.as_str()
            ),
        }
    }

    pub fn require_admin(&self, what: &str) -> Result<()> {
        if self.admin {
            Ok(())
        } else {
            bail!("{what} needs an admin")
        }
    }
}

fn article(l: Level) -> &'static str {
    match l {
        Level::Observer | Level::Operator => "an",
        Level::Developer => "a",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(subjects: &[&str]) -> Caller {
        Caller {
            name: "bob".into(),
            role: Role::Member,
            subjects: subjects.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("via.db")).unwrap();
        for f in ["acme", "acme-east", "line-07", "other"] {
            db.create_fleet(f).unwrap();
        }
        db.set_fleet_parent("acme-east", Some("acme")).unwrap();
        db.set_fleet_parent("line-07", Some("acme-east")).unwrap();
        (dir, db)
    }

    #[test]
    fn a_grant_covers_the_fleets_under_it() {
        let (_d, db) = db();
        db.set_grant("github:bob", Some("acme-east"), Level::Operator)
            .unwrap();
        let a = Access::load(&db, &caller(&["github:bob"])).unwrap();
        assert_eq!(a.level("line-07"), Some(Level::Operator));
        assert_eq!(a.level("acme-east"), Some(Level::Operator));
        assert_eq!(a.level("acme"), None);
        assert_eq!(a.level("other"), None);
        assert!(a.require("line-07", Level::Developer, "deploy").is_err());
        let hidden = a.require("other", Level::Observer, "logs").unwrap_err();
        assert_eq!(hidden.to_string(), "no fleet named \"other\"");
    }

    #[test]
    fn the_strongest_grant_wins() {
        let (_d, db) = db();
        db.set_grant("github-org", None, Level::Observer).unwrap();
        db.set_grant("github-team:line", Some("line-07"), Level::Developer)
            .unwrap();
        let a = Access::load(
            &db,
            &caller(&["github:bob", "github-org", "github-team:line"]),
        )
        .unwrap();
        assert_eq!(a.level("line-07"), Some(Level::Developer));
        assert_eq!(a.level("other"), Some(Level::Observer));
        // Someone else's grants aren't this caller's.
        let b = Access::load(&db, &caller(&["github:eve"])).unwrap();
        assert!(!b.any());
    }

    #[test]
    fn subjects_are_checked() {
        for ok in ["token:ci", "github:bob-1", "github-team:line", "github-org"] {
            check_subject(ok).unwrap();
        }
        for bad in ["bob", "github:", "github:a b", "team:x", "github-org:x"] {
            assert!(check_subject(bad).is_err(), "{bad}");
        }
    }
}
