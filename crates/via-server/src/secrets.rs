//! App variables on their way to devices, and secrets at rest.
//!
//! A secret is sealed with a key the database does not hold: copying the
//! database, or a backup of it, gives ciphertext. Each value is bound to the
//! row it belongs to, so ciphertext copied onto another key will not open.
//! A device gets the plaintext over its own TLS connection, because its
//! containers need it, and keeps it readable by root only.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use crate::State;
use crate::db::{Device, Variable};

const NONCE: usize = 24;

#[derive(Clone)]
pub struct Secrets {
    cipher: XChaCha20Poly1305,
}

impl Secrets {
    /// The key from `configured` (64 hex digits) or from `secret.key` in the
    /// data directory, made on first use.
    pub fn open(data_dir: &Path, configured: Option<&str>) -> Result<Self> {
        let hex_key = match configured {
            Some(k) => k.trim().to_string(),
            None => {
                let path = data_dir.join("secret.key");
                if !path.exists() {
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&path)
                        .with_context(|| format!("creating {}", path.display()))?;
                    writeln!(f, "{}", crate::db::random_secret())?;
                }
                std::fs::read_to_string(&path)?.trim().to_string()
            }
        };
        let bytes = hex::decode(&hex_key).context("the secret key is not hex")?;
        ensure!(bytes.len() == 32, "the secret key is not 32 bytes");
        Ok(Self {
            cipher: XChaCha20Poly1305::new_from_slice(&bytes)?,
        })
    }

    /// What a sealed value is tied to. A row with no service keeps the form
    /// from before services existed, so its ciphertext still opens.
    fn binding(scope: &str, target: &str, app: &str, service: Option<&str>, key: &str) -> String {
        match service {
            None => format!("{scope}\0{target}\0{app}\0{key}"),
            Some(service) => format!("{scope}\0{target}\0{app}\0{key}\0{service}"),
        }
    }

    /// Nonce followed by ciphertext.
    pub fn seal(
        &self,
        scope: &str,
        target: &str,
        app: &str,
        service: Option<&str>,
        key: &str,
        value: &str,
    ) -> Vec<u8> {
        let nonce: [u8; NONCE] = rand::random();
        let aad = Self::binding(scope, target, app, service, key);
        let sealed = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: value.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .expect("encrypting cannot fail for a value this size");
        [nonce.as_slice(), &sealed].concat()
    }

    /// A GitHub token kept so a connection can be checked again.
    pub fn seal_github(&self, token: &str) -> Vec<u8> {
        self.seal("oauth", "github", "", None, "token", token)
    }

    pub fn open_github(&self, sealed: &[u8]) -> Result<String> {
        self.open_sealed(
            sealed,
            &Self::binding("oauth", "github", "", None, "token"),
            "the GitHub token",
        )
    }

    fn open_value(&self, v: &Variable) -> Result<String> {
        let aad = Self::binding(&v.scope, &v.target, &v.app, v.service.as_deref(), &v.key);
        self.open_sealed(&v.value, &aad, &v.key)
    }

    fn open_sealed(&self, value: &[u8], aad: &str, what: &str) -> Result<String> {
        ensure!(value.len() > NONCE, "stored secret is too short");
        let (nonce, sealed) = value.split_at(NONCE);
        let plain = self
            .cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("cannot open secret {what}: wrong key or altered"))?;
        Ok(String::from_utf8(plain)?)
    }
}

/// What a device should hold. `apps` applies to every service that declares a
/// name; `services` sits on top of it for one service.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Resolved {
    pub apps: BTreeMap<String, BTreeMap<String, String>>,
    pub services: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
}

/// Work out what a device holds, weakest first: fleet, fleet for one service,
/// device, device for one service. A device's value beats a fleet's even when
/// the fleet's is aimed at one service, so it clears those as it lands. Each
/// service's value then only has to win over `apps`, however a release uses it.
///
/// A variable with no app is for every app in `apps`, and at each level
/// gives way to one set for the app itself.
pub fn resolve(
    secrets: &Secrets,
    vars: &[Variable],
    device: &Device,
    fleets: &[String],
    apps: &[String],
) -> Result<Resolved> {
    let mut out = Resolved::default();
    // Weakest first: the outermost fleet, on in to the device's own.
    let mut layers: Vec<(&str, &String, bool)> = Vec::new();
    for fleet in fleets {
        layers.push(("fleet", fleet, false));
        layers.push(("fleet", fleet, true));
    }
    layers.push(("device", &device.id, false));
    layers.push(("device", &device.id, true));
    for (scope, target, scoped) in layers {
        let mut here: Vec<&Variable> = vars
            .iter()
            .filter(|v| v.scope == scope && &v.target == target && v.service.is_some() == scoped)
            .collect();
        // Every app's values first, so the app's own land on top.
        here.sort_by_key(|v| !v.app.is_empty());
        for v in here {
            let value = if v.secret {
                secrets.open_value(v)?
            } else {
                String::from_utf8_lossy(&v.value).into_owned()
            };
            match &v.service {
                None => {
                    let every = std::slice::from_ref(&v.app);
                    for app in if v.app.is_empty() { apps } else { every } {
                        if let Some(services) = out.services.get_mut(app) {
                            for values in services.values_mut() {
                                values.remove(&v.key);
                            }
                            services.retain(|_, values| !values.is_empty());
                        }
                        out.apps
                            .entry(app.clone())
                            .or_default()
                            .insert(v.key.clone(), value.clone());
                    }
                }
                Some(service) => {
                    out.services
                        .entry(v.app.clone())
                        .or_default()
                        .entry(service.clone())
                        .or_default()
                        .insert(v.key.clone(), value);
                }
            }
        }
    }
    out.services.retain(|_, services| !services.is_empty());
    Ok(out)
}

/// Send a device everything it should hold.
pub async fn push(state: &State, device: &Device) -> Result<Value> {
    let fleets = state.db.fleet_lineage(&device.fleet)?;
    let root = state.releases_dir();
    let mut apps: Vec<String> =
        tokio::task::spawn_blocking(move || crate::releases::list(&root, None))
            .await?
            .into_iter()
            .map(|r| r.app)
            .collect();
    apps.sort();
    apps.dedup();
    let resolved = resolve(
        &state.secrets,
        &state.db.variables()?,
        device,
        &fleets,
        &apps,
    )?;
    let mut args = JsonObject::new();
    args.insert("apps".into(), json!(resolved.apps));
    args.insert("services".into(), json!(resolved.services));
    let res = state.hub.call(&device.id, "sync_env", args).await?;
    ensure!(
        res.is_error != Some(true),
        "{}",
        res.content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect::<Vec<_>>()
            .join(" ")
    );
    Ok(res.structured_content.unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(key: &str, value: Vec<u8>, secret: bool) -> Variable {
        Variable {
            scope: "fleet".into(),
            target: "lab".into(),
            app: "hello".into(),
            service: None,
            key: key.into(),
            value,
            secret,
            updated_at: 0,
            updated_by: "t".into(),
        }
    }

    fn device() -> Device {
        Device {
            id: "d1".into(),
            name: "line-07".into(),
            title: String::new(),
            fleet: "lab".into(),
            arch: None,
            os_version: None,
            variant: String::new(),
            agent_version: None,
            enrolled_at: 0,
            last_seen: None,
            tags: Vec::new(),
            note: String::new(),
        }
    }

    #[test]
    fn a_secret_opens_only_where_it_was_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let s = Secrets::open(dir.path(), None).unwrap();
        let sealed = s.seal("fleet", "lab", "hello", None, "TOKEN", "s3cret");
        assert!(!sealed.windows(6).any(|w| w == b"s3cret"));
        assert_eq!(
            s.open_value(&var("TOKEN", sealed.clone(), true)).unwrap(),
            "s3cret"
        );
        assert!(s.open_value(&var("OTHER", sealed.clone(), true)).is_err());

        // The key is kept, so a restart opens what was sealed before it.
        let again = Secrets::open(dir.path(), None).unwrap();
        assert_eq!(
            again.open_value(&var("TOKEN", sealed, true)).unwrap(),
            "s3cret"
        );
    }

    #[test]
    fn a_value_for_every_app_gives_way_to_the_apps_own() {
        let dir = tempfile::tempdir().unwrap();
        let s = Secrets::open(dir.path(), None).unwrap();
        let every = |key: &str, value: &str| {
            let mut v = var(key, value.as_bytes().to_vec(), false);
            v.app = String::new();
            v
        };
        let mut device_wide = every("SITE", "dallas-line-3");
        device_wide.scope = "device".into();
        device_wide.target = "d1".into();
        let vars = vec![
            every("SITE", "dallas"),
            every("MODE", "every"),
            var("MODE", b"hello's own".to_vec(), false),
            device_wide,
        ];
        let apps = ["hello".to_string(), "other".to_string()];
        let env = resolve(&s, &vars, &device(), &["lab".to_string()], &apps).unwrap();
        // The fleet's value for one app beats the fleet's for every app,
        assert_eq!(env.apps["hello"]["MODE"], "hello's own");
        assert_eq!(env.apps["other"]["MODE"], "every");
        // and the device's for every app beats the fleet's.
        assert_eq!(env.apps["hello"]["SITE"], "dallas-line-3");
        assert_eq!(env.apps["other"]["SITE"], "dallas-line-3");
    }

    #[test]
    fn a_devices_value_beats_its_fleets() {
        let dir = tempfile::tempdir().unwrap();
        let s = Secrets::open(dir.path(), None).unwrap();
        let mut own = var("MODE", b"device".to_vec(), false);
        own.scope = "device".into();
        own.target = "d1".into();
        let mut other = var("MODE", b"other".to_vec(), false);
        other.target = "elsewhere".into();
        let vars = vec![
            own,
            var("MODE", b"fleet".to_vec(), false),
            other,
            var("REGION", b"us".to_vec(), false),
        ];
        let env = resolve(&s, &vars, &device(), &["lab".to_string()], &[]).unwrap();
        assert_eq!(env.apps["hello"]["MODE"], "device");
        assert_eq!(env.apps["hello"]["REGION"], "us");
    }

    #[test]
    fn a_nearer_fleet_beats_one_further_out_and_a_device_beats_them_all() {
        let dir = tempfile::tempdir().unwrap();
        let s = Secrets::open(dir.path(), None).unwrap();
        let at = |target: &str, value: &str| {
            let mut v = var("MODE", value.as_bytes().to_vec(), false);
            v.target = target.into();
            v
        };
        let lineage = ["acme".to_string(), "lab".to_string()];
        let mode = |vars: &[Variable]| {
            resolve(&s, vars, &device(), &lineage, &[]).unwrap().apps["hello"]["MODE"].clone()
        };
        assert_eq!(mode(&[at("acme", "outer")]), "outer");
        assert_eq!(mode(&[at("lab", "inner"), at("acme", "outer")]), "inner");
        // A service-scoped value further out doesn't outrank a nearer fleet's.
        let mut scoped = at("acme", "outer-web");
        scoped.service = Some("web".into());
        let r = resolve(&s, &[scoped, at("lab", "inner")], &device(), &lineage, &[]).unwrap();
        assert_eq!(r.apps["hello"]["MODE"], "inner");
        assert!(
            r.services
                .get("hello")
                .is_none_or(|m| !m.contains_key("web"))
        );
        // A fleet elsewhere in the tree doesn't reach it.
        assert!(
            resolve(&s, &[at("sibling", "no")], &device(), &lineage, &[])
                .unwrap()
                .apps
                .is_empty()
        );
    }

    /// A plain value at one layer.
    fn layer(scope: &str, service: Option<&str>, value: &str) -> Variable {
        let mut v = var("MODE", value.as_bytes().to_vec(), false);
        v.scope = scope.into();
        v.target = if scope == "fleet" { "lab" } else { "d1" }.into();
        v.service = service.map(Into::into);
        v
    }

    /// What `web` and `db` end up with, given the layers.
    fn seen(vars: &[Variable]) -> (Option<String>, Option<String>) {
        let dir = tempfile::tempdir().unwrap();
        let s = Secrets::open(dir.path(), None).unwrap();
        let r = resolve(&s, vars, &device(), &["lab".to_string()], &[]).unwrap();
        let get = |service: &str| {
            r.services
                .get("hello")
                .and_then(|m| m.get(service))
                .and_then(|m| m.get("MODE"))
                .or_else(|| r.apps.get("hello").and_then(|m| m.get("MODE")))
                .cloned()
        };
        (get("web"), get("db"))
    }

    #[test]
    fn layers_win_in_the_documented_order() {
        let fleet = layer("fleet", None, "fleet");
        let fleet_web = layer("fleet", Some("web"), "fleet-web");
        let device_all = layer("device", None, "device");
        let device_web = layer("device", Some("web"), "device-web");
        let some = |s: &str| Some(s.to_string());

        assert_eq!(
            seen(std::slice::from_ref(&fleet)),
            (some("fleet"), some("fleet"))
        );
        assert_eq!(
            seen(&[fleet_web.clone(), fleet.clone()]),
            (some("fleet-web"), some("fleet")),
            "a value for one service leaves the others on the fleet's"
        );
        assert_eq!(
            seen(&[fleet_web.clone(), device_all.clone(), fleet.clone()]),
            (some("device"), some("device")),
            "a device's value beats a fleet's, even one aimed at a service"
        );
        assert_eq!(
            seen(&[device_web.clone(), device_all, fleet_web, fleet]),
            (some("device-web"), some("device")),
        );
        assert_eq!(seen(&[device_web]), (some("device-web"), None));
    }

    #[test]
    fn a_service_value_is_sealed_to_that_service() {
        let dir = tempfile::tempdir().unwrap();
        let s = Secrets::open(dir.path(), None).unwrap();
        let sealed = s.seal("fleet", "lab", "hello", Some("web"), "TOKEN", "s3cret");
        let mut v = var("TOKEN", sealed, true);
        assert!(s.open_value(&v).is_err(), "not valid for every service");
        v.service = Some("db".into());
        assert!(s.open_value(&v).is_err(), "not valid for another service");
        v.service = Some("web".into());
        assert_eq!(s.open_value(&v).unwrap(), "s3cret");
    }

    #[test]
    fn a_secret_sealed_before_services_existed_still_opens() {
        // The binding from the first release of this table, spelled out: if
        // this changes, every secret on every server stops opening.
        let dir = tempfile::tempdir().unwrap();
        let s = Secrets::open(dir.path(), None).unwrap();
        let nonce = [7u8; NONCE];
        let sealed = s
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: b"s3cret",
                    aad: b"fleet\0lab\0hello\0TOKEN",
                },
            )
            .unwrap();
        let v = var("TOKEN", [nonce.as_slice(), &sealed].concat(), true);
        assert_eq!(s.open_value(&v).unwrap(), "s3cret");
    }
}
