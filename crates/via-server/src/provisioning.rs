//! Network and system settings for new images: what a fleet keeps, what an
//! image inherits, and the viaos.toml sections they become.
//!
//! Each section (Wi-Fi, network, time, proxy) comes from the nearest fleet
//! up the tree that sets it, so a customer can set the proxy once and each
//! site its own Wi-Fi. Passphrases are sealed at rest and never leave in a
//! tool's output: they go into images and nowhere else.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use via_core::settings::{Settings, Wifi};

use crate::State;

pub const SECTIONS: &[&str] = &["wifi", "network", "time", "proxy"];

/// A fleet's row: its settings with passphrases taken out, and those
/// passphrases sealed, by SSID.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    settings: Settings,
    #[serde(default)]
    sealed: BTreeMap<String, String>,
}

/// A fleet's own settings, passphrases opened.
fn own(state: &State, fleet: &str) -> Result<Settings> {
    let Some(json) = state.db.fleet_settings(fleet)? else {
        return Ok(Settings::default());
    };
    let stored: Stored = serde_json::from_str(&json).context("reading a fleet's settings")?;
    let mut s = stored.settings;
    for w in s.wifi.iter_mut().flatten() {
        if let Some(hex) = stored.sealed.get(&w.ssid) {
            let sealed = hex::decode(hex)?;
            w.passphrase = Some(state.secrets.open_wifi(fleet, &w.ssid, &sealed)?);
        }
    }
    Ok(s)
}

/// What a new image in a fleet starts from, and which fleet each section
/// came from.
#[derive(Debug, Default)]
pub struct Inherited {
    pub settings: Settings,
    pub from: BTreeMap<&'static str, String>,
}

pub fn inherited(state: &State, fleet: &str) -> Result<Inherited> {
    let mut out = Inherited::default();
    let lineage = state.db.fleet_lineage(fleet)?;
    for f in lineage.iter().rev() {
        let s = own(state, f)?;
        let (to, from) = (&mut out.settings, &mut out.from);
        pick(&mut to.wifi, s.wifi, "wifi", f, from);
        pick(&mut to.network, s.network, "network", f, from);
        pick(&mut to.time, s.time, "time", f, from);
        pick(&mut to.proxy, s.proxy, "proxy", f, from);
    }
    Ok(out)
}

/// Take a fleet's section unless a nearer fleet already gave one.
fn pick<T>(
    slot: &mut Option<T>,
    here: Option<T>,
    name: &'static str,
    fleet: &str,
    from: &mut BTreeMap<&'static str, String>,
) {
    if slot.is_none() && here.is_some() {
        *slot = here;
        from.insert(name, fleet.to_string());
    }
}

/// A network listed without a passphrase keeps the one already known for
/// its SSID, so a form can show `has_passphrase` and send nothing back.
fn keep_passphrases(wifi: &mut [Wifi], known: Option<&Vec<Wifi>>) {
    for w in wifi.iter_mut().filter(|w| w.passphrase.is_none()) {
        w.passphrase = known
            .and_then(|k| k.iter().find(|k| k.ssid == w.ssid))
            .and_then(|k| k.passphrase.clone());
    }
}

/// The settings an image for `fleet` gets: the sections given, over the
/// ones it inherits.
pub fn for_image(state: &State, fleet: &str, given: &Settings) -> Result<Settings> {
    let inherited = inherited(state, fleet)?.settings;
    let mut s = Settings {
        wifi: given.wifi.clone(),
        network: given.network.clone().or(inherited.network),
        time: given.time.clone().or(inherited.time),
        proxy: given.proxy.clone().or(inherited.proxy),
    };
    match &mut s.wifi {
        Some(w) => keep_passphrases(w, inherited.wifi.as_ref()),
        None => s.wifi = inherited.wifi,
    }
    s.check()?;
    Ok(s)
}

/// Set the sections given as `fleet`'s own, and drop those named in
/// `inherit` so they come from above again.
pub fn set(
    state: &State,
    fleet: &str,
    given: &Settings,
    inherit: &[String],
    by: &str,
) -> Result<()> {
    for name in inherit {
        anyhow::ensure!(
            SECTIONS.contains(&name.as_str()),
            "no section {name:?} to inherit; there are {}",
            SECTIONS.join(", ")
        );
    }
    let mut s = own(state, fleet)?;
    if let Some(wifi) = &given.wifi {
        let mut wifi = wifi.clone();
        keep_passphrases(&mut wifi, inherited(state, fleet)?.settings.wifi.as_ref());
        s.wifi = Some(wifi);
    }
    if given.network.is_some() {
        s.network = given.network.clone();
    }
    if given.time.is_some() {
        s.time = given.time.clone();
    }
    if given.proxy.is_some() {
        s.proxy = given.proxy.clone();
    }
    for name in inherit {
        match name.as_str() {
            "wifi" => s.wifi = None,
            "network" => s.network = None,
            "time" => s.time = None,
            _ => s.proxy = None,
        }
    }
    s.check()?;
    if s.is_empty() {
        return state.db.set_fleet_settings(fleet, None, by);
    }
    let mut stored = Stored::default();
    for w in s.wifi.iter_mut().flatten() {
        if let Some(p) = w.passphrase.take().filter(|p| !p.is_empty()) {
            let sealed = state.secrets.seal_wifi(fleet, &w.ssid, &p);
            stored.sealed.insert(w.ssid.clone(), hex::encode(sealed));
        }
    }
    stored.settings = s;
    state
        .db
        .set_fleet_settings(fleet, Some(&serde_json::to_string(&stored)?), by)
}

/// What a fleet's new images get, for people and Claude: passphrases are
/// `has_passphrase`, never the value.
pub fn view(fleet: &str, inherited: &Inherited) -> Value {
    let mut v = serde_json::to_value(&inherited.settings).unwrap_or_else(|_| json!({}));
    if let Some(wifi) = &inherited.settings.wifi {
        v["wifi"] = wifi
            .iter()
            .map(|w| {
                json!({
                    "ssid": w.ssid,
                    "hidden": w.hidden,
                    "priority": w.priority,
                    "has_passphrase": !w.is_open(),
                })
            })
            .collect();
    }
    json!({ "fleet": fleet, "settings": v, "from": inherited.from })
}

/// The viaos.toml sections for `s`. Every one is a table, so they can
/// follow the rest of the file.
pub fn toml(s: &Settings) -> Result<String> {
    let mut s = s.clone();
    if s.wifi.as_ref().is_some_and(Vec::is_empty) {
        s.wifi = None;
    }
    Ok(::toml::to_string(&s)?)
}

#[cfg(test)]
mod tests {
    use via_core::settings::{Addressing, Network, Proxy, Time};

    use super::*;

    fn wifi(ssid: &str, pass: Option<&str>) -> Wifi {
        Wifi {
            ssid: ssid.into(),
            passphrase: pass.map(Into::into),
            ..Default::default()
        }
    }

    fn state(dir: &std::path::Path) -> std::sync::Arc<State> {
        let s = crate::test_state(dir, "http://x", None);
        for f in ["acme", "east", "line"] {
            s.db.create_fleet(f).unwrap();
        }
        s.db.set_fleet_parent("east", Some("acme")).unwrap();
        s.db.set_fleet_parent("line", Some("east")).unwrap();
        s
    }

    #[test]
    fn each_section_comes_from_the_nearest_fleet() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let proxy = Proxy {
            https: Some("http://proxy:3128".into()),
            ..Default::default()
        };
        let top = Settings {
            wifi: Some(vec![wifi("corp", Some("corp-pass-1"))]),
            proxy: Some(proxy.clone()),
            ..Default::default()
        };
        set(&s, "acme", &top, &[], "t").unwrap();
        let mid = Settings {
            wifi: Some(vec![wifi("east-floor", Some("east-pass-1"))]),
            time: Some(Time {
                timezone: Some("America/New_York".into()),
                ntp: vec![],
            }),
            ..Default::default()
        };
        set(&s, "east", &mid, &[], "t").unwrap();

        let got = inherited(&s, "line").unwrap();
        assert_eq!(got.from["wifi"], "east");
        assert_eq!(got.from["proxy"], "acme");
        assert_eq!(got.from["time"], "east");
        assert!(!got.from.contains_key("network"));
        let w = got.settings.wifi.as_ref().unwrap();
        assert_eq!(w[0].passphrase.as_deref(), Some("east-pass-1"));
        assert_eq!(got.settings.proxy, Some(proxy));

        // An image overrides one section and keeps the rest.
        let image = for_image(
            &s,
            "line",
            &Settings {
                network: Some(Network {
                    mode: Addressing::Static,
                    address: Some("10.0.0.9/24".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(image.network.is_some() && image.time.is_some() && image.proxy.is_some());
        let text = toml(&image).unwrap();
        assert!(
            text.contains("[[wifi]]\nssid = \"east-floor\"\npassphrase = \"east-pass-1\"\n"),
            "{text}"
        );
        assert!(
            text.contains("[network]\nmode = \"static\"\naddress = \"10.0.0.9/24\"\n"),
            "{text}"
        );
        let back: Settings = ::toml::from_str(&text).unwrap();
        assert_eq!(back, image);

        // Going back to inheriting.
        set(&s, "east", &Settings::default(), &["wifi".into()], "t").unwrap();
        let got = inherited(&s, "line").unwrap();
        assert_eq!(got.from["wifi"], "acme");
        assert!(set(&s, "east", &Settings::default(), &["dns".into()], "t").is_err());
    }

    #[test]
    fn passphrases_are_kept_sealed_and_not_shown() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let given = Settings {
            wifi: Some(vec![
                wifi("floor", Some("hunter2-but-longer")),
                wifi("guest", None),
            ]),
            ..Default::default()
        };
        set(&s, "acme", &given, &[], "t").unwrap();
        let raw = s.db.fleet_settings("acme").unwrap().unwrap();
        assert!(!raw.contains("hunter2"), "{raw}");

        let shown = view("acme", &inherited(&s, "acme").unwrap()).to_string();
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains(r#""has_passphrase":true"#), "{shown}");

        // Listing the network again without its passphrase keeps it, at the
        // fleet and in an image; an empty one makes it open.
        let again = Settings {
            wifi: Some(vec![wifi("floor", None)]),
            ..Default::default()
        };
        set(&s, "acme", &again, &[], "t").unwrap();
        let image = for_image(&s, "line", &again).unwrap();
        assert_eq!(
            image.wifi.unwrap()[0].passphrase.as_deref(),
            Some("hunter2-but-longer")
        );
        let open = for_image(
            &s,
            "line",
            &Settings {
                wifi: Some(vec![wifi("floor", Some(""))]),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(open.wifi.unwrap()[0].is_open());

        // A sealed passphrase does not open as another fleet's.
        let stored: Stored = serde_json::from_str(&raw).unwrap();
        let sealed = hex::decode(&stored.sealed["floor"]).unwrap();
        assert!(s.secrets.open_wifi("other", "floor", &sealed).is_err());

        // Clearing every section removes the row.
        set(&s, "acme", &Settings::default(), &["wifi".into()], "t").unwrap();
        assert!(s.db.fleet_settings("acme").unwrap().is_none());
    }

    #[test]
    fn bad_settings_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let bad = Settings {
            wifi: Some(vec![wifi("floor", Some("short"))]),
            ..Default::default()
        };
        assert!(set(&s, "acme", &bad, &[], "t").is_err());
        assert!(for_image(&s, "acme", &bad).is_err());
        assert_eq!(toml(&Settings::default()).unwrap(), "");
        let none = Settings {
            wifi: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(toml(&none).unwrap(), "");
    }
}
