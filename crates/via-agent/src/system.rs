//! Network and system settings from `viaos.toml`: Wi-Fi, addressing, time
//! and proxy.
//!
//! `via-agent system` applies them early in every boot, before networkd,
//! iwd, timesyncd and Docker start (see nix/network.nix), so the first
//! boot comes up on the network it was given. `/` is tmpfs, so files under
//! `/etc` and `/run` are written fresh each boot from viaos.toml, which
//! lives on the boot partition and survives reboots and OS updates alike.
//! Only Wi-Fi goes to `/var`: iwd keeps what it learns about a network
//! next to its passphrase, so those files are kept and rewritten only when
//! the settings change.
//!
//! Everything here takes its paths from [`Paths`] and can run again on a
//! live system, which is how settings changed after enrollment will land.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use via_core::settings::{self, Addressing, Interface, Network, Proxy, Settings, Time, Wifi};

/// Where each setting is written.
#[derive(Debug, Clone)]
pub struct Paths {
    /// networkd's runtime directory: its files outrank the OS's own in
    /// /etc/systemd/network by name, and vanish with the boot.
    pub network: PathBuf,
    /// iwd's state directory.
    pub iwd: PathBuf,
    /// The iwd files written from viaos.toml, so ones dropped from it go.
    pub wifi_written: PathBuf,
    pub timesyncd: PathBuf,
    pub localtime: PathBuf,
    pub zoneinfo: PathBuf,
    /// Read by docker.service and via-agent.service as an EnvironmentFile.
    pub proxy_env: PathBuf,
    /// The Docker CLI's config, which Compose reads: its `proxies` reach
    /// the containers apps run.
    pub docker_config: PathBuf,
}

impl Paths {
    pub fn system(data_dir: &Path) -> Self {
        Self {
            network: "/run/systemd/network".into(),
            iwd: "/var/lib/iwd".into(),
            wifi_written: data_dir.join("wifi-written"),
            timesyncd: "/run/systemd/timesyncd.conf.d".into(),
            localtime: "/etc/localtime".into(),
            zoneinfo: "/etc/zoneinfo".into(),
            proxy_env: "/run/via/proxy.env".into(),
            docker_config: "/root/.docker/config.json".into(),
        }
    }
}

/// Make the system match `s`. Each section is checked and applied on its
/// own, so one bad value does not cost the rest; a missing section undoes
/// what an earlier one set.
pub fn apply(s: &Settings, p: &Paths) {
    let wifi = s.wifi.as_deref().unwrap_or_default();
    let steps: [(&str, Result<()>); 4] = [
        (
            "wifi",
            settings::check_wifi(wifi)
                .map_err(Into::into)
                .and_then(|()| apply_wifi(wifi, p)),
        ),
        ("network", apply_network(s.network.as_ref(), p)),
        ("time", apply_time(s.time.as_ref(), p)),
        ("proxy", apply_proxy(s.proxy.as_ref(), p)),
    ];
    for (what, result) in steps {
        if let Err(e) = result {
            tracing::warn!("[{what}] not applied: {e:#}");
        }
    }
}

// ---- Wi-Fi ----

/// iwd's name for a network's file: the SSID itself when it is only
/// letters, digits, space, `-` and `_`, otherwise `=` and its hex.
pub fn iwd_file_name(w: &Wifi) -> String {
    let kind = if w.is_open() { "open" } else { "psk" };
    let plain = w
        .ssid
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" -_".contains(&b));
    if plain {
        format!("{}.{kind}", w.ssid)
    } else {
        format!("={}.{kind}", hex::encode(w.ssid.as_bytes()))
    }
}

/// The file iwd reads for a network.
pub fn iwd_file(w: &Wifi) -> String {
    let mut out = String::new();
    match w.passphrase.as_deref().filter(|p| !p.is_empty()) {
        Some(key) if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) => {
            out += &format!("[Security]\nPreSharedKey={}\n", key.to_ascii_lowercase());
        }
        Some(phrase) => out += &format!("[Security]\nPassphrase={}\n", ell_escape(phrase)),
        None => {}
    }
    if w.hidden {
        if !out.is_empty() {
            out.push('\n');
        }
        out += "[Settings]\nHidden=true\n";
    }
    out
}

/// A value as iwd's settings parser reads it back: backslashes escaped,
/// and spaces at either end kept by writing them as `\s`.
fn ell_escape(v: &str) -> String {
    let lead = v.len() - v.trim_start_matches(' ').len();
    let rest = &v[lead..];
    let body = rest.trim_end_matches(' ');
    let trail = rest.len() - body.len();
    format!(
        "{}{}{}",
        "\\s".repeat(lead),
        body.replace('\\', "\\\\"),
        "\\s".repeat(trail)
    )
}

/// Write each network's file, unless the same settings were written
/// before: iwd adds what it learns to the file, and rewriting it would lose
/// that. iwd prefers the network it joined most recently and dates that by
/// the file's mtime, so new files are dated in priority order and the first
/// boot tries the highest first.
fn apply_wifi(wifi: &[Wifi], p: &Paths) -> Result<()> {
    let before = read_written(&p.wifi_written);
    if wifi.is_empty() && before.is_empty() {
        return Ok(());
    }
    mkdir_private(&p.iwd)?;
    let now = std::time::SystemTime::now();
    let mut written = BTreeMap::new();
    for (i, w) in settings::by_priority(wifi).into_iter().enumerate() {
        let name = iwd_file_name(w);
        let body = iwd_file(w);
        let hash = hex::encode(Sha256::digest(body.as_bytes()));
        let path = p.iwd.join(&name);
        if before.get(&name) != Some(&hash) || !path.exists() {
            write_private(&path, body.as_bytes())?;
            let when = now - std::time::Duration::from_secs(i as u64);
            std::fs::File::options()
                .write(true)
                .open(&path)?
                .set_modified(when)?;
        }
        written.insert(name, hash);
    }
    for name in before.keys().filter(|n| !written.contains_key(*n)) {
        let _ = std::fs::remove_file(p.iwd.join(name));
    }
    let list: String = written.iter().map(|(n, h)| format!("{h} {n}\n")).collect();
    // On a first boot this runs before via-agent.service makes its directory.
    if let Some(dir) = p.wifi_written.parent() {
        mkdir_private(dir)?;
    }
    write_private(&p.wifi_written, list.as_bytes())
}

fn read_written(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once(' '))
        // A name is only ever one file in iwd's directory.
        .filter(|(_, n)| !n.contains('/') && !n.starts_with('.'))
        .map(|(h, n)| (n.to_string(), h.to_string()))
        .collect()
}

// ---- addressing ----

const NETWORK_PREFIX: &str = "05-via-";

/// networkd files for `n`, by file name. DHCP with no DNS of its own needs
/// none: the OS's defaults already do that.
pub fn network_files(n: &Network) -> Vec<(String, String)> {
    if n.mode == Addressing::Dhcp && n.dns.is_empty() {
        return Vec::new();
    }
    n.links()
        .into_iter()
        .map(|link| {
            let (name, matching) = match link {
                // As the OS's own: a veth is `ether` too and belongs to Docker.
                Interface::Wired => ("wired", "Type=ether\nKind=!*\n"),
                Interface::Wifi => ("wifi", "Type=wlan\nWLANInterfaceType=station\n"),
            };
            let mut body =
                format!("# From viaos.toml [network].\n[Match]\n{matching}\n[Network]\n");
            match n.mode {
                Addressing::Static => {
                    if let Some((ip, prefix)) = n.address() {
                        body += &format!("Address={ip}/{prefix}\n");
                    }
                    if let Some(g) = &n.gateway {
                        body += &format!("Gateway={g}\n");
                    }
                }
                Addressing::Dhcp => body += "DHCP=yes\n",
            }
            for d in &n.dns {
                body += &format!("DNS={d}\n");
            }
            if n.mode == Addressing::Dhcp {
                body +=
                    "\n[DHCPv4]\nUseDNS=no\n\n[DHCPv6]\nUseDNS=no\n\n[IPv6AcceptRA]\nUseDNS=no\n";
            }
            (format!("{NETWORK_PREFIX}{name}.network"), body)
        })
        .collect()
}

fn apply_network(n: Option<&Network>, p: &Paths) -> Result<()> {
    let files = match n {
        Some(n) => {
            n.check()?;
            network_files(n)
        }
        None => Vec::new(),
    };
    replace_files(&p.network, NETWORK_PREFIX, &files)
}

// ---- time ----

pub fn timesyncd_conf(t: &Time) -> Option<String> {
    (!t.ntp.is_empty()).then(|| format!("[Time]\nNTP={}\n", t.ntp.join(" ")))
}

fn apply_time(t: Option<&Time>, p: &Paths) -> Result<()> {
    let empty = Time::default();
    let t = t.unwrap_or(&empty);
    t.check()?;
    let conf: Vec<(String, String)> = timesyncd_conf(t)
        .map(|c| ("50-via.conf".to_string(), c))
        .into_iter()
        .collect();
    replace_files(&p.timesyncd, "50-via", &conf)?;
    let _ = std::fs::remove_file(&p.localtime);
    if let Some(tz) = &t.timezone {
        let zone = p.zoneinfo.join(tz);
        anyhow::ensure!(
            zone.is_file(),
            "no time zone {tz:?} in {}",
            p.zoneinfo.display()
        );
        std::os::unix::fs::symlink(&zone, &p.localtime)
            .with_context(|| format!("linking {}", p.localtime.display()))?;
    }
    Ok(())
}

// ---- proxy ----

/// The environment docker.service and via-agent.service read, in both the
/// upper- and lower-case spellings programs look for.
pub fn proxy_env(proxy: &Proxy) -> String {
    let mut out = String::new();
    for (name, value) in [("HTTP_PROXY", &proxy.http), ("HTTPS_PROXY", &proxy.https)] {
        if let Some(v) = value {
            out += &format!("{name}={v}\n{}={v}\n", name.to_lowercase());
        }
    }
    let no = proxy.no_proxy_list();
    out += &format!("NO_PROXY={no}\nno_proxy={no}\n");
    out
}

/// The Docker CLI config with `proxies` set to `proxy`, or taken out.
pub fn docker_config(
    existing: Option<serde_json::Value>,
    proxy: Option<&Proxy>,
) -> serde_json::Value {
    let mut config = existing
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));
    let obj = config.as_object_mut().expect("an object");
    match proxy.filter(|p| p.is_set()) {
        Some(p) => {
            let mut d = serde_json::Map::new();
            if let Some(v) = &p.http {
                d.insert("httpProxy".into(), v.clone().into());
            }
            if let Some(v) = &p.https {
                d.insert("httpsProxy".into(), v.clone().into());
            }
            d.insert("noProxy".into(), p.no_proxy_list().into());
            obj.insert("proxies".into(), serde_json::json!({ "default": d }));
        }
        None => {
            obj.remove("proxies");
        }
    }
    config
}

fn apply_proxy(proxy: Option<&Proxy>, p: &Paths) -> Result<()> {
    let proxy = proxy.filter(|p| p.is_set());
    if let Some(proxy) = proxy {
        proxy.check()?;
        if let Some(dir) = p.proxy_env.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_private(&p.proxy_env, proxy_env(proxy).as_bytes())?;
    } else {
        let _ = std::fs::remove_file(&p.proxy_env);
    }
    let existing = std::fs::read_to_string(&p.docker_config)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    if existing.is_none() && proxy.is_none() {
        return Ok(());
    }
    let config = docker_config(existing, proxy);
    if let Some(dir) = p.docker_config.parent() {
        mkdir_private(dir)?;
    }
    write_private(&p.docker_config, &serde_json::to_vec_pretty(&config)?)
}

// ---- files ----

/// Make `dir`'s files starting with `prefix` exactly `files`.
fn replace_files(dir: &Path, prefix: &str, files: &[(String, String)]) -> Result<()> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with(prefix) && !files.iter().any(|(n, _)| *n == name) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    if files.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for (name, body) in files {
        let path = dir.join(name);
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

fn mkdir_private(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

/// Root-only, and whole or not at all.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wifi(ssid: &str, pass: Option<&str>) -> Wifi {
        Wifi {
            ssid: ssid.into(),
            passphrase: pass.map(Into::into),
            ..Default::default()
        }
    }

    fn paths(root: &Path) -> Paths {
        let zoneinfo = root.join("zoneinfo");
        std::fs::create_dir_all(zoneinfo.join("America")).unwrap();
        std::fs::write(zoneinfo.join("America/Chicago"), "TZif").unwrap();
        Paths {
            network: root.join("network"),
            iwd: root.join("iwd"),
            wifi_written: root.join("via/wifi-written"),
            timesyncd: root.join("timesyncd.conf.d"),
            localtime: root.join("localtime"),
            zoneinfo,
            proxy_env: root.join("run/proxy.env"),
            docker_config: root.join("docker/config.json"),
        }
    }

    #[test]
    fn iwd_names_its_files_as_iwd_does() {
        assert_eq!(
            iwd_file_name(&wifi("Plant Floor_2-a", Some("x"))),
            "Plant Floor_2-a.psk"
        );
        assert_eq!(iwd_file_name(&wifi("guest", None)), "guest.open");
        assert_eq!(iwd_file_name(&wifi("guest", Some(""))), "guest.open");
        // Anything else is hex: punctuation, dots, UTF-8, and `=` itself.
        assert_eq!(iwd_file_name(&wifi("a.b", Some("x"))), "=612e62.psk");
        assert_eq!(iwd_file_name(&wifi("café", Some("x"))), "=636166c3a9.psk");
        assert_eq!(iwd_file_name(&wifi("=x", None)), "=3d78.open");
        assert_eq!(iwd_file_name(&wifi("../etc", None)), "=2e2e2f657463.open");
    }

    #[test]
    fn iwd_files_hold_the_key() {
        assert_eq!(
            iwd_file(&wifi("w", Some("correct horse"))),
            "[Security]\nPassphrase=correct horse\n"
        );
        assert_eq!(
            iwd_file(&wifi("w", Some(r" back\slash "))),
            "[Security]\nPassphrase=\\sback\\\\slash\\s\n"
        );
        let key = "AB".repeat(32);
        assert_eq!(
            iwd_file(&wifi("w", Some(&key))),
            format!("[Security]\nPreSharedKey={}\n", "ab".repeat(32))
        );
        let mut hidden = wifi("w", None);
        hidden.hidden = true;
        assert_eq!(iwd_file(&hidden), "[Settings]\nHidden=true\n");
        assert_eq!(iwd_file(&wifi("w", None)), "");
        assert_eq!(ell_escape("  "), "\\s\\s");
    }

    #[test]
    fn wifi_files_follow_the_settings() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let mut list = vec![wifi("first", Some("password1")), wifi("second", None)];
        list[1].priority = 1;
        apply_wifi(&list, &p).unwrap();
        let psk = p.iwd.join("first.psk");
        assert_eq!(
            std::fs::read_to_string(&psk).unwrap(),
            "[Security]\nPassphrase=password1\n"
        );
        let mtime = |n: &str| {
            std::fs::metadata(p.iwd.join(n))
                .unwrap()
                .modified()
                .unwrap()
        };
        // Higher priority looks more recently used.
        assert!(mtime("second.open") > mtime("first.psk"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&psk).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // What iwd adds is kept while the settings stay the same.
        std::fs::write(&psk, "[Security]\nPassphrase=password1\nPreSharedKey=00\n").unwrap();
        apply_wifi(&list, &p).unwrap();
        assert!(
            std::fs::read_to_string(&psk)
                .unwrap()
                .contains("PreSharedKey")
        );

        // A new passphrase rewrites it; a network dropped goes, and a file
        // iwd made on its own stays.
        std::fs::write(p.iwd.join("phone.psk"), "x").unwrap();
        apply_wifi(&[wifi("first", Some("password2"))], &p).unwrap();
        assert_eq!(
            std::fs::read_to_string(&psk).unwrap(),
            "[Security]\nPassphrase=password2\n"
        );
        assert!(!p.iwd.join("second.open").exists());
        assert!(p.iwd.join("phone.psk").exists());
        apply_wifi(&[], &p).unwrap();
        assert!(!psk.exists());
    }

    #[test]
    fn static_addressing_is_a_networkd_file_per_link() {
        let n = Network {
            mode: Addressing::Static,
            address: Some("192.168.10.20/24".into()),
            gateway: Some("192.168.10.1".into()),
            dns: vec!["192.168.10.1".into(), "1.1.1.1".into()],
            interfaces: vec![Interface::Wired],
        };
        assert_eq!(
            network_files(&n),
            [(
                "05-via-wired.network".to_string(),
                "# From viaos.toml [network].\n[Match]\nType=ether\nKind=!*\n\n[Network]\n\
                 Address=192.168.10.20/24\nGateway=192.168.10.1\nDNS=192.168.10.1\nDNS=1.1.1.1\n"
                    .to_string()
            )]
        );
        let both = Network {
            interfaces: vec![],
            ..n
        };
        let files = network_files(&both);
        assert_eq!(files[1].0, "05-via-wifi.network");
        assert!(
            files[1]
                .1
                .contains("Type=wlan\nWLANInterfaceType=station\n")
        );
        assert!(network_files(&Network::default()).is_empty());
        let dns = network_files(&Network {
            dns: vec!["10.0.0.53".into()],
            ..Default::default()
        });
        assert!(dns[0].1.contains("DHCP=yes\nDNS=10.0.0.53\n"));
        assert!(dns[0].1.contains("[DHCPv4]\nUseDNS=no"));
    }

    #[test]
    fn network_time_and_proxy_land_and_leave() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let s: Settings = toml::from_str(
            r#"
            [network]
            mode = "static"
            address = "10.0.0.5/24"
            interfaces = ["wifi"]
            [time]
            timezone = "America/Chicago"
            ntp = ["ntp.plant.lan", "10.0.0.1"]
            [proxy]
            https = "http://proxy:3128"
            no_proxy = [".plant.lan"]
            "#,
        )
        .unwrap();
        std::fs::create_dir_all(&p.network).unwrap();
        std::fs::write(p.network.join("05-via-wired.network"), "old").unwrap();
        std::fs::write(p.network.join("90-other.network"), "theirs").unwrap();
        std::fs::create_dir_all(p.docker_config.parent().unwrap()).unwrap();
        std::fs::write(&p.docker_config, r#"{"auths":{"r":{}}}"#).unwrap();
        apply(&s, &p);

        assert!(!p.network.join("05-via-wired.network").exists());
        assert!(p.network.join("90-other.network").exists());
        let wifi = std::fs::read_to_string(p.network.join("05-via-wifi.network")).unwrap();
        assert!(wifi.contains("Address=10.0.0.5/24\n"));
        assert_eq!(
            std::fs::read_to_string(p.timesyncd.join("50-via.conf")).unwrap(),
            "[Time]\nNTP=ntp.plant.lan 10.0.0.1\n"
        );
        assert_eq!(
            std::fs::read_link(&p.localtime).unwrap(),
            p.zoneinfo.join("America/Chicago")
        );
        let env = std::fs::read_to_string(&p.proxy_env).unwrap();
        assert!(env.contains("HTTPS_PROXY=http://proxy:3128\nhttps_proxy=http://proxy:3128\n"));
        assert!(env.contains("NO_PROXY=localhost,127.0.0.1,::1,.plant.lan\n"));
        assert!(!env.contains("HTTP_PROXY"));
        let docker: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p.docker_config).unwrap()).unwrap();
        assert_eq!(
            docker["proxies"]["default"]["httpsProxy"],
            "http://proxy:3128"
        );
        assert!(docker["auths"].is_object());

        // A time zone that isn't there leaves UTC; nothing set undoes it all.
        let bad: Settings = toml::from_str("[time]\ntimezone = \"Mars/Olympus\"\n").unwrap();
        apply(&bad, &p);
        assert!(p.localtime.symlink_metadata().is_err());
        apply(&Settings::default(), &p);
        assert!(!p.network.join("05-via-wifi.network").exists());
        assert!(!p.timesyncd.join("50-via.conf").exists());
        assert!(!p.proxy_env.exists());
        let docker: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p.docker_config).unwrap()).unwrap();
        assert!(docker.get("proxies").is_none());
    }
}
