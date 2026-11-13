//! A device's network and system settings: Wi-Fi, addressing, time and
//! proxy.
//!
//! One shape for every place they appear: the `[[wifi]]`, `[network]`,
//! `[time]` and `[proxy]` sections of `viaos.toml`, the arguments of the
//! control plane's provisioning tools, and a fleet's stored defaults. Each
//! section is optional, so an absent one means "not set here" and a fleet
//! can leave it to the fleet above.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Wi-Fi networks to join. The list replaces any inherited one; an
    /// empty list means none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wifi: Option<Vec<Wifi>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<Time>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Proxy>,
}

/// A Wi-Fi network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Wifi {
    pub ssid: String,
    /// WPA passphrase (8 to 63 characters) or a 64-hex-digit key. Empty
    /// for an open network. Omitted in a tool call: keep the one already
    /// stored for this SSID, or open if there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    /// The network does not broadcast its name.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    /// Higher is tried first. Equal priorities go in list order.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub priority: i32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Addressing {
    #[default]
    Dhcp,
    Static,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Interface {
    Wired,
    Wifi,
}

/// How the device gets its address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// `dhcp` (the default) or `static`.
    #[serde(default)]
    pub mode: Addressing,
    /// Static only: IPv4 address and prefix, e.g. `192.168.10.20/24`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Static only: the default gateway, e.g. `192.168.10.1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// DNS servers. With DHCP these replace the ones it offers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    /// Which links this applies to, `wired` and/or `wifi`. Empty: both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<Interface>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Time {
    /// IANA name, e.g. `America/Chicago`. Unset is UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// NTP servers, by name or address. Empty keeps the OS's defaults.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ntp: Vec<String>,
}

/// An HTTP proxy for the agent, Docker's image pulls and the containers
/// apps run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    /// For plain HTTP, e.g. `http://proxy.plant.lan:3128`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<String>,
    /// For HTTPS (and the control plane's `wss://`). Usually the same URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https: Option<String>,
    /// Hosts, domains (`.plant.lan`) or networks (`10.0.0.0/8`) to reach
    /// directly. Loopback always is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub no_proxy: Vec<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i32) -> bool {
    *n == 0
}

fn bad(what: impl Into<String>, reason: impl Into<String>) -> Error {
    Error::InvalidSetting {
        what: what.into(),
        reason: reason.into(),
    }
}

impl Settings {
    /// Every section checked. The agent checks each one on its own, so one
    /// bad value does not cost the rest.
    pub fn check(&self) -> Result<(), Error> {
        if let Some(wifi) = &self.wifi {
            check_wifi(wifi)?;
        }
        if let Some(n) = &self.network {
            n.check()?;
        }
        if let Some(t) = &self.time {
            t.check()?;
        }
        if let Some(p) = &self.proxy {
            p.check()?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// The networks in the order to try them: highest priority first, list
/// order among equals.
pub fn by_priority(wifi: &[Wifi]) -> Vec<&Wifi> {
    let mut v: Vec<&Wifi> = wifi.iter().collect();
    v.sort_by_key(|w| std::cmp::Reverse(w.priority));
    v
}

pub fn check_wifi(wifi: &[Wifi]) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for w in wifi {
        w.check()?;
        if !seen.insert(&w.ssid) {
            return Err(bad(format!("wifi {:?}", w.ssid), "listed twice"));
        }
    }
    Ok(())
}

impl Wifi {
    pub fn check(&self) -> Result<(), Error> {
        let what = || format!("wifi {:?}", self.ssid);
        if self.ssid.is_empty() || self.ssid.len() > 32 {
            return Err(bad(what(), "an SSID is 1 to 32 bytes"));
        }
        if self.ssid.chars().any(char::is_control) {
            return Err(bad(what(), "the SSID has control characters"));
        }
        if let Some(p) = self.passphrase.as_deref().filter(|p| !p.is_empty()) {
            let key = p.len() == 64 && p.chars().all(|c| c.is_ascii_hexdigit());
            let phrase = (8..=63).contains(&p.len()) && p.bytes().all(|b| (32..=126).contains(&b));
            if !key && !phrase {
                return Err(bad(
                    what(),
                    "a passphrase is 8 to 63 printable ASCII characters, or a key of 64 hex digits",
                ));
            }
        }
        Ok(())
    }

    pub fn is_open(&self) -> bool {
        self.passphrase.as_deref().unwrap_or_default().is_empty()
    }
}

impl Network {
    /// The links it covers, both when none are named.
    pub fn links(&self) -> Vec<Interface> {
        if self.interfaces.is_empty() {
            vec![Interface::Wired, Interface::Wifi]
        } else {
            let set: BTreeSet<Interface> = self.interfaces.iter().copied().collect();
            set.into_iter().collect()
        }
    }

    /// The static address split into address and prefix length.
    pub fn address(&self) -> Option<(Ipv4Addr, u8)> {
        let (ip, prefix) = self.address.as_deref()?.split_once('/')?;
        let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 32)?;
        Some((ip.parse().ok()?, prefix))
    }

    pub fn check(&self) -> Result<(), Error> {
        for d in &self.dns {
            d.parse::<IpAddr>()
                .map_err(|_| bad(format!("network dns {d:?}"), "not an IP address"))?;
        }
        match self.mode {
            Addressing::Dhcp => {
                if self.address.is_some() || self.gateway.is_some() {
                    return Err(bad(
                        "network",
                        "an address or gateway needs mode = \"static\"",
                    ));
                }
            }
            Addressing::Static => {
                let Some(text) = &self.address else {
                    return Err(bad(
                        "network",
                        "static needs an address, like 192.168.10.20/24",
                    ));
                };
                if self.address().is_none() {
                    return Err(bad(
                        format!("network address {text:?}"),
                        "expected an IPv4 address and prefix, like 192.168.10.20/24",
                    ));
                }
                if let Some(g) = &self.gateway {
                    g.parse::<Ipv4Addr>().map_err(|_| {
                        bad(format!("network gateway {g:?}"), "not an IPv4 address")
                    })?;
                }
            }
        }
        Ok(())
    }
}

impl Time {
    pub fn check(&self) -> Result<(), Error> {
        if let Some(tz) = &self.timezone {
            let ok = !tz.is_empty()
                && tz.len() <= 64
                && !tz.starts_with('/')
                && !tz.split('/').any(|p| p.is_empty() || p == "." || p == "..")
                && tz
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/_+-".contains(c));
            if !ok {
                return Err(bad(
                    format!("time zone {tz:?}"),
                    "expected an IANA name like America/Chicago",
                ));
            }
        }
        for s in &self.ntp {
            if !host_like(s) {
                return Err(bad(
                    format!("ntp server {s:?}"),
                    "not a host name or address",
                ));
            }
        }
        Ok(())
    }
}

impl Proxy {
    pub fn check(&self) -> Result<(), Error> {
        for (name, url) in [("http", &self.http), ("https", &self.https)] {
            let Some(url) = url else { continue };
            let rest = url
                .strip_prefix("http://")
                .or_else(|| url.strip_prefix("https://"));
            let ok = rest.is_some_and(|r| !r.is_empty())
                && url
                    .chars()
                    .all(|c| c.is_ascii_graphic() && !"\"'\\`$,;".contains(c));
            if !ok {
                return Err(bad(
                    format!("proxy {name} {url:?}"),
                    "expected a URL like http://proxy.example:3128",
                ));
            }
        }
        for n in &self.no_proxy {
            let ok = !n.is_empty()
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-:/*_[]".contains(c));
            if !ok {
                return Err(bad(
                    format!("no_proxy {n:?}"),
                    "expected a host, .domain or network",
                ));
            }
        }
        Ok(())
    }

    pub fn is_set(&self) -> bool {
        self.http.is_some() || self.https.is_some()
    }

    /// `no_proxy` as the comma list every tool reads, with loopback in it.
    pub fn no_proxy_list(&self) -> String {
        let mut all: Vec<&str> = vec!["localhost", "127.0.0.1", "::1"];
        for n in &self.no_proxy {
            if !all.contains(&n.as_str()) {
                all.push(n);
            }
        }
        all.join(",")
    }
}

/// A host name or an IP address.
fn host_like(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
        || (!s.is_empty()
            && s.len() <= 253
            && !s.starts_with(['-', '.'])
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.'))
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

    #[test]
    fn wifi_rules() {
        assert!(wifi("plant", Some("correct horse")).check().is_ok());
        assert!(wifi("café ☕", None).check().is_ok());
        assert!(wifi("open", Some("")).check().is_ok());
        assert!(wifi("k", Some(&"a1".repeat(32))).check().is_ok());
        assert!(wifi("", None).check().is_err());
        assert!(wifi(&"x".repeat(33), None).check().is_err());
        assert!(wifi("short", Some("1234567")).check().is_err());
        assert!(wifi("tab", Some("pass\tword")).check().is_err());
        assert!(check_wifi(&[wifi("a", None), wifi("a", None)]).is_err());
    }

    #[test]
    fn priority_then_list_order() {
        let mut list = vec![wifi("a", None), wifi("b", None), wifi("c", None)];
        list[2].priority = 5;
        let order: Vec<&str> = by_priority(&list).iter().map(|w| w.ssid.as_str()).collect();
        assert_eq!(order, ["c", "a", "b"]);
    }

    #[test]
    fn network_rules() {
        let mut n = Network {
            mode: Addressing::Static,
            address: Some("10.1.2.3/24".into()),
            gateway: Some("10.1.2.1".into()),
            dns: vec!["10.1.2.1".into(), "2606:4700::1111".into()],
            interfaces: vec![Interface::Wifi, Interface::Wired, Interface::Wifi],
        };
        assert!(n.check().is_ok());
        assert_eq!(n.address(), Some(("10.1.2.3".parse().unwrap(), 24)));
        assert_eq!(n.links(), [Interface::Wired, Interface::Wifi]);
        n.address = Some("10.1.2.3".into());
        assert!(n.check().is_err());
        n.address = Some("10.1.2.3/33".into());
        assert!(n.check().is_err());
        n.address = None;
        assert!(n.check().is_err());
        let dhcp = Network {
            gateway: Some("10.0.0.1".into()),
            ..Default::default()
        };
        assert!(dhcp.check().is_err());
        assert_eq!(Network::default().links().len(), 2);
    }

    #[test]
    fn time_and_proxy_rules() {
        let t = |tz: &str| Time {
            timezone: Some(tz.into()),
            ntp: vec!["pool.ntp.org".into(), "10.0.0.1".into()],
        };
        assert!(t("America/Argentina/Buenos_Aires").check().is_ok());
        assert!(t("Etc/GMT+5").check().is_ok());
        assert!(t("../etc/passwd").check().is_err());
        assert!(t("/UTC").check().is_err());
        let p = |url: &str| Proxy {
            http: Some(url.into()),
            ..Default::default()
        };
        assert!(p("http://user:pw@proxy:3128").check().is_ok());
        assert!(p("proxy:3128").check().is_err());
        assert!(p("http://a b").check().is_err());
        assert!(p("http://a\"b").check().is_err());
        let p = Proxy {
            no_proxy: vec![".plant.lan".into(), "localhost".into()],
            ..Default::default()
        };
        assert_eq!(p.no_proxy_list(), "localhost,127.0.0.1,::1,.plant.lan");
    }
}
