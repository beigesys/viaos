//! A budget for requests from people who aren't signed in.
//!
//! Each client address gets a bucket of [`BURST`] requests that refills at
//! [`PER_MINUTE`]. Anonymous routes (sign-in, OAuth, enrollment) spend from
//! it, and so does a request that offers a token we don't know. Someone with
//! a good token is never limited: this is one organisation's server.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Instant;

use axum::extract::{ConnectInfo, Request, State as AxState};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use crate::State;

pub const BURST: f64 = 30.0;
pub const PER_MINUTE: f64 = 30.0;
/// More addresses than this at once and the full buckets are dropped: a
/// full bucket is the same as no bucket.
const MAX_ADDRESSES: usize = 10_000;

pub struct Limiter {
    /// How many proxies in front of us add to X-Forwarded-For.
    proxies: usize,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl Limiter {
    pub fn new(proxies: usize) -> Self {
        Self {
            proxies,
            buckets: Mutex::default(),
        }
    }

    /// Who's asking: the peer, or with a trusted proxy the address it saw.
    /// An IPv6 client is its /64, since it has the whole /64 to pick from.
    pub fn client(&self, req: &Request) -> IpAddr {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        let ip = match self.proxies {
            0 => peer,
            n => forwarded(req.headers(), n).or(peer),
        }
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => {
                    let s = v6.segments();
                    IpAddr::from([s[0], s[1], s[2], s[3], 0, 0, 0, 0])
                }
            },
            v4 => v4,
        }
    }

    /// Spend one request; `Err` holds the seconds until there's one to spend.
    pub fn take(&self, ip: IpAddr) -> Result<(), u64> {
        self.spend(ip, Instant::now(), 1.0)
    }

    /// Whether `ip` has a request left, without spending it.
    pub fn peek(&self, ip: IpAddr) -> Result<(), u64> {
        self.spend(ip, Instant::now(), 0.0)
    }

    fn spend(&self, ip: IpAddr, now: Instant, cost: f64) -> Result<(), u64> {
        let rate = PER_MINUTE / 60.0;
        let refilled = |left: f64, at: Instant| {
            (left + now.saturating_duration_since(at).as_secs_f64() * rate).min(BURST)
        };
        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() >= MAX_ADDRESSES && !buckets.contains_key(&ip) {
            buckets.retain(|_, (left, at)| refilled(*left, *at) < BURST);
            if buckets.len() >= MAX_ADDRESSES {
                // A flood of addresses: forget them all rather than grow.
                buckets.clear();
            }
        }
        let (left, at) = buckets.entry(ip).or_insert((BURST, now));
        *left = refilled(*left, *at);
        *at = now;
        if *left >= 1.0 {
            *left -= cost;
            Ok(())
        } else {
            Err(((1.0 - *left) / rate).ceil() as u64)
        }
    }
}

/// The address the outermost of `proxies` proxies saw. Each adds the one it
/// saw to the end of the list, so anything further left came from the client
/// and proves nothing.
fn forwarded(headers: &HeaderMap, proxies: usize) -> Option<IpAddr> {
    let all: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    all.get(all.len().checked_sub(proxies)?)?.parse().ok()
}

pub fn too_many(wait: u64) -> Response {
    let mut res = (
        StatusCode::TOO_MANY_REQUESTS,
        "too many requests without signing in; try again shortly",
    )
        .into_response();
    res.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(wait.max(1)));
    res
}

/// Every request through here spends from its sender's budget.
pub async fn every(AxState(s): AxState<Arc<State>>, req: Request, next: Next) -> Response {
    match s.limiter.take(s.limiter.client(&req)) {
        Ok(()) => next.run(req).await,
        Err(wait) => too_many(wait),
    }
}

/// Only a refused request spends, so a building full of devices enrolling at
/// once isn't held up; one that's spent its budget is refused unread.
pub async fn failures(AxState(s): AxState<Arc<State>>, req: Request, next: Next) -> Response {
    let ip = s.limiter.client(&req);
    if let Err(wait) = s.limiter.peek(ip) {
        return too_many(wait);
    }
    let res = next.run(req).await;
    if res.status().is_client_error() {
        let _ = s.limiter.take(ip);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_bucket_empties_and_refills() {
        let l = Limiter::new(0);
        let ip = IpAddr::from([10, 0, 0, 1]);
        let t = Instant::now();
        for _ in 0..BURST as usize {
            l.spend(ip, t, 1.0).unwrap();
        }
        assert_eq!(l.spend(ip, t, 1.0), Err(2));
        // Someone else still has theirs.
        l.spend(IpAddr::from([10, 0, 0, 2]), t, 1.0).unwrap();
        l.spend(ip, t + Duration::from_secs(2), 1.0).unwrap();
        assert!(l.spend(ip, t + Duration::from_secs(2), 1.0).is_err());
    }

    #[test]
    fn only_a_trusted_proxy_names_the_client() {
        let req = |xff: &str| {
            let mut r = Request::builder()
                .header("x-forwarded-for", xff)
                .body(axum::body::Body::empty())
                .unwrap();
            r.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([10, 9, 9, 9], 1))));
            r
        };
        let proxied = Limiter::new(1);
        // A client can say what it likes before the proxy's entry.
        assert_eq!(
            proxied.client(&req("1.1.1.1, 203.0.113.7")),
            IpAddr::from([203, 0, 113, 7])
        );
        assert_eq!(
            proxied.client(&req("2001:db8:1:2:3:4:5:6")),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap()
        );
        // Railway: the client, then its own edge.
        let railway = Limiter::new(2);
        assert_eq!(
            railway.client(&req("1.1.1.1, 203.0.113.7, 192.0.2.1")),
            IpAddr::from([203, 0, 113, 7])
        );
        // Fewer entries than proxies: the peer, not a guess.
        assert_eq!(
            railway.client(&req("203.0.113.7")),
            IpAddr::from([10, 9, 9, 9])
        );
        let direct = Limiter::new(0);
        assert_eq!(
            direct.client(&req("203.0.113.7")),
            IpAddr::from([10, 9, 9, 9])
        );
    }
}
