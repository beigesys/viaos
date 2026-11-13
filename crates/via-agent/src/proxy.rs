//! The control-plane WebSocket through an HTTP proxy.
//!
//! reqwest (enrollment, downloads) takes `HTTPS_PROXY` and `NO_PROXY` from
//! the environment on its own; the WebSocket library does not. A site that
//! only lets traffic out through a proxy still needs the device's one
//! connection, so this opens it with `CONNECT`, the way a browser would.
//! The variables come from `[proxy]` in viaos.toml, through the
//! EnvironmentFile via-agent.service reads.

use anyhow::{Context, Result, bail};
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The proxy to reach `host` through for a `ws`/`wss` URL, if any.
pub fn for_url(scheme: &str, host: &str) -> Option<String> {
    let var = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()))
    };
    let proxy = match scheme {
        "wss" | "https" => var(&["HTTPS_PROXY", "https_proxy"]),
        _ => var(&["HTTP_PROXY", "http_proxy"]),
    }?;
    let no_proxy = var(&["NO_PROXY", "no_proxy"]).unwrap_or_default();
    (!bypassed(host, &no_proxy)).then_some(proxy)
}

/// Whether `no_proxy` (comma-separated: `*`, hosts, `.domains`, IPv4
/// networks) sends `host` direct.
fn bypassed(host: &str, no_proxy: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    no_proxy.split(',').map(str::trim).any(|entry| {
        if entry == "*" {
            return true;
        }
        if let Some((net, bits)) = entry.split_once('/') {
            return in_network(host, net, bits);
        }
        let domain = entry.trim_start_matches('.');
        !domain.is_empty()
            && (host.eq_ignore_ascii_case(domain)
                || host
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", domain.to_ascii_lowercase())))
    })
}

fn in_network(host: &str, net: &str, bits: &str) -> bool {
    let (Ok(ip), Ok(net), Ok(bits)) = (
        host.parse::<std::net::Ipv4Addr>(),
        net.parse::<std::net::Ipv4Addr>(),
        bits.parse::<u32>(),
    ) else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    u32::from(ip) & mask == u32::from(net) & mask
}

/// A TCP stream to `host:port` tunnelled through `proxy`, an `http://`
/// URL, optionally with `user:password@`.
pub async fn tunnel(proxy: &str, host: &str, port: u16) -> Result<TcpStream> {
    let Some(rest) = proxy.strip_prefix("http://") else {
        bail!("proxy {proxy:?}: the control-plane connection needs an http:// proxy");
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let (auth, addr) = match authority.rsplit_once('@') {
        Some((userinfo, addr)) => (Some(userinfo), addr),
        None => (None, authority),
    };
    let addr = if addr
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
    {
        addr.to_string()
    } else {
        format!("{addr}:80")
    };
    let mut stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("reaching the proxy at {addr}"))?;
    let target = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(userinfo) = auth {
        let encoded = base64::engine::general_purpose::STANDARD.encode(userinfo);
        req += &format!("Proxy-Authorization: Basic {encoded}\r\n");
    }
    req += "\r\n";
    stream.write_all(req.as_bytes()).await?;

    // Read up to the end of the response head, a byte at a time so nothing
    // past it is taken from the tunnel.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(head.len() < 8192, "the proxy's answer is too long");
        let b = stream
            .read_u8()
            .await
            .context("the proxy closed the connection")?;
        head.push(b);
    }
    let status = String::from_utf8_lossy(&head);
    let line = status.lines().next().unwrap_or_default();
    match line.split_whitespace().nth(1) {
        Some(code) if code.starts_with('2') => Ok(stream),
        _ => bail!("the proxy refused {target}: {line}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_matches_hosts_domains_and_networks() {
        let list = "localhost, .plant.lan,example.com,10.0.0.0/8";
        assert!(bypassed("localhost", list));
        assert!(bypassed("via.plant.lan", list));
        assert!(bypassed("plant.lan", list));
        assert!(bypassed("API.Example.com", list));
        assert!(bypassed("10.20.30.40", list));
        assert!(!bypassed("notexample.com", list));
        assert!(!bypassed("11.0.0.1", list));
        assert!(!bypassed("via.example.org", list));
        assert!(bypassed("anything", "*"));
        assert!(!bypassed("anything", ""));
    }

    #[tokio::test]
    async fn tunnels_through_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nhello")
                .await
                .unwrap();
            req
        });
        let mut s = tunnel(&format!("http://u:p@{addr}"), "via.example.com", 443)
            .await
            .unwrap();
        let mut rest = [0; 5];
        s.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"hello");
        let req = proxy.await.unwrap();
        assert!(
            req.starts_with("CONNECT via.example.com:443 HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(req.contains("Proxy-Authorization: Basic dTpw\r\n"), "{req}");
    }

    #[tokio::test]
    async fn a_refusal_is_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0; 512];
            let _ = s.read(&mut buf).await;
            s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        });
        let e = tunnel(&format!("http://{addr}"), "x", 443)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("403"), "{e}");
    }
}
