use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_native_tls::{native_tls, TlsConnector};

use crate::access::upstream_allowed;

/// Default time-to-live for cached DNS entries (10 minutes).
pub const DEFAULT_DNS_TTL: Duration = Duration::from_secs(600);

/// Maximum cache capacity to prevent unbounded memory growth.
pub const MAX_DNS_CACHE_CAPACITY: usize = 4096;

/// Entry stored in the in-memory DNS cache.
#[derive(Debug, Clone, Copy)]
pub struct DnsCacheEntry {
    pub ip: IpAddr,
    pub expires_at: Instant,
}

impl DnsCacheEntry {
    pub fn new(ip: IpAddr, ttl: Duration) -> Self {
        Self {
            ip,
            expires_at: Instant::now() + ttl,
        }
    }

    #[inline]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Thread-safe in-memory DNS cache with TTL expiration and bounded capacity.
pub struct DnsCache {
    entries: RwLock<HashMap<String, DnsCacheEntry>>,
    default_ttl: Duration,
    max_capacity: usize,
}

impl DnsCache {
    pub fn new(default_ttl: Duration, max_capacity: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            default_ttl,
            max_capacity,
        }
    }

    /// Looks up an unexpired IP for the specified hostname.
    pub fn get(&self, hostname: &str) -> Option<IpAddr> {
        let now = Instant::now();
        let guard = self.entries.read();
        if let Some(entry) = guard.get(&hostname.to_ascii_lowercase()) {
            if !entry.is_expired(now) {
                return Some(entry.ip);
            }
        }
        None
    }

    /// Stores an IP for the given hostname with the default TTL.
    pub fn insert(&self, hostname: &str, ip: IpAddr) {
        self.insert_with_ttl(hostname, ip, self.default_ttl);
    }

    /// Stores an IP for the given hostname with a custom TTL.
    pub fn insert_with_ttl(&self, hostname: &str, ip: IpAddr, ttl: Duration) {
        let now = Instant::now();
        let entry = DnsCacheEntry::new(ip, ttl);
        let mut guard = self.entries.write();

        // Evict expired entries if cache exceeds capacity threshold
        if guard.len() >= self.max_capacity {
            guard.retain(|_, v| !v.is_expired(now));
        }

        // If still full after pruning expired, drop one item to bound memory
        if guard.len() >= self.max_capacity {
            if let Some(key_to_remove) = guard.keys().next().cloned() {
                guard.remove(&key_to_remove);
            }
        }

        guard.insert(hostname.to_ascii_lowercase(), entry);
    }

    /// Removes an entry from the cache.
    pub fn remove(&self, hostname: &str) -> Option<IpAddr> {
        let mut guard = self.entries.write();
        guard.remove(&hostname.to_ascii_lowercase()).map(|e| e.ip)
    }

    /// Returns the number of entries currently in cache.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Checks whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Prunes expired entries from the cache, returning the number of removed entries.
    pub fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.entries.write();
        let original_len = guard.len();
        guard.retain(|_, v| !v.is_expired(now));
        original_len.saturating_sub(guard.len())
    }
}

/// Global DNS cache initialized lazily using `std::sync::LazyLock`.
///
/// Replaces legacy `lazy_static` with zero external crate dependencies.
pub static GLOBAL_DNS_CACHE: LazyLock<DnsCache> =
    LazyLock::new(|| DnsCache::new(DEFAULT_DNS_TTL, MAX_DNS_CACHE_CAPACITY));

/// Validates whether a candidate IP address is routable and valid.
pub fn is_valid_candidate_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Filter 0.0.0.0/8, 127.0.0.0/8
            if octets[0] == 0 || octets[0] == 127 {
                return false;
            }
            // Explicit filter of known unroutable IPs from legacy reference
            if v4 == std::net::Ipv4Addr::new(94, 190, 64, 51)
                || v4 == std::net::Ipv4Addr::new(151, 101, 195, 6)
                || v4 == std::net::Ipv4Addr::new(129, 134, 30, 12)
                || v4 == std::net::Ipv4Addr::new(66, 254, 114, 41)
                || v4 == std::net::Ipv4Addr::new(66, 254, 114, 42)
                || v4 == std::net::Ipv4Addr::new(66, 254, 122, 21)
                || v4 == std::net::Ipv4Addr::new(212, 102, 62, 43)
                || v4 == std::net::Ipv4Addr::new(146, 75, 119, 52)
                || (octets[0] == 212 && octets[1] == 188)
                || (octets[0] == 121 && octets[1] == 127 && octets[2] == 45)
                || (octets[0] == 37 && octets[1] == 19 && octets[2] == 202)
            {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    }
}

/// Delay before launching the next fallback IP in Happy Eyeballs connection racing.
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(150);

/// One address to try, and whether it may be cached before any payload arrives.
#[derive(Clone, Copy, Debug)]
struct Candidate {
    ip: IpAddr,
    /// System-resolver answers (ISP GGC) are cached only after downstream bytes.
    confirm_before_cache: bool,
}

/// Successful outbound TCP connection.
pub struct Outbound {
    pub stream: TcpStream,
    pub ip: IpAddr,
    /// When true, the caller caches `ip` only after the remote sends data.
    pub confirm_cache: bool,
}

fn build_dns_query_with_type(hostname: &str, qtype: u16) -> Option<(u16, Vec<u8>)> {
    let query_id: u16 = rand::random();
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&query_id.to_be_bytes());
    // RD=1, one question.
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for part in hostname.split('.') {
        let b = part.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return None;
        }
        packet.push(b.len() as u8);
        packet.extend_from_slice(b);
    }
    packet.push(0x00);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]);
    Some((query_id, packet))
}

fn build_dns_query(hostname: &str) -> Option<(u16, Vec<u8>)> {
    build_dns_query_with_type(hostname, 1)
}

/// Skips a domain name. A compression pointer ends the name on the wire.
fn skip_dns_name(buf: &[u8], mut idx: usize) -> Option<usize> {
    let mut hops = 0;
    loop {
        if idx >= buf.len() || hops > 32 {
            return None;
        }
        let len = buf[idx];
        if len == 0 {
            return idx.checked_add(1);
        }
        if len & 0xC0 == 0xC0 {
            if idx + 1 >= buf.len() {
                return None;
            }
            return idx.checked_add(2);
        }
        if len & 0xC0 != 0 || len > 63 {
            return None;
        }
        idx = idx.checked_add(1 + len as usize)?;
        hops += 1;
    }
}

/// Parses A (IPv4) and AAAA (IPv6) records from a DNS wire response.
pub fn parse_dns_ip_answers(buf: &[u8], expected_id: u16) -> Option<Vec<IpAddr>> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = flags & 0x8000 != 0;
    let rcode = flags & 0x000F;
    if !qr || rcode != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut idx = 12usize;
    for _ in 0..qdcount {
        idx = skip_dns_name(buf, idx)?;
        idx = idx.checked_add(4)?;
        if idx > buf.len() {
            return None;
        }
    }
    let mut ips = Vec::new();
    for _ in 0..ancount {
        idx = skip_dns_name(buf, idx)?;
        if idx + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        let rdlen = u16::from_be_bytes([buf[idx + 8], buf[idx + 9]]) as usize;
        idx += 10;
        if idx + rdlen > buf.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            ips.push(IpAddr::V4(Ipv4Addr::new(
                buf[idx],
                buf[idx + 1],
                buf[idx + 2],
                buf[idx + 3],
            )));
        } else if rtype == 28 && rdlen == 16 {
            let octets: [u8; 16] = buf[idx..idx + 16].try_into().ok()?;
            ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
        }
        idx += rdlen;
    }
    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

/// Parses A records. The question is walked in the response, and the id must match.
pub fn parse_dns_a_answers(buf: &[u8], expected_id: u16) -> Option<Vec<Ipv4Addr>> {
    let ips: Vec<Ipv4Addr> = parse_dns_ip_answers(buf, expected_id)?
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

static DOT_CONNECTOR: LazyLock<Option<TlsConnector>> =
    LazyLock::new(|| native_tls::TlsConnector::new().ok().map(TlsConnector::from));

async fn exchange_dns_stream<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    packet: &[u8],
    query_id: u16,
) -> Option<Vec<Ipv4Addr>> {
    let len = packet.len() as u16;
    let mut tcp_msg = Vec::with_capacity(2 + packet.len());
    tcp_msg.extend_from_slice(&len.to_be_bytes());
    tcp_msg.extend_from_slice(packet);

    timeout(Duration::from_millis(1500), stream.write_all(&tcp_msg))
        .await
        .ok()?
        .ok()?;
    let _ = timeout(Duration::from_millis(500), stream.flush()).await;

    let mut len_buf = [0u8; 2];
    timeout(Duration::from_millis(2000), stream.read_exact(&mut len_buf))
        .await
        .ok()?
        .ok()?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if !(12..=4096).contains(&resp_len) {
        return None;
    }

    let mut buf = vec![0u8; resp_len];
    timeout(Duration::from_millis(2000), stream.read_exact(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_dns_a_answers(&buf, query_id)
}

/// Queries a public DNS server directly over TCP (RFC 7766) for IPv4 (A) records.
/// Avoids ISP UDP 53 interception and spoofed NXDOMAIN / blackhole responses.
pub async fn query_dns_tcp(server_ip: &str, hostname: &str) -> Option<Vec<Ipv4Addr>> {
    let (query_id, packet) = build_dns_query(hostname)?;
    let target = format!("{server_ip}:53");
    let mut stream = timeout(Duration::from_millis(1500), TcpStream::connect(&target))
        .await
        .ok()?
        .ok()?;
    exchange_dns_stream(&mut stream, &packet, query_id).await
}

/// Queries a DNS-over-TLS (RFC 7858, port 853) resolver for IPv4 (A) records.
/// Prevents both UDP 53 response spoofing and plaintext port 53 filtering.
pub async fn query_dns_dot(
    server_ip: &str,
    tls_domain: &str,
    hostname: &str,
) -> Option<Vec<Ipv4Addr>> {
    let connector = DOT_CONNECTOR.as_ref()?;
    let (query_id, packet) = build_dns_query(hostname)?;
    let target = format!("{server_ip}:853");
    let tcp = timeout(Duration::from_millis(1800), TcpStream::connect(&target))
        .await
        .ok()?
        .ok()?;
    let mut tls = timeout(Duration::from_millis(1800), connector.connect(tls_domain, tcp))
        .await
        .ok()?
        .ok()?;
    exchange_dns_stream(&mut tls, &packet, query_id).await
}

/// Queries a public DNS server directly over UDP for IPv4 (A) records.
pub async fn query_dns_udp(server_ip: &str, hostname: &str) -> Option<Vec<Ipv4Addr>> {
    let (query_id, packet) = build_dns_query(hostname)?;
    let target: SocketAddr = format!("{server_ip}:53").parse().ok()?;
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.send_to(&packet, target).await.ok()?;

    let mut buf = [0u8; 1024];
    timeout(Duration::from_millis(1500), async {
        loop {
            let (len, from_addr) = socket.recv_from(&mut buf).await.ok()?;
            if from_addr != target || len < 12 {
                continue;
            }
            if let Some(ans) = parse_dns_a_answers(&buf[..len], query_id) {
                return Some(ans);
            }
        }
    })
    .await
    .ok()?
}

/// Parses HTTP/1.1 DoH response (plain or chunked) and extracts A/AAAA records.
fn parse_doh_http_response(raw: &[u8], expected_id: u16) -> Option<Vec<Ipv4Addr>> {
    let hdr_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&raw[..hdr_end]).ok()?;
    let status_line = headers.lines().next()?;
    if !status_line.contains(" 200 ") {
        return None;
    }
    let body = &raw[hdr_end + 4..];
    let is_chunked = headers
        .lines()
        .any(|l| l.to_ascii_lowercase().contains("transfer-encoding") && l.to_ascii_lowercase().contains("chunked"));
    if is_chunked {
        let mut decoded = Vec::with_capacity(body.len());
        let mut cursor = body;
        loop {
            let crlf = cursor.windows(2).position(|w| w == b"\r\n")?;
            let size_str = std::str::from_utf8(&cursor[..crlf])
                .ok()?
                .split(';')
                .next()?
                .trim();
            let chunk_len = usize::from_str_radix(size_str, 16).ok()?;
            cursor = &cursor[crlf + 2..];
            if chunk_len == 0 {
                break;
            }
            if cursor.len() < chunk_len + 2 {
                return None;
            }
            decoded.extend_from_slice(&cursor[..chunk_len]);
            cursor = &cursor[chunk_len + 2..];
        }
        parse_dns_a_answers(&decoded, expected_id)
    } else {
        parse_dns_a_answers(body, expected_id)
    }
}

/// Queries a DNS-over-HTTPS (RFC 8484, port 443) resolver when ports 53 and 853 are unavailable.
pub async fn query_dns_doh(
    server_ip: &str,
    tls_domain: &str,
    hostname: &str,
) -> Option<Vec<Ipv4Addr>> {
    let connector = DOT_CONNECTOR.as_ref()?;
    let (query_id, packet) = build_dns_query(hostname)?;
    let target = format!("{server_ip}:443");
    let tcp = timeout(Duration::from_millis(1800), TcpStream::connect(&target))
        .await
        .ok()?
        .ok()?;
    let mut tls = timeout(Duration::from_millis(1800), connector.connect(tls_domain, tcp))
        .await
        .ok()?
        .ok()?;

    let req_hdr = format!(
        "POST /dns-query HTTP/1.1\r\n\
         Host: {tls_domain}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        packet.len()
    );
    timeout(Duration::from_millis(1500), tls.write_all(req_hdr.as_bytes()))
        .await
        .ok()?
        .ok()?;
    timeout(Duration::from_millis(1500), tls.write_all(&packet))
        .await
        .ok()?
        .ok()?;
    let _ = timeout(Duration::from_millis(500), tls.flush()).await;

    let mut resp = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let _ = timeout(Duration::from_millis(2000), async {
        while resp.len() < 16384 {
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => resp.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    parse_doh_http_response(&resp, query_id)
}

/// Checks whether the host has a usable IPv6 route (cached for 60s, zero packets sent).
fn has_ipv6_route() -> bool {
    static V6_STATE: LazyLock<parking_lot::Mutex<Option<(Instant, bool)>>> =
        LazyLock::new(|| parking_lot::Mutex::new(None));
    {
        let guard = V6_STATE.lock();
        if let Some((checked_at, ok)) = *guard {
            if checked_at.elapsed() < Duration::from_secs(60) {
                return ok;
            }
        }
    }
    let ok = std::net::UdpSocket::bind("[::]:0")
        .and_then(|sock| sock.connect("[2001:4860:4860::8888]:443"))
        .is_ok();
    *V6_STATE.lock() = Some((Instant::now(), ok));
    ok
}

fn push_candidate(
    out: &mut Vec<Candidate>,
    ip: IpAddr,
    confirm_before_cache: bool,
    allow_local: bool,
) {
    if !is_valid_candidate_ip(ip)
        || !upstream_allowed(ip, allow_local)
        || out.iter().any(|c| c.ip == ip)
    {
        return;
    }
    if ip.is_ipv6() && !has_ipv6_route() {
        return;
    }
    out.push(Candidate {
        ip,
        confirm_before_cache,
    });
}

async fn lookup_system(hostname: &str, allow_local: bool, out: &mut Vec<Candidate>) {
    let addr_str = format!("{hostname}:443");
    if let Ok(Ok(addrs)) = timeout(
        Duration::from_millis(1500),
        tokio::net::lookup_host(addr_str),
    )
    .await
    {
        for sa in addrs {
            // ISP answers stay uncached until the connection actually carries data.
            push_candidate(out, sa.ip(), true, allow_local);
        }
    }
}

/// Races two DNS futures so a fast valid answer does not wait 1500ms if the peer server drops packets.
async fn race_dns_pair<F1, F2>(f1: F1, f2: F2) -> (Option<Vec<Ipv4Addr>>, Option<Vec<Ipv4Addr>>)
where
    F1: std::future::Future<Output = Option<Vec<Ipv4Addr>>>,
    F2: std::future::Future<Output = Option<Vec<Ipv4Addr>>>,
{
    tokio::pin!(f1);
    tokio::pin!(f2);

    tokio::select! {
        r1 = &mut f1 => {
            let r2 = if r1.is_some() {
                timeout(Duration::from_millis(120), &mut f2).await.ok().flatten()
            } else {
                f2.await
            };
            (r1, r2)
        }
        r2 = &mut f2 => {
            let r1 = if r2.is_some() {
                timeout(Duration::from_millis(120), &mut f1).await.ok().flatten()
            } else {
                f1.await
            };
            (r1, r2)
        }
    }
}

fn push_ips(out: &mut Vec<Candidate>, ips: Option<Vec<Ipv4Addr>>, confirm_before_cache: bool, allow_local: bool) -> bool {
    let Some(ips) = ips else {
        return false;
    };
    let mut found = false;
    for ip4 in ips {
        push_candidate(out, IpAddr::V4(ip4), confirm_before_cache, allow_local);
        found = true;
    }
    found
}

async fn lookup_public(hostname: &str, allow_local: bool, out: &mut Vec<Candidate>) {
    // Tier 1: Fast TCP:53 to public resolvers (immune to UDP:53 response injection).
    let (res_cf, res_goog) = race_dns_pair(
        query_dns_tcp("1.1.1.1", hostname),
        query_dns_tcp("8.8.8.8", hostname),
    )
    .await;
    if push_ips(out, res_cf, false, allow_local) | push_ips(out, res_goog, false, allow_local) {
        return;
    }

    // Tier 2: Encrypted DoT:853 (immune to port-53 filtering and plaintext interception).
    let (res_cf_dot, res_goog_dot) = race_dns_pair(
        query_dns_dot("1.1.1.1", "cloudflare-dns.com", hostname),
        query_dns_dot("8.8.8.8", "dns.google", hostname),
    )
    .await;
    if push_ips(out, res_cf_dot, false, allow_local)
        | push_ips(out, res_goog_dot, false, allow_local)
    {
        return;
    }

    // Tier 3: Encrypted DoH:443 fallback when both port 53 and 853 are restricted.
    let (res_cf_doh, res_goog_doh) = race_dns_pair(
        query_dns_doh("1.1.1.1", "cloudflare-dns.com", hostname),
        query_dns_doh("8.8.8.8", "dns.google", hostname),
    )
    .await;
    if push_ips(out, res_cf_doh, false, allow_local)
        | push_ips(out, res_goog_doh, false, allow_local)
    {
        return;
    }

    // Tier 4: Domestic non-poisoned DoT:853 + TCP:53 fallback.
    let (res_ya_dot, res_ya_tcp) = race_dns_pair(
        query_dns_dot("77.88.8.8", "common.dot.dns.yandex.net", hostname),
        query_dns_tcp("77.88.8.2", hostname),
    )
    .await;
    if push_ips(out, res_ya_dot, false, allow_local)
        | push_ips(out, res_ya_tcp, false, allow_local)
    {
        return;
    }

    // Tier 4: Last-resort UDP:53. Require downstream confirmation before caching
    // so an ISP-injected UDP:53 response cannot poison GLOBAL_DNS_CACHE.
    let (res_cf_udp, res_goog_udp) = race_dns_pair(
        query_dns_udp("1.1.1.1", hostname),
        query_dns_udp("8.8.8.8", hostname),
    )
    .await;
    let _ = push_ips(out, res_cf_udp, true, allow_local)
        | push_ips(out, res_goog_udp, true, allow_local);
}

/// Resolves candidate IP addresses for a given hostname.
///
/// Public resolvers over TCP are preferred for the long-lived cache.
/// The system resolver is included so a nearby CDN node can still win the race,
/// but those addresses are not stored until payload bytes arrive.
pub async fn resolve_candidate_ips(hostname: &str) -> Vec<IpAddr> {
    resolve_candidates(hostname, true)
        .await
        .into_iter()
        .map(|c| c.ip)
        .collect()
}

async fn resolve_candidates(hostname: &str, allow_local: bool) -> Vec<Candidate> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let mut out = Vec::new();
        push_candidate(&mut out, ip, false, allow_local);
        return out;
    }

    if let Some(cached_ip) = GLOBAL_DNS_CACHE.get(hostname) {
        let mut out = Vec::with_capacity(1);
        push_candidate(&mut out, cached_ip, false, allow_local);
        if !out.is_empty() {
            return out;
        }
    }

    let mut candidates = Vec::new();
    let host_lower = hostname.to_ascii_lowercase();
    if host_lower.contains("battleye") || host_lower.contains("becdn.net") {
        // Fast, valid European Anycast nodes for BattlEye CDN
        push_candidate(&mut candidates, IpAddr::V4(std::net::Ipv4Addr::new(185, 229, 190, 148)), false, allow_local);
        push_candidate(&mut candidates, IpAddr::V4(std::net::Ipv4Addr::new(185, 229, 190, 147)), false, allow_local);
    }

    let mut public_candidates = Vec::new();
    let mut system = Vec::new();
    tokio::join!(
        lookup_public(hostname, allow_local, &mut public_candidates),
        lookup_system(hostname, allow_local, &mut system)
    );
    for c in public_candidates {
        push_candidate(&mut candidates, c.ip, c.confirm_before_cache, allow_local);
    }
    // Keep public answers even when the ISP resolver returns a long CDN list.
    select_candidates(candidates, system)
}

fn select_candidates(mut public: Vec<Candidate>, system: Vec<Candidate>) -> Vec<Candidate> {
    public.truncate(4);
    for candidate in system {
        if public.len() >= 6 {
            break;
        }
        if public.iter().any(|existing| existing.ip == candidate.ip) {
            continue;
        }
        public.push(Candidate {
            ip: candidate.ip,
            confirm_before_cache: true,
        });
    }
    public
}

pub const SOCKET_BUF_SIZE: usize = 128 * 1024; // 128 KB OS socket buffer

/// Configures socket options: `TCP_NODELAY`, keepalive (30s/10s), and receive/send buffers.
pub fn tune_socket_with_buf(stream: &TcpStream, buf_size: usize) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(buf_size);
    let _ = sock.set_send_buffer_size(buf_size);

    let mut keepalive = socket2::TcpKeepalive::new();
    keepalive = keepalive.with_time(Duration::from_secs(30));
    keepalive = keepalive.with_interval(Duration::from_secs(10));
    let _ = sock.set_tcp_keepalive(&keepalive);
}

/// Configures socket options with the default 128 KB receive/send buffers.
pub fn tune_socket(stream: &TcpStream) {
    tune_socket_with_buf(stream, SOCKET_BUF_SIZE);
}

async fn connect_one(ip: IpAddr, port: u16) -> Option<TcpStream> {
    let target = SocketAddr::new(ip, port);
    match timeout(Duration::from_millis(2500), TcpStream::connect(target)).await {
        Ok(Ok(stream)) => {
            if crate::logger::verbose_logging_enabled() {
                eprintln!("[DNS] connect_one to {}:{} SUCCESS", ip, port);
            }
            tune_socket(&stream);
            Some(stream)
        }
        Ok(Err(e)) => {
            if crate::logger::verbose_logging_enabled() {
                eprintln!("[DNS] connect_one to {}:{} ERROR: {}", ip, port, e);
            }
            None
        }
        Err(_) => {
            if crate::logger::verbose_logging_enabled() {
                eprintln!("[DNS] connect_one to {}:{} TIMED OUT", ip, port);
            }
            None
        }
    }
}

/// Connects to a remote host using in-memory DNS cache fast-path and staggered Happy Eyeballs racing.
///
/// `allow_local` permits a loopback upstream. Private and link-local addresses
/// stay closed. Public-resolver answers are cached immediately. System-resolver
/// answers set `confirm_cache` so the caller stores them only after data flows.
pub async fn connect_to_remote(hostname: &str, port: u16, allow_local: bool) -> Option<Outbound> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        if !upstream_allowed(ip, allow_local) {
            return None;
        }
        let stream = connect_one(ip, port).await?;
        return Some(Outbound {
            stream,
            ip,
            confirm_cache: false,
        });
    }

    // Fast-path: attempt cached IP directly with zero network DNS queries
    if let Some(cached_ip) = GLOBAL_DNS_CACHE.get(hostname) {
        if is_valid_candidate_ip(cached_ip) && upstream_allowed(cached_ip, allow_local) {
            if let Some(stream) = connect_one(cached_ip, port).await {
                return Some(Outbound {
                    stream,
                    ip: cached_ip,
                    confirm_cache: false,
                });
            }
        }
        GLOBAL_DNS_CACHE.remove(hostname);
    }

    let candidates = resolve_candidates(hostname, allow_local).await;
    if crate::logger::verbose_logging_enabled() {
        eprintln!(
            "[DNS] connect_to_remote for {hostname}:{port}: {} candidates: {:?}",
            candidates.len(),
            candidates.iter().map(|c| c.ip).collect::<Vec<_>>()
        );
    }
    if candidates.is_empty() {
        return None;
    }

    // Staggered Happy Eyeballs (RFC 8305): start primary candidate immediately,
    // launching subsequent candidates every 150ms (or immediately on fast error).
    let mut pending = JoinSet::new();
    let mut next_idx = 0usize;

    let spawn_next = |pending: &mut JoinSet<Option<(TcpStream, Candidate)>>, cand: Candidate| {
        pending.spawn(async move {
            let stream = connect_one(cand.ip, port).await?;
            Some((stream, cand))
        });
    };

    spawn_next(&mut pending, candidates[0]);
    next_idx += 1;

    loop {
        if pending.is_empty() {
            if next_idx < candidates.len() {
                spawn_next(&mut pending, candidates[next_idx]);
                next_idx += 1;
            } else {
                break;
            }
        }

        if next_idx < candidates.len() {
            tokio::select! {
                joined = pending.join_next() => {
                    match joined {
                        Some(Ok(Some((stream, candidate)))) => {
                            pending.abort_all();
                            if !candidate.confirm_before_cache {
                                GLOBAL_DNS_CACHE.insert(hostname, candidate.ip);
                            }
                            return Some(Outbound {
                                stream,
                                ip: candidate.ip,
                                confirm_cache: candidate.confirm_before_cache,
                            });
                        }
                        Some(_) => {
                            // Fast failure on current attempt: launch next candidate immediately
                            spawn_next(&mut pending, candidates[next_idx]);
                            next_idx += 1;
                        }
                        None => {}
                    }
                }
                _ = tokio::time::sleep(HAPPY_EYEBALLS_DELAY) => {
                    spawn_next(&mut pending, candidates[next_idx]);
                    next_idx += 1;
                }
            }
        } else {
            match pending.join_next().await {
                Some(Ok(Some((stream, candidate)))) => {
                    pending.abort_all();
                    if !candidate.confirm_before_cache {
                        GLOBAL_DNS_CACHE.insert(hostname, candidate.ip);
                    }
                    return Some(Outbound {
                        stream,
                        ip: candidate.ip,
                        confirm_cache: candidate.confirm_before_cache,
                    });
                }
                Some(_) => continue,
                None => break,
            }
        }
    }

    GLOBAL_DNS_CACHE.remove(hostname);
    None
}

pub fn remember_confirmed_ip(hostname: &str, ip: IpAddr) {
    if upstream_allowed(ip, false)
        && is_valid_candidate_ip(ip)
        && (!ip.is_ipv6() || has_ipv6_route())
    {
        GLOBAL_DNS_CACHE.insert_with_ttl(hostname, ip, Duration::from_secs(300));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_select_candidates_keeps_public_answers() {
        let public = vec![
            Candidate {
                ip: "1.1.1.1".parse().unwrap(),
                confirm_before_cache: false,
            },
            Candidate {
                ip: "1.0.0.1".parse().unwrap(),
                confirm_before_cache: false,
            },
            Candidate {
                ip: "8.8.8.8".parse().unwrap(),
                confirm_before_cache: false,
            },
            Candidate {
                ip: "8.8.4.4".parse().unwrap(),
                confirm_before_cache: false,
            },
            Candidate {
                ip: "9.9.9.9".parse().unwrap(),
                confirm_before_cache: false,
            },
        ];
        let system = vec![
            Candidate {
                ip: "203.0.113.5".parse().unwrap(),
                confirm_before_cache: true,
            },
            Candidate {
                ip: "203.0.113.6".parse().unwrap(),
                confirm_before_cache: true,
            },
            Candidate {
                ip: "203.0.113.7".parse().unwrap(),
                confirm_before_cache: true,
            },
        ];
        let chosen = select_candidates(public, system);
        assert_eq!(chosen.len(), 6);
        assert!(chosen.iter().take(4).all(|c| !c.confirm_before_cache));
        assert_eq!(chosen.iter().filter(|c| c.confirm_before_cache).count(), 2);
        assert!(!chosen
            .iter()
            .any(|c| c.ip == "203.0.113.7".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_dns_cache_ttl_and_eviction() {
        let cache = DnsCache::new(Duration::from_millis(50), 2);
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "8.8.8.8".parse().unwrap();
        let ip3: IpAddr = "9.9.9.9".parse().unwrap();

        cache.insert("example1.com", ip1);
        cache.insert("example2.com", ip2);
        assert_eq!(cache.get("example1.com"), Some(ip1));
        assert_eq!(cache.get("example2.com"), Some(ip2));
        assert_eq!(cache.len(), 2);

        // Third entry triggers eviction due to capacity = 2
        cache.insert("example3.com", ip3);
        assert_eq!(cache.len(), 2);

        // Sleep to test TTL expiration
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cache.get("example3.com"), None);
    }

    #[test]
    fn test_is_valid_candidate_ip() {
        assert!(!is_valid_candidate_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_valid_candidate_ip("0.0.0.0".parse().unwrap()));
        assert!(!is_valid_candidate_ip("94.190.64.51".parse().unwrap()));
        assert!(!is_valid_candidate_ip("::1".parse().unwrap()));
        assert!(!is_valid_candidate_ip("::".parse().unwrap()));
        assert!(is_valid_candidate_ip("1.1.1.1".parse().unwrap()));
        assert!(is_valid_candidate_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_dns_cache_prune() {
        let cache = DnsCache::new(Duration::from_millis(50), 10);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.insert("expired.com", ip);
        cache.insert_with_ttl("valid.com", ip, Duration::from_secs(60));
        assert_eq!(cache.len(), 2);

        std::thread::sleep(Duration::from_millis(60));
        let pruned = cache.prune_expired();
        assert_eq!(pruned, 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("valid.com"), Some(ip));
        assert_eq!(cache.get("expired.com"), None);
    }

    #[test]
    fn test_dns_query_and_a_answer_roundtrip() {
        let (qid, query) = build_dns_query("www.pixiv.net").expect("valid query");
        assert!(query.len() > 12);

        // Build a synthetic valid A-record response matching qid and question
        let mut resp = query.clone();
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80; // RA=1, RCODE=0
        resp[6] = 0x00;
        resp[7] = 0x01; // ANCOUNT=1
        // Compression pointer to offset 12, Type=A (1), Class=IN (1), TTL=60, RDLEN=4, IP=8.47.69.0
        resp.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 8, 47, 69, 0,
        ]);

        let ips = parse_dns_a_answers(&resp, qid).expect("valid response");
        assert_eq!(ips, vec![Ipv4Addr::new(8, 47, 69, 0)]);
        assert!(parse_dns_a_answers(&resp, qid.wrapping_add(1)).is_none());
    }

    #[test]
    fn test_doh_http_response_plain_and_chunked_and_aaaa() {
        let (qid, query) = build_dns_query_with_type("example.com", 28).expect("valid AAAA query");
        let mut dns_resp = query;
        dns_resp[2] = 0x81;
        dns_resp[3] = 0x80;
        dns_resp[6] = 0x00;
        dns_resp[7] = 0x01;
        dns_resp.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10,
            0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ]);
        let parsed = parse_dns_ip_answers(&dns_resp, qid).expect("parsed AAAA");
        assert_eq!(parsed, vec!["2606:4700::1111".parse::<IpAddr>().unwrap()]);

        let (qid4, q4) = build_dns_query("example.com").unwrap();
        let mut r4 = q4;
        r4[2] = 0x81;
        r4[3] = 0x80;
        r4[6] = 0x00;
        r4[7] = 0x01;
        r4.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 1, 2, 3, 4,
        ]);
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        chunked.extend_from_slice(format!("{:x}\r\n", r4.len()).as_bytes());
        chunked.extend_from_slice(&r4);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let doh_ips = parse_doh_http_response(&chunked, qid4).expect("chunked DoH parse");
        assert_eq!(doh_ips, vec![Ipv4Addr::new(1, 2, 3, 4)]);
    }
}
