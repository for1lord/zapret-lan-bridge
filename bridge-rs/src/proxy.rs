use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::access::{self, upstream_allowed};
use crate::dns::{self, connect_to_remote};
use crate::metrics::ProxyMetrics;
use crate::router::SmartRouter;
use crate::socks5;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(3000);
pub const MAX_HEADER_SIZE: usize = 65536;
pub const UPSTREAM_BUF_SIZE: usize = 32768; // 32 KB client -> remote
pub const DOWNSTREAM_BUF_SIZE: usize = 262144; // 256 KB remote -> client (optimized for high-bitrate streaming)
pub const SOCKET_BUF_SIZE: usize = 512 * 1024; // 512 KB OS socket buffer

/// Runs the unified protocol-autodetecting proxy listener with default web router.
pub async fn run_proxy_listener(
    addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let web_config = crate::web::WebConfig::default_with_port(addr.port());
    let web_router = crate::web::create_web_router(Arc::clone(&metrics), web_config);
    run_proxy_listener_with_web(addr, router, metrics, web_router).await
}

/// Runs the unified protocol-autodetecting proxy listener with a custom web router.
pub async fn run_proxy_listener_with_web(
    addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
    web_router: axum::Router,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    run_proxy_accept_loop(listener, router, metrics, web_router).await
}

/// Runs the universal proxy accept loop on an already-bound `TcpListener`.
pub async fn run_proxy_accept_loop(
    listener: TcpListener,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
    web_router: axum::Router,
) -> io::Result<()> {
    if let Ok(addr) = listener.local_addr() {
        println!("[Proxy] Universal listener active on {}", addr);
    }

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => {
                metrics.inc_errors();
                continue;
            }
        };

        let router = Arc::clone(&router);
        let metrics = Arc::clone(&metrics);
        let web_router = web_router.clone();

        tokio::spawn(async move {
            let _ = handle_inbound_stream_with_web(stream, peer_addr, router, metrics, web_router)
                .await;
        });
    }
}

/// Dispatches inbound streams via 1-byte non-destructive peek autodetection.
pub async fn handle_inbound_stream(
    stream: TcpStream,
    peer_addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let web_config = crate::web::WebConfig::default_with_port(8080);
    let web_router = crate::web::create_web_router(Arc::clone(&metrics), web_config);
    handle_inbound_stream_with_web(stream, peer_addr, router, metrics, web_router).await
}

/// Dispatches inbound streams via 1-byte non-destructive peek autodetection with custom web router.
pub async fn handle_inbound_stream_with_web(
    stream: TcpStream,
    peer_addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
    web_router: axum::Router,
) -> io::Result<()> {
    tune_socket(&stream);
    if !access::peer_allowed(peer_addr) {
        metrics.inc_errors();
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client is outside the local subnet",
        ));
    }

    // Non-destructive 1-byte peek
    let mut peek_buf = [0u8; 1];
    let peek_res = match timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut peek_buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            metrics.inc_errors();
            return Err(e);
        }
        Err(_) => {
            metrics.inc_errors();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Handshake timed out",
            ));
        }
    };

    if peek_res == 0 {
        return Ok(());
    }

    let first_byte = peek_buf[0];
    if crate::logger::verbose_logging_enabled() {
        eprintln!(
            "[Proxy] Inbound stream from {peer_addr}: first byte 0x{first_byte:02X} ('{}')",
            if first_byte.is_ascii_graphic() {
                first_byte as char
            } else {
                '.'
            }
        );
    }
    if first_byte == socks5::SOCKS_VERSION {
        // Dispatch to SOCKS5 engine (tracks its own connection guard)
        socks5::handle_socks5_stream(stream, router, metrics).await
    } else if first_byte.is_ascii_alphabetic() {
        // Dispatch to HTTP engine (tracks its own connection guard)
        handle_http_stream_with_web(stream, peer_addr, router, metrics, web_router).await
    } else {
        if crate::logger::verbose_logging_enabled() {
            eprintln!("[Proxy] Inbound connection from {peer_addr}: unsupported protocol leading byte 0x{first_byte:02X}");
        }
        metrics.inc_errors();
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported protocol leading byte: 0x{:02X}", first_byte),
        ))
    }
}

/// Handles incoming HTTP stream: parses headers, determines routing, and delegates.
pub async fn handle_http_stream(
    stream: TcpStream,
    peer_addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let web_config = crate::web::WebConfig::default_with_port(8080);
    let web_router = crate::web::create_web_router(Arc::clone(&metrics), web_config);
    handle_http_stream_with_web(stream, peer_addr, router, metrics, web_router).await
}

/// Handles incoming HTTP stream with given web router.
pub async fn handle_http_stream_with_web(
    mut client: TcpStream,
    _peer_addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
    web_router: axum::Router,
) -> io::Result<()> {
    let _guard = metrics.connection_guard();
    let local_port = client.local_addr().map(|a| a.port()).unwrap_or(8080);
    let mut header_buf = Vec::with_capacity(2048);
    let mut temp = [0u8; 2048];

    let (header_len, is_connect, target) = loop {
        let n = match timeout(HANDSHAKE_TIMEOUT, client.read(&mut temp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                metrics.inc_errors();
                return Err(e);
            }
            Err(_) => {
                metrics.inc_errors();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Header read timed out",
                ));
            }
        };

        if n == 0 {
            return Ok(());
        }

        header_buf.extend_from_slice(&temp[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 256];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&header_buf) {
            Ok(httparse::Status::Complete(offset)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("").to_string();
                let is_connect = method.eq_ignore_ascii_case("CONNECT");
                let mut target = path.clone();

                // Reject invalid or unsupported HTTP version (only HTTP/1.0 and HTTP/1.1 allowed)
                if req.version != Some(1) && req.version != Some(0) {
                    eprintln!("[Proxy] HTTP unsupported version {:?} from {_peer_addr}", req.version);
                    let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    let _ = client.flush().await;
                    metrics.inc_errors();
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unsupported HTTP version",
                    ));
                }

                if !is_connect {
                    // Extract Host header for forward plain HTTP proxy
                    for h in req.headers.iter() {
                        if h.name.eq_ignore_ascii_case("Host") {
                            if let Ok(v) = std::str::from_utf8(h.value) {
                                target = v.to_string();
                            }
                            break;
                        }
                    }
                }
                if crate::logger::verbose_logging_enabled() {
                    eprintln!("[Proxy] HTTP request from {_peer_addr}: {method} {target} (path: {path}, is_connect={is_connect})");
                }
                if !is_connect && request_is_local(&path, &target, local_port) {
                    let body_slice = if offset < header_buf.len() {
                        &header_buf[offset..]
                    } else {
                        &[]
                    };
                    return crate::web::handle_local_request(
                        client,
                        &method,
                        &path,
                        req.headers,
                        body_slice,
                        web_router,
                    )
                    .await;
                }
                break (offset, is_connect, target);
            }
            Ok(httparse::Status::Partial) => {
                if header_buf.len() >= MAX_HEADER_SIZE {
                    eprintln!("[Proxy] HTTP header size exceeded from {_peer_addr} ({} bytes)", header_buf.len());
                    let _ = client
                        .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    let _ = client.flush().await;
                    // Drain remaining in-flight incoming bytes from client socket to avoid TCP RST on Windows
                    let mut drain_buf = [0u8; 4096];
                    while let Ok(Ok(n)) =
                        timeout(Duration::from_millis(50), client.read(&mut drain_buf)).await
                    {
                        if n == 0 {
                            break;
                        }
                    }
                    metrics.inc_errors();
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Header size exceeded",
                    ));
                }
                continue;
            }
            Err(e) => {
                eprintln!("[Proxy] HTTP parse error from {_peer_addr}: {e}");
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                let _ = client.flush().await;
                metrics.inc_errors();
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
    };

    if is_connect {
        handle_http_connect(client, &target, header_len, &header_buf, router, metrics).await
    } else {
        handle_plain_http(client, &target, &header_buf, router, metrics).await
    }
}

/// Handles RFC 7231 HTTP CONNECT tunneling with zero-copy bidirectional streaming.
pub async fn handle_http_connect(
    mut client: TcpStream,
    target: &str,
    header_len: usize,
    header_buf: &[u8],
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let (host, port) = match parse_connect_target(target) {
        Some((h, p)) => (h, p),
        None => {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            let _ = client.flush().await;
            metrics.inc_errors();
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Malformed CONNECT target (missing port)",
            ));
        }
    };

    if crate::logger::verbose_logging_enabled() {
        let peer = client
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        println!("[Proxy] CONNECT {target} from {peer}");
    }

    let (should_route, reason) = router.should_route(&host);
    if should_route {
        router.observe_domain(&host, reason);
    }
    let allow_local = client
        .peer_addr()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false);
    if let Some(blocked) = blocked_literal(&host, allow_local) {
        if crate::logger::verbose_logging_enabled() {
            eprintln!("[Proxy] CONNECT {target} blocked: upstream is private/local");
        }
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        metrics.inc_errors();
        return Err(blocked);
    }

    // Fast failover connection via DNS candidate cache or direct lookup
    let remote_conn = connect_upstream(&host, port, allow_local).await;
    let (remote, remote_ip, confirm_cache) = match remote_conn {
        Some(conn) => {
            if crate::logger::verbose_logging_enabled() {
                println!(
                    "[Proxy] CONNECT {target} -> connected to upstream {}:{}",
                    conn.ip, port
                );
            }
            (conn.stream, conn.ip, conn.confirm_cache)
        }
        None => {
            if crate::logger::verbose_logging_enabled() {
                eprintln!("[Proxy] CONNECT {target} -> FAILED to connect upstream");
            }
            metrics.inc_errors();
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            let _ = client.flush().await;
            let _ = client.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Remote connection failed",
            ));
        }
    };

    tune_socket(&remote);

    // Send 200 Connection Established handshake response
    if let Err(e) = client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
    {
        metrics.inc_errors();
        return Err(e);
    }
    let _ = client.flush().await;

    // Flush any pipelined data received during header read, applying userspace ClientHello split if needed
    let pipelined = &header_buf[header_len..];
    let split_tls = should_split_tls(should_route)
        && (port == 443 || port == 8443 || (!pipelined.is_empty() && pipelined[0] == 0x16));

    // Zero-copy bidirectional relay with asymmetric buffer sizes
    relay_bidirectional_with_split(
        client,
        remote,
        &host,
        remote_ip,
        confirm_cache,
        UPSTREAM_BUF_SIZE,
        DOWNSTREAM_BUF_SIZE,
        "CONNECT",
        target,
        pipelined,
        split_tls,
        metrics,
    )
    .await
}

/// Handles plain forward HTTP requests.
pub async fn handle_plain_http(
    mut client: TcpStream,
    target: &str,
    initial_request: &[u8],
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let (host, port) = parse_host_port(target, 80);
    if crate::logger::verbose_logging_enabled() {
        let peer = client
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        eprintln!("[Proxy] HTTP-PLAIN {target} from {peer}");
    }
    let (should_route, reason) = router.should_route(&host);
    if should_route {
        router.observe_domain(&host, reason);
    }
    let allow_local = client
        .peer_addr()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false);
    if let Some(blocked) = blocked_literal(&host, allow_local) {
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        metrics.inc_errors();
        return Err(blocked);
    }

    let remote_conn = connect_upstream(&host, port, allow_local).await;
    let (mut remote, remote_ip, confirm_cache) = match remote_conn {
        Some(conn) => (conn.stream, conn.ip, conn.confirm_cache),
        None => {
            metrics.inc_errors();
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            let _ = client.flush().await;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Plain HTTP connect failed",
            ));
        }
    };

    tune_socket(&remote);

    let outbound_request = rewrite_to_origin_form(initial_request);
    if let Err(e) = remote.write_all(&outbound_request).await {
        metrics.inc_errors();
        return Err(e);
    }
    let _ = remote.flush().await;

    relay_bidirectional(
        client,
        remote,
        &host,
        remote_ip,
        confirm_cache,
        UPSTREAM_BUF_SIZE,
        DOWNSTREAM_BUF_SIZE,
        "HTTP-PLAIN",
        target,
        metrics,
    )
    .await
}

#[inline]
pub(crate) fn should_split_tls(should_route: bool) -> bool {
    if !should_route {
        return false;
    }
    match std::env::var("BRIDGE_TLS_SPLIT")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("off" | "0" | "false") => false,
        Some("always" | "1" | "true") => true,
        _ => !is_zapret_service_active_cached(),
    }
}

fn is_zapret_service_active_cached() -> bool {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::Instant;

    static EPOCH: OnceLock<Instant> = OnceLock::new();
    static LAST_CHECK_SEC: AtomicU64 = AtomicU64::new(0);
    static LAST_ACTIVE: AtomicBool = AtomicBool::new(false);

    let start = EPOCH.get_or_init(Instant::now);
    let now_sec = start.elapsed().as_secs().max(1);
    let prev = LAST_CHECK_SEC.load(Ordering::Relaxed);
    if prev != 0 && now_sec.saturating_sub(prev) < 5 {
        return LAST_ACTIVE.load(Ordering::Relaxed);
    }
    let active = crate::menu::query_zapret_service_fast()
        .map(|(running, _)| running)
        .unwrap_or(false);
    LAST_ACTIVE.store(active, Ordering::Relaxed);
    LAST_CHECK_SEC.store(now_sec, Ordering::Relaxed);
    active
}

/// Splits a complete TLS ClientHello record (`0x16 0x03 ...`) into two valid TLS Handshake records.
pub(crate) fn split_tls_client_hello(buf: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if buf.len() < 10 || buf[0] != 0x16 || buf[1] != 0x03 || buf[5] != 0x01 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if rec_len < 12 || 5 + rec_len > buf.len() {
        return None;
    }
    let payload = &buf[5..5 + rec_len];
    let tail = &buf[5 + rec_len..];
    let split_at = 2.min(payload.len() / 2);
    if split_at == 0 || split_at >= payload.len() {
        return None;
    }

    let (p1, p2) = payload.split_at(split_at);
    let mut rec1 = Vec::with_capacity(5 + p1.len());
    rec1.extend_from_slice(&[0x16, buf[1], buf[2]]);
    rec1.extend_from_slice(&(p1.len() as u16).to_be_bytes());
    rec1.extend_from_slice(p1);

    let mut rec2 = Vec::with_capacity(5 + p2.len() + tail.len());
    rec2.extend_from_slice(&[0x16, buf[1], buf[2]]);
    rec2.extend_from_slice(&(p2.len() as u16).to_be_bytes());
    rec2.extend_from_slice(p2);
    rec2.extend_from_slice(tail);

    Some((rec1, rec2))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_bidirectional_with_split(
    mut client: TcpStream,
    mut remote: TcpStream,
    host: &str,
    remote_ip: std::net::IpAddr,
    confirm_cache: bool,
    up_buf: usize,
    down_buf: usize,
    label: &str,
    target: &str,
    pipelined: &[u8],
    split_tls: bool,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let mut pre_sent_up = 0u64;
    if split_tls {
        let mut scratch = [0u8; 4096];
        let first_chunk: &[u8] = if !pipelined.is_empty() {
            pipelined
        } else {
            match timeout(Duration::from_secs(3), client.read(&mut scratch)).await {
                Ok(Ok(n)) if n > 0 => &scratch[..n],
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => {
                    metrics.inc_errors();
                    return Err(e);
                }
                Err(_) => &[],
            }
        };
        if !first_chunk.is_empty() {
            pre_sent_up = first_chunk.len() as u64;
            if let Some((rec1, rec2)) = split_tls_client_hello(first_chunk) {
                if let Err(e) = remote.write_all(&rec1).await {
                    metrics.inc_errors();
                    return Err(e);
                }
                let _ = remote.flush().await;
                if let Err(e) = remote.write_all(&rec2).await {
                    metrics.inc_errors();
                    return Err(e);
                }
                let _ = remote.flush().await;
            } else {
                if let Err(e) = remote.write_all(first_chunk).await {
                    metrics.inc_errors();
                    return Err(e);
                }
                let _ = remote.flush().await;
            }
        }
    } else if !pipelined.is_empty() {
        pre_sent_up = pipelined.len() as u64;
        if let Err(e) = remote.write_all(pipelined).await {
            metrics.inc_errors();
            return Err(e);
        }
        let _ = remote.flush().await;
    }

    match tokio::io::copy_bidirectional_with_sizes(&mut client, &mut remote, up_buf, down_buf)
        .await
    {
        Ok((up, down)) => {
            let total_up = pre_sent_up + up;
            if crate::logger::verbose_logging_enabled() {
                println!("[Proxy] {label} {target} finished: up {total_up} B, down {down} B");
            }
            metrics.add_bytes_up(total_up);
            metrics.add_bytes_down(down);
            if confirm_cache && down > 0 {
                dns::remember_confirmed_ip(host, remote_ip);
            }
            Ok(())
        }
        Err(e) => {
            if pre_sent_up > 0 {
                metrics.add_bytes_up(pre_sent_up);
            }
            if crate::logger::verbose_logging_enabled() {
                eprintln!("[Proxy] {label} {target} relay ended: {e}");
            }
            if e.kind() != io::ErrorKind::ConnectionReset && e.kind() != io::ErrorKind::NotConnected
            {
                metrics.inc_errors();
            }
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_bidirectional(
    client: TcpStream,
    remote: TcpStream,
    host: &str,
    remote_ip: std::net::IpAddr,
    confirm_cache: bool,
    up_buf: usize,
    down_buf: usize,
    label: &str,
    target: &str,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    relay_bidirectional_with_split(
        client,
        remote,
        host,
        remote_ip,
        confirm_cache,
        up_buf,
        down_buf,
        label,
        target,
        &[],
        false,
        metrics,
    )
    .await
}

/// Handles local HTTP diagnostic routes via the embedded Axum web engine.
pub async fn handle_local_route(client: TcpStream, path: &str) -> io::Result<()> {
    let metrics = Arc::new(ProxyMetrics::new());
    let config = crate::web::WebConfig::default();
    let router = crate::web::create_web_router(metrics, config);
    crate::web::handle_local_request(client, "GET", path, &[], &[], router).await
}

async fn connect_upstream(host: &str, port: u16, allow_local: bool) -> Option<dns::Outbound> {
    connect_to_remote(host, port, allow_local).await
}

fn blocked_literal(host: &str, allow_local: bool) -> Option<io::Error> {
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return None;
    };
    if upstream_allowed(ip, allow_local) {
        None
    } else {
        Some(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upstream address is not public",
        ))
    }
}

fn request_is_local(path: &str, host_header: &str, local_port: u16) -> bool {
    if let Some(absolute_host) = absolute_request_host(path) {
        return is_addressed_to_self(&absolute_host, local_port);
    }

    let bare = path
        .split('?')
        .next()
        .unwrap_or(path)
        .split('#')
        .next()
        .unwrap_or(path);

    if is_autoconfig_path(bare) {
        return true;
    }

    if path.starts_with('/') && !path.starts_with("//") {
        let host = if host_header.starts_with('/') {
            ""
        } else {
            host_header.trim()
        };
        if host_is_local_or_lan(host, local_port) {
            return true;
        }
        return false;
    }

    is_addressed_to_self(host_header, local_port)
}

/// True when `host_header` points to this bridge, a local/LAN alias, or a non-public IP.
fn host_is_local_or_lan(host_header: &str, local_port: u16) -> bool {
    if host_header.is_empty() || is_addressed_to_self(host_header, local_port) {
        return true;
    }
    let (host, _) = parse_host_port(host_header, local_port);
    let h = host
        .trim()
        .trim_matches(['[', ']'])
        .split('%')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if h.is_empty()
        || h == "localhost"
        || h.ends_with(".local")
        || h.ends_with(".lan")
        || h.ends_with(".internal")
        || (!h.contains('.') && !h.contains(':'))
    {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return !upstream_allowed(ip, false);
    }
    false
}

fn is_autoconfig_path(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    matches!(
        path,
        "/proxy.pac"
            | "/anticensority.pac"
            | "/pac"
            | "/wpad.dat"
            | "/PROXY.PAC"
            | "/Proxy.Pac"
            | "/supercell.mobileconfig"
            | "/brawlstars.mobileconfig"
            | "/clashroyale.mobileconfig"
            | "/comss.mobileconfig"
            | "/nullsproxy.mobileconfig"
            | "/yandexdns.mobileconfig"
            | "/dns.mobileconfig"
    )
}

fn absolute_request_host(path: &str) -> Option<String> {
    let rest = path
        .split_once("://")
        .map(|(_, rest)| rest)
        .or_else(|| path.strip_prefix("//"))?;
    let host = rest.split('/').next().unwrap_or(rest);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Rewrites an absolute-form request line into origin-form before it reaches a website.
pub fn rewrite_to_origin_form(raw: &[u8]) -> Vec<u8> {
    let line_end = raw
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(raw.len());
    let line = &raw[..line_end];
    let mut parts = line.splitn(3, |b| *b == b' ');
    let Some(method) = parts.next() else {
        return raw.to_vec();
    };
    let Some(target) = parts.next() else {
        return raw.to_vec();
    };
    let version = parts.next().unwrap_or(b"HTTP/1.1");
    if target.starts_with(b"/") {
        return raw.to_vec();
    }
    let path = origin_path(target);
    let mut out = Vec::with_capacity(raw.len());
    out.extend_from_slice(method);
    out.push(b' ');
    out.extend_from_slice(path);
    out.push(b' ');
    out.extend_from_slice(version);
    out.extend_from_slice(&raw[line_end..]);
    out
}

fn origin_path(target: &[u8]) -> &[u8] {
    let rest = if let Some(pos) = target.windows(3).position(|w| w == b"://") {
        &target[pos + 3..]
    } else if let Some(stripped) = target.strip_prefix(b"//") {
        stripped
    } else {
        return b"/";
    };
    rest.iter()
        .position(|b| *b == b'/')
        .map(|idx| &rest[idx..])
        .unwrap_or(b"/")
}

/// Checks whether an HTTP request target is addressed to the local proxy instance itself.
pub fn is_addressed_to_self(target: &str, local_port: u16) -> bool {
    let (host, port) = parse_host_port(target, local_port);
    let h = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    access::is_local_host(&h) && (port == local_port || port == 80)
}

/// Parses target host and port strictly for CONNECT (requires host:port).
pub fn parse_connect_target(target: &str) -> Option<(String, u16)> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Bracketed IPv6 address [2001:db8::1]:443
    if trimmed.starts_with('[') {
        if let Some(end_bracket) = trimmed.find(']') {
            let host = trimmed[1..end_bracket].to_string();
            let remainder = &trimmed[end_bracket + 1..];
            if remainder.starts_with(':') {
                if let Ok(p) = remainder[1..].parse::<u16>() {
                    return Some((host, p));
                }
            }
            return None;
        }
    }

    // Host:port (IPv4 or hostname)
    if let Some(pos) = trimmed.rfind(':') {
        let host = trimmed[..pos].trim();
        let port_str = &trimmed[pos + 1..];
        if let Ok(p) = port_str.parse::<u16>() {
            if !host.is_empty() {
                return Some((host.to_string(), p));
            }
        }
    }

    None
}

/// Parses target host and port with a default port fallback.
pub fn parse_host_port(target: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = parse_connect_target(target) {
        (h, p)
    } else {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            ("127.0.0.1".to_string(), default_port)
        } else {
            (trimmed.to_string(), default_port)
        }
    }
}

/// Configures socket options: TCP_NODELAY, TCP keepalive, and 512 KB receive/send buffers.
pub fn tune_socket(stream: &TcpStream) {
    dns::tune_socket_with_buf(stream, SOCKET_BUF_SIZE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_target() {
        assert_eq!(
            parse_connect_target("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_connect_target("127.0.0.1:8080"),
            Some(("127.0.0.1".to_string(), 8080))
        );
        assert_eq!(
            parse_connect_target("[::1]:443"),
            Some(("::1".to_string(), 443))
        );
        assert_eq!(parse_connect_target("127.0.0.1"), None);
        assert_eq!(parse_connect_target("example.com"), None);
        assert_eq!(parse_connect_target(""), None);
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("example.com:8080", 80),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            parse_host_port("example.com", 80),
            ("example.com".to_string(), 80)
        );
        assert_eq!(parse_host_port("", 443), ("127.0.0.1".to_string(), 443));
    }

    #[test]
    fn test_rewrite_absolute_form() {
        let raw = b"GET http://example.com/watch?v=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let rewritten = rewrite_to_origin_form(raw);
        let text = String::from_utf8(rewritten).unwrap();
        assert!(text.starts_with("GET /watch?v=1 HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com"));
    }

    #[test]
    fn test_origin_form_remote_is_not_local() {
        assert!(!request_is_local("/watch", "youtube.com", 8080));
        assert!(!request_is_local("/", "youtube.com", 8080));
        assert!(!request_is_local("/favicon.ico", "example.com", 8080));
        assert!(!request_is_local("/health", "example.com", 8080));
        assert!(request_is_local("/health", "127.0.0.1:8080", 8080));
        assert!(request_is_local("/", "192.168.0.50:8080", 8080));
        assert!(request_is_local("/proxy.pac", "custom-host.lan:8888", 8080));
        assert!(request_is_local(
            "http://127.0.0.1:8080/proxy.pac",
            "127.0.0.1:8080",
            8080
        ));
        assert!(!request_is_local(
            "http://example.com/a",
            "example.com",
            8080
        ));
        assert!(request_is_local(
            "/yandexdns.mobileconfig",
            "custom-host.lan:8888",
            8080
        ));
        assert!(request_is_local(
            "/dns.mobileconfig",
            "custom-host.lan:8888",
            8080
        ));
        assert!(!request_is_local(
            "http://example.com/yandexdns.mobileconfig",
            "example.com",
            8080
        ));
    }

    #[test]
    fn test_split_tls_client_hello() {
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c];
        hello.extend_from_slice(&[0xAA; 12]);
        let (r1, r2) = split_tls_client_hello(&hello).expect("should split TLS ClientHello");
        assert_eq!(&r1[0..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([r1[3], r1[4]]), 2);
        assert_eq!(&r2[0..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([r2[3], r2[4]]), 14);
        let mut reassembled = Vec::new();
        reassembled.extend_from_slice(&r1[5..]);
        reassembled.extend_from_slice(&r2[5..]);
        assert_eq!(reassembled, &hello[5..]);
        assert!(split_tls_client_hello(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }
}
