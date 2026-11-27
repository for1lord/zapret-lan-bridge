//! Self-Update Checker & Detached Installer for Zapret TV & Mobile Bridge.
//!
//! Queries GitHub Releases over native SChannel TLS (`api.github.com`), compares semantic
//! versions, downloads and verifies release archives, cleanly replaces legacy Windows Task
//! Scheduler entries, preserves user lists/secrets, and restarts services gracefully.

use serde::Serialize;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio_native_tls::native_tls;

pub const REPO_OWNER: &str = "for1lord";
pub const REPO_NAME: &str = "zapret-lan-bridge";
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

const UPDATE_CACHE_TTL: Duration = Duration::from_secs(6 * 3600);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    pub version: String,
    pub html_url: String,
    pub asset_name: String,
    pub download_url: String,
    pub asset_size: u64,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum UpdateCheckResult {
    UpToDate {
        current: String,
        latest: String,
    },
    UpdateAvailable {
        current: String,
        release: ReleaseInfo,
    },
    Error(String),
}

struct CachedCheck {
    checked_at: Instant,
    result: UpdateCheckResult,
}

static UPDATE_CACHE: Mutex<Option<CachedCheck>> = Mutex::new(None);

/// Parses versions like `"v1.20"`, `"1.19.0"`, or `"v1.20.3-rc1"` into `(major, minor, patch)`.
pub fn parse_version_tuple(raw: &str) -> Option<(u32, u32, u32)> {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    let core = trimmed.split(['-', '+']).next().unwrap_or("").trim();
    if core.is_empty() {
        return None;
    }
    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let major = parts[0].parse::<u32>().ok()?;
    let minor = if parts.len() >= 2 {
        parts[1].parse::<u32>().ok()?
    } else {
        0
    };
    let patch = if parts.len() >= 3 {
        parts[2].parse::<u32>().ok()?
    } else {
        0
    };
    Some((major, minor, patch))
}

/// Returns `true` strictly when `candidate` is newer than `current`.
pub fn is_newer_version(current: &str, candidate: &str) -> bool {
    match (parse_version_tuple(current), parse_version_tuple(candidate)) {
        (Some(cur), Some(cand)) => cand > cur,
        _ => false,
    }
}

/// Decodes a raw HTTP/1.1 response into `(status_code, body_bytes)`.
pub fn decode_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response (no header terminator)".to_string())?;

    let header_str = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "Invalid UTF-8 in HTTP headers".to_string())?;
    let mut lines = header_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "Missing HTTP status line".to_string())?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("Invalid HTTP status line: {status_line}"))?;

    let is_chunked = lines.any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });

    let body_raw = &raw[header_end + 4..];
    if !is_chunked {
        return Ok((status_code, body_raw.to_vec()));
    }

    let mut decoded = Vec::new();
    let mut pos = 0usize;
    while pos < body_raw.len() {
        let Some(rel_crlf) = body_raw[pos..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = std::str::from_utf8(&body_raw[pos..pos + rel_crlf])
            .map_err(|_| "Invalid chunk size encoding".to_string())?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16)
            .map_err(|_| format!("Invalid chunk hex length: {hex_part}"))?;
        pos += rel_crlf + 2;
        if chunk_len == 0 {
            break;
        }
        if pos + chunk_len > body_raw.len() {
            return Err("Truncated chunked HTTP response".to_string());
        }
        decoded.extend_from_slice(&body_raw[pos..pos + chunk_len]);
        pos += chunk_len;
        if pos + 2 <= body_raw.len() && &body_raw[pos..pos + 2] == b"\r\n" {
            pos += 2;
        }
    }

    Ok((status_code, decoded))
}

/// Parses GitHub `/releases/latest` JSON payload into [`ReleaseInfo`].
pub fn parse_release_json(json_str: &str) -> Result<ReleaseInfo, String> {
    let val: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid GitHub JSON: {e}"))?;

    let tag_name = val["tag_name"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Release tag_name missing".to_string())?
        .to_string();

    let version = tag_name.trim_start_matches(['v', 'V']).to_string();
    let html_url = val["html_url"].as_str().unwrap_or("").trim().to_string();
    let notes = val["body"].as_str().unwrap_or("").trim().to_string();

    let mut chosen_asset: Option<(String, String, u64)> = None;
    if let Some(assets) = val["assets"].as_array() {
        for asset in assets {
            let name = asset["name"].as_str().unwrap_or("").trim();
            let url = asset["browser_download_url"].as_str().unwrap_or("").trim();
            let size = asset["size"].as_u64().unwrap_or(0);
            if !name.to_ascii_lowercase().ends_with(".zip") || url.is_empty() {
                continue;
            }
            let preferred = name.to_ascii_lowercase().starts_with("zapret-lan-bridge");
            if preferred || chosen_asset.is_none() {
                chosen_asset = Some((name.to_string(), url.to_string(), size));
                if preferred {
                    break;
                }
            }
        }
    }

    let (asset_name, download_url, asset_size) = chosen_asset
        .ok_or_else(|| format!("ZIP archive asset not found in release {tag_name}"))?;

    Ok(ReleaseInfo {
        tag_name,
        version,
        html_url,
        asset_name,
        download_url,
        asset_size,
        notes,
    })
}

/// Performs a fast HTTPS GET to `api.github.com` using Windows native TLS.
pub fn fetch_latest_release() -> Result<ReleaseInfo, String> {
    let host = "api.github.com";
    let addrs: Vec<_> = (host, 443)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
        .collect();
    let addr = addrs
        .into_iter()
        .find(|a| a.is_ipv4())
        .or_else(|| (host, 443).to_socket_addrs().ok()?.next())
        .ok_or_else(|| "No address found for api.github.com".to_string())?;

    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(4))
        .map_err(|e| format!("GitHub connection error: {e}"))?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(4)));

    let connector =
        native_tls::TlsConnector::new().map_err(|e| format!("TLS init error: {e}"))?;
    let mut tls = connector
        .connect(host, tcp)
        .map_err(|e| format!("TLS handshake error: {e}"))?;

    let req = format!(
        "GET /repos/{REPO_OWNER}/{REPO_NAME}/releases/latest HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: ZapretTVBridge/{CURRENT_VERSION}\r\n\
         Accept: application/vnd.github+json\r\n\
         Connection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes())
        .map_err(|e| format!("HTTP send error: {e}"))?;
    tls.flush().map_err(|e| format!("HTTP flush error: {e}"))?;

    let mut raw = Vec::with_capacity(16 * 1024);
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 2 * 1024 * 1024 {
                    return Err("GitHub API response too large".to_string());
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if raw.is_empty() {
                    return Err(format!("GitHub API timeout: {e}"));
                }
                break;
            }
            Err(e) => {
                if raw.is_empty() {
                    return Err(format!("GitHub API read error: {e}"));
                }
                break;
            }
        }
    }

    let (status, body) = decode_http_response(&raw)?;
    if status != 200 {
        return Err(format!("GitHub API returned HTTP {status}"));
    }

    let body_str = std::str::from_utf8(&body)
        .map_err(|_| "GitHub API body is not valid UTF-8".to_string())?;
    parse_release_json(body_str)
}

/// Checks for a newer release on GitHub.
pub fn check_for_updates() -> UpdateCheckResult {
    match fetch_latest_release() {
        Ok(release) => {
            if is_newer_version(CURRENT_VERSION, &release.version) {
                UpdateCheckResult::UpdateAvailable {
                    current: CURRENT_VERSION.to_string(),
                    release,
                }
            } else {
                UpdateCheckResult::UpToDate {
                    current: CURRENT_VERSION.to_string(),
                    latest: release.version,
                }
            }
        }
        Err(err) => UpdateCheckResult::Error(err),
    }
}

/// Returns a cached update check result (refreshes every 6 hours unless `force` is true).
pub fn check_for_updates_cached(force: bool) -> UpdateCheckResult {
    if !force {
        if let Ok(guard) = UPDATE_CACHE.lock() {
            if let Some(cached) = guard.as_ref() {
                if cached.checked_at.elapsed() < UPDATE_CACHE_TTL {
                    return cached.result.clone();
                }
            }
        }
    }

    let result = check_for_updates();
    if !matches!(result, UpdateCheckResult::Error(_)) {
        if let Ok(mut guard) = UPDATE_CACHE.lock() {
            *guard = Some(CachedCheck {
                checked_at: Instant::now(),
                result: result.clone(),
            });
        }
    }
    result
}

/// Non-blocking cache probe used by the Web Dashboard without stalling page renders.
pub fn peek_cached_update() -> Option<ReleaseInfo> {
    if let Ok(guard) = UPDATE_CACHE.lock() {
        if let Some(cached) = guard.as_ref() {
            if cached.checked_at.elapsed() < UPDATE_CACHE_TTL {
                if let UpdateCheckResult::UpdateAvailable { release, .. } = &cached.result {
                    return Some(release.clone());
                }
            }
        }
    }
    None
}

/// Spawns a background update check once per cache TTL so the Web Dashboard can show new releases.
pub fn trigger_background_update_check() {
    let needs_check = UPDATE_CACHE
        .lock()
        .ok()
        .map(|guard| {
            guard
                .as_ref()
                .map(|c| c.checked_at.elapsed() >= UPDATE_CACHE_TTL)
                .unwrap_or(true)
        })
        .unwrap_or(false);
    if !needs_check {
        return;
    }
    std::thread::spawn(|| {
        let _ = check_for_updates_cached(false);
    });
}

fn verify_zip_file(path: &Path) -> Result<u64, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("Archive missing: {e}"))?;
    let size = meta.len();
    if size < 100 * 1024 {
        return Err(format!("Downloaded archive too small ({size} bytes)"));
    }
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("Cannot read archive: {e}"))?;
    let mut sig = [0u8; 2];
    file.read_exact(&mut sig)
        .map_err(|e| format!("Archive header read failed: {e}"))?;
    if &sig != b"PK" {
        return Err("Downloaded file is not a valid ZIP archive".to_string());
    }
    Ok(size)
}

/// Downloads the release ZIP using Windows built-in `curl.exe` with PowerShell WebClient fallback.
pub fn download_release_zip(url: &str, dest: &Path) -> Result<u64, String> {
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(dest);

    let dest_str = dest.to_string_lossy().to_string();
    let curl_ok = Command::new("curl.exe")
        .args([
            "-fSL",
            "--connect-timeout",
            "15",
            "--max-time",
            "240",
            "-o",
            &dest_str,
            url,
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if curl_ok {
        if let Ok(sz) = verify_zip_file(dest) {
            return Ok(sz);
        }
    }

    let _ = std::fs::remove_file(dest);
    let ps_cmd = format!(
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
         (New-Object System.Net.WebClient).DownloadFile('{}', '{}')",
        url.replace('\'', "''"),
        dest_str.replace('\'', "''")
    );
    let ps_ok = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_cmd])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if ps_ok {
        return verify_zip_file(dest);
    }

    Err("Failed to download release archive via curl.exe and PowerShell".to_string())
}

fn extract_zip_to_dir(zip_path: &Path, stage_dir: &Path) -> Result<PathBuf, String> {
    if stage_dir.exists() {
        let _ = std::fs::remove_dir_all(stage_dir);
    }
    std::fs::create_dir_all(stage_dir)
        .map_err(|e| format!("Cannot create staging directory: {e}"))?;

    let ps_cmd = format!(
        "Add-Type -AssemblyName System.IO.Compression.FileSystem; \
         [System.IO.Compression.ZipFile]::ExtractToDirectory('{}', '{}')",
        zip_path.to_string_lossy().replace('\'', "''"),
        stage_dir.to_string_lossy().replace('\'', "''")
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_cmd])
        .output()
        .map_err(|e| format!("Failed to invoke PowerShell ZIP extractor: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ZIP extraction failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // Handle either flat zip root or single nested folder
    if stage_dir.join("ZapretTVBridge.exe").exists()
        || stage_dir.join("bin").join("ZapretTVBridge.exe").exists()
    {
        return Ok(stage_dir.to_path_buf());
    }

    if let Ok(entries) = std::fs::read_dir(stage_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir()
                && (p.join("ZapretTVBridge.exe").exists()
                    || p.join("bin").join("ZapretTVBridge.exe").exists())
            {
                return Ok(p);
            }
        }
    }

    Err("Extracted archive does not contain ZapretTVBridge.exe".to_string())
}

/// Merges custom non-comment lines from `existing_file` into `staged_file` before copying.
fn merge_user_list_file(existing_file: &Path, staged_file: &Path) {
    let Ok(existing_text) = std::fs::read_to_string(existing_file) else {
        return;
    };
    let Ok(staged_text) = std::fs::read_to_string(staged_file) else {
        return;
    };

    let mut seen: HashSet<String> = staged_text
        .lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let mut extras = Vec::new();
    for line in existing_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if seen.insert(key) {
            extras.push(trimmed.to_string());
        }
    }

    if extras.is_empty() {
        return;
    }

    let mut merged = staged_text;
    if !merged.ends_with('\n') {
        merged.push('\n');
    }
    for extra in extras {
        merged.push_str(&extra);
        merged.push('\n');
    }
    let _ = std::fs::write(staged_file, merged);
}

fn preserve_user_state_in_stage(base_dir: &Path, stage_root: &Path) {
    let secret = base_dir.join("tg_secret.txt");
    if secret.is_file() {
        let _ = std::fs::copy(&secret, stage_root.join("tg_secret.txt"));
    }

    for fname in [
        "list-general-user.txt",
        "list-exclude-user.txt",
        "ipset-exclude-user.txt",
    ] {
        let cur = base_dir.join("lists").join(fname);
        let staged = stage_root.join("lists").join(fname);
        if cur.is_file() && staged.is_file() {
            merge_user_list_file(&cur, &staged);
        }
    }
}

/// Builds the detached Windows `.cmd` updater script that cleanly stops services,
/// removes old Task Scheduler tasks, replaces program files, re-registers tasks, and restarts.
pub fn build_update_batch_script(
    stage_root: &Path,
    target_dir: &Path,
    zip_path: &Path,
    stage_base: &Path,
    had_startup: bool,
    strategy: Option<&str>,
    was_running: bool,
    version_label: &str,
) -> String {
    let stage_s = stage_root.to_string_lossy().trim_end_matches('\\').to_string();
    let target_s = target_dir.to_string_lossy().trim_end_matches('\\').to_string();
    let zip_s = zip_path.to_string_lossy().to_string();
    let stage_base_s = stage_base.to_string_lossy().to_string();

    let startup_line = if had_startup {
        format!(
            "echo [*] Регистрация новой задачи в Планировщике заданий Windows...\r\n\
             \"%NEW_EXE%\" --startup-enable >nul 2>&1\r\n"
        )
    } else {
        String::new()
    };

    let strategy_line = if let Some(strat) = strategy.filter(|s| !s.trim().is_empty()) {
        format!(
            "echo [*] Обновление пути службы Zapret [{}]...\r\n\
             \"%NEW_EXE%\" --install-strategy \"{}\" >nul 2>&1\r\n",
            strat,
            strat.replace('"', "")
        )
    } else {
        String::new()
    };

    let start_line = if was_running {
        "echo [*] Запуск обновлённого шлюза...\r\n\
         \"%NEW_EXE%\" --start >nul 2>&1\r\n"
            .to_string()
    } else {
        String::new()
    };

    format!(
        "@echo off\r\n\
         chcp 65001 >nul 2>&1\r\n\
         title ОБНОВЛЕНИЕ ZAPRET TV ^& MOBILE BRIDGE {version_label}\r\n\
         echo.\r\n\
         echo ==================================================\r\n\
         echo   УСТАНОВКА ОБНОВЛЕНИЯ {version_label}\r\n\
         echo ==================================================\r\n\
         echo [*] Ожидание завершения текущего процесса...\r\n\
         timeout /t 2 /nobreak >nul\r\n\
         echo [*] Корректная остановка службы Zapret и шлюза...\r\n\
         sc stop zapret >nul 2>&1\r\n\
         set /a _w=0\r\n\
         :wait_zapret\r\n\
         sc query zapret 2>nul | findstr /i \"STOPPED\" >nul && goto :zapret_stopped\r\n\
         set /a _w+=1\r\n\
         if %_w% GEQ 12 goto :zapret_stopped\r\n\
         timeout /t 1 /nobreak >nul\r\n\
         goto :wait_zapret\r\n\
         :zapret_stopped\r\n\
         tasklist /FI \"IMAGENAME eq winws.exe\" 2>nul | findstr /i \"winws.exe\" >nul && taskkill /F /IM winws.exe >nul 2>&1\r\n\
         sc stop WinDivert >nul 2>&1\r\n\
         sc delete WinDivert >nul 2>&1\r\n\
         sc stop WinDivert14 >nul 2>&1\r\n\
         sc delete WinDivert14 >nul 2>&1\r\n\
         taskkill /F /IM ZapretTVBridge.exe >nul 2>&1\r\n\
         taskkill /F /IM tgwsproxy.exe >nul 2>&1\r\n\
         timeout /t 1 /nobreak >nul\r\n\
         echo [*] Удаление старых задач Планировщика заданий и автозагрузки...\r\n\
         schtasks /delete /tn \"Zapret_TV_Bridge\" /f >nul 2>&1\r\n\
         schtasks /delete /tn \"ZapretTVBridge\" /f >nul 2>&1\r\n\
         powershell -NoProfile -Command \"Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -match 'Zapret.*Bridge|ZapretTVBridge' }} | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue\" >nul 2>&1\r\n\
         reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"ZapretTVBridge\" /f >nul 2>&1\r\n\
         reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"ZapretTVBridge\" /f >nul 2>&1\r\n\
         del /f /q \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Zapret_TV_Bridge.lnk\" >nul 2>&1\r\n\
         del /f /q \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Zapret_TV_Bridge.vbs\" >nul 2>&1\r\n\
         del /f /q \"%LOCALAPPDATA%\\ZapretTVBridge\\bridge_autostart.vbs\" >nul 2>&1\r\n\
         echo [*] Копирование файлов новой версии в {target_s}...\r\n\
         xcopy \"{stage_s}\\*\" \"{target_s}\\\" /E /Y /I /Q >nul 2>&1\r\n\
         set \"NEW_EXE={target_s}\\bin\\ZapretTVBridge.exe\"\r\n\
         if not exist \"%NEW_EXE%\" set \"NEW_EXE={target_s}\\ZapretTVBridge.exe\"\r\n\
         {strategy_line}\
         {startup_line}\
         {start_line}\
         del /f /q \"{zip_s}\" >nul 2>&1\r\n\
         rmdir /s /q \"{stage_base_s}\" >nul 2>&1\r\n\
         echo.\r\n\
         echo [+] Программа успешно обновлена до версии {version_label}!\r\n\
         timeout /t 3 >nul\r\n\
         del /f /q \"%~f0\" >nul 2>&1\r\n"
    )
}

/// Checks if a matching Zapret Bridge scheduled task exists even if Startup folder/registry checks differ.
fn has_bridge_scheduled_task() -> bool {
    let direct = Command::new("schtasks")
        .args(["/query", "/tn", "Zapret_TV_Bridge"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if direct {
        return true;
    }
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "if (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'Zapret.*Bridge|ZapretTVBridge' }) { exit 0 } else { exit 1 }",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Performs interactive or CLI self-update to `release`, replacing legacy scheduled tasks cleanly.
pub fn perform_self_update(base_dir: &Path, release: &ReleaseInfo) -> Result<(), String> {
    let temp_dir = std::env::temp_dir();
    let zip_path = temp_dir.join(format!("ztb_update_{}.zip", release.version));
    let stage_base = temp_dir.join(format!("ztb_stage_{}", release.version));

    println!(
        "[*] Скачивание {} ({:.2} МБ)...",
        release.asset_name,
        release.asset_size as f64 / (1024.0 * 1024.0)
    );
    let bytes = download_release_zip(&release.download_url, &zip_path)?;
    println!(
        "[+] Архив загружен ({:.2} МБ). Распаковка...",
        bytes as f64 / (1024.0 * 1024.0)
    );

    let stage_root = extract_zip_to_dir(&zip_path, &stage_base)?;
    preserve_user_state_in_stage(base_dir, &stage_root);

    let had_startup = crate::menu::is_startup_enabled() || has_bridge_scheduled_task();
    let (zapret_running, active_strategy) = crate::menu::get_zapret_service_status();
    let (bridge_running, _) = crate::menu::is_bridge_running(base_dir);
    let strategy_to_apply = if !active_strategy.is_empty() {
        Some(active_strategy)
    } else if zapret_running {
        Some("general (ALT12)".to_string())
    } else {
        None
    };

    let cmd_content = build_update_batch_script(
        &stage_root,
        base_dir,
        &zip_path,
        &stage_base,
        had_startup,
        strategy_to_apply.as_deref(),
        bridge_running || zapret_running,
        &release.tag_name,
    );

    let script_path = temp_dir.join("ztb_apply_update.cmd");
    std::fs::write(&script_path, cmd_content.as_bytes())
        .map_err(|e| format!("Failed to write updater script: {e}"))?;

    println!("[*] Запуск установщика обновления и замена задач Планировщика...");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_CONSOLE: u32 = 0x00000010;
        Command::new("cmd.exe")
            .args(["/c", &script_path.to_string_lossy()])
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .map_err(|e| format!("Failed to launch updater script: {e}"))?;
    }
    #[cfg(not(windows))]
    {
        let _ = script_path;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing_and_comparison() {
        assert_eq!(parse_version_tuple("v1.19"), Some((1, 19, 0)));
        assert_eq!(parse_version_tuple("1.20.0"), Some((1, 20, 0)));
        assert_eq!(parse_version_tuple("V2.0.1-beta"), Some((2, 0, 1)));
        assert_eq!(parse_version_tuple("invalid"), None);

        assert!(is_newer_version("1.19.0", "v1.20"));
        assert!(is_newer_version("1.19.0", "1.19.1"));
        assert!(is_newer_version("1.19.0", "v2.0"));
        assert!(!is_newer_version("1.19.0", "v1.19"));
        assert!(!is_newer_version("1.20.0", "v1.19"));
    }

    #[test]
    fn test_parse_release_json_selects_zip_asset() {
        let json = r#"{
            "tag_name": "v1.20",
            "html_url": "https://github.com/for1lord/zapret-lan-bridge/releases/tag/v1.20",
            "body": "Release notes",
            "assets": [
                {
                    "name": "checksums.txt",
                    "browser_download_url": "https://example.com/checksums.txt",
                    "size": 128
                },
                {
                    "name": "zapret-lan-bridge-v1.20.zip",
                    "browser_download_url": "https://github.com/for1lord/zapret-lan-bridge/releases/download/v1.20/zapret-lan-bridge-v1.20.zip",
                    "size": 57000000
                }
            ]
        }"#;
        let info = parse_release_json(json).expect("valid json");
        assert_eq!(info.tag_name, "v1.20");
        assert_eq!(info.version, "1.20");
        assert_eq!(info.asset_name, "zapret-lan-bridge-v1.20.zip");
        assert_eq!(info.asset_size, 57000000);
    }

    #[test]
    fn test_decode_http_response_plain_and_chunked() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (st, body) = decode_http_response(plain).unwrap();
        assert_eq!(st, 200);
        assert_eq!(body, b"hello");

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (st2, body2) = decode_http_response(chunked).unwrap();
        assert_eq!(st2, 200);
        assert_eq!(body2, b"hello world");
    }

    #[test]
    fn test_build_update_batch_script_replaces_tasks_and_stops_gracefully() {
        let script = build_update_batch_script(
            Path::new(r"C:\Temp\stage"),
            Path::new(r"C:\zapret-tv-bridge"),
            Path::new(r"C:\Temp\update.zip"),
            Path::new(r"C:\Temp\stage_base"),
            true,
            Some("general (ALT12)"),
            true,
            "v1.20",
        );
        assert!(script.contains("sc stop zapret"));
        assert!(script.contains("sc stop WinDivert"));
        assert!(script.contains("sc delete WinDivert"));
        assert!(script.contains("schtasks /delete /tn \"Zapret_TV_Bridge\" /f"));
        assert!(script.contains("Unregister-ScheduledTask"));
        assert!(script.contains("--install-strategy \"general (ALT12)\""));
        assert!(script.contains("--startup-enable"));
        assert!(script.contains("--start"));
        // Graceful sc stop must appear before fallback winws taskkill
        assert!(script.find("sc stop zapret").unwrap() < script.find("taskkill /F /IM winws.exe").unwrap());
    }

    #[test]
    fn test_merge_user_list_file_preserves_custom_entries() {
        let dir = std::env::temp_dir().join(format!("ztb_merge_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let existing = dir.join("old.txt");
        let staged = dir.join("new.txt");
        std::fs::write(&existing, "# comment\nshared.example\ncustom-user.example\n").unwrap();
        std::fs::write(&staged, "shared.example\nnew-default.example\n").unwrap();

        merge_user_list_file(&existing, &staged);
        let merged = std::fs::read_to_string(&staged).unwrap();
        assert!(merged.contains("shared.example"));
        assert!(merged.contains("new-default.example"));
        assert!(merged.contains("custom-user.example"));
        assert_eq!(merged.matches("shared.example").count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
