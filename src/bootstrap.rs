//! Bootstrap-адреса VOID DHT: vault, встроенные seed, HTTP(S), env, Ed25519-подписи.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libp2p::identity::ed25519;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use reqwest;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tracing::warn;

pub(crate) fn peer_id_from_multiaddr(ma: &Multiaddr) -> Option<PeerId> {
    ma.iter().last().and_then(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
}
const BUILTIN_VOID_BOOTSTRAP: &[&str] = &[];

/// Публичный URL со списком seed (как `void-bootstrap.txt`: одна multiaddr на строку, `#` — комментарий).
/// Замените на свой endpoint один раз на релиз; клиенты подтянут список при старте.
const VOID_BOOTSTRAP_PUBLIC_LIST_URL: &str = "";

/// Узлы для заполнения **отдельного** VOID DHT (не IPFS): сообщения по-прежнему идут напрямую между пирами.
///
/// Источники (все опциональны, объединяются и дедуплицируются):
/// - `void_bootstraps` в `vault.bin` (основное хранилище, обмен с участниками);
/// - `BUILTIN_VOID_BOOTSTRAP` и сборка с `VOID_BUILTIN_BOOTSTRAP=/ip4/.../p2p/...,...` (вшито в exe);
/// - HTTP(S): `VOID_BOOTSTRAP_URL` и/или `VOID_BOOTSTRAP_PUBLIC_LIST_URL`;
/// - переменная `VOID_BOOTSTRAP`: multiaddr через запятую;
/// - `VOID_DISABLE_MDNS` — отключить mDNS в LAN;
/// - `VOID_APPLY_FIREWALL_RULE=1` — разрешить автоматическую настройку файрвола (Windows/macOS).
///
/// Любой может поднять публичный узел VOID — это не «центральный сервер чата», а точка входа в DHT (как у torrent).
fn append_bootstraps_from_lines(out: &mut Vec<Multiaddr>, text: &str, source: &str) {
    for line in text.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<Multiaddr>() {
            Ok(ma) => out.push(ma),
            Err(_) => warn!("{}: пропуск строки: {}", source, t),
        }
    }
}

fn append_bootstraps_from_comma_separated(out: &mut Vec<Multiaddr>, s: &str, source: &str) {
    for part in s.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<Multiaddr>() {
            Ok(ma) => {
                if peer_id_from_multiaddr(&ma).is_some() {
                    out.push(ma);
                } else {
                    warn!("{}: нет /p2p/ в конце, пропуск: {}", source, t);
                }
            }
            Err(_) => warn!("{}: пропуск неверной multiaddr: {}", source, t),
        }
    }
}

/// Однократный импорт из устаревшего `void-bootstrap.txt` в vault при первом запуске.
pub(crate) fn migrate_void_bootstrap_txt() -> Vec<String> {
    let path = Path::new("void-bootstrap.txt");
    if !path.exists() {
        return Vec::new();
    }
    let Ok(txt) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    if let Err(e) = verify_void_bootstrap_file(path, &txt) {
        tracing::warn!("VOID: migrate void-bootstrap.txt: {}", e);
        return Vec::new();
    }
    let mut out = Vec::new();
    for line in txt.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(ma) = t.parse::<Multiaddr>() {
            if peer_id_from_multiaddr(&ma).is_some() {
                let s = ma.to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    }
    out
}

/// Объединяет списки bootstrap multiaddr (строки), оставляя только валидные с `/p2p/`.
pub(crate) fn merge_bootstrap_string_lists(
    existing: &[String],
    incoming: &[String],
) -> Vec<String> {
    let mut out: Vec<String> = existing.to_vec();
    for s in incoming {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(ma) = t.parse::<Multiaddr>() {
            if peer_id_from_multiaddr(&ma).is_some() {
                let normalized = ma.to_string();
                if !out.contains(&normalized) {
                    out.push(normalized);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Макс. размер тела ответа bootstrap-списка (защита от DoS по памяти).
const VOID_BOOTSTRAP_HTTP_MAX_BODY: u64 = 256 * 1024;

/// Опционально: через запятую имена хостов, с которых разрешена загрузка seed по HTTPS/HTTP
/// (`VOID_BOOTSTRAP_URL`, публичный URL из кода). Пусто — как раньше, любой хост.
fn void_bootstrap_url_host_allowed(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let Ok(list) = std::env::var("VOID_BOOTSTRAP_TRUSTED_HOSTS") else {
        return true;
    };
    let t = list.trim();
    if t.is_empty() {
        return true;
    }
    t.split(',').any(|h| h.trim().eq_ignore_ascii_case(host))
}

fn fetch_void_bootstrap_list(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !void_bootstrap_url_host_allowed(parsed.host_str()) {
        warn!(
            "VOID bootstrap URL {}: хост не в списке VOID_BOOTSTRAP_TRUSTED_HOSTS — отказ.",
            url
        );
        return None;
    }

    let client = void_bootstrap_blocking_client(&parsed)?;
    let resp = match client.get(url).send() {
        Ok(r) => r,
        Err(e) => {
            warn!("VOID bootstrap URL {}: {}", url, e);
            return None;
        }
    };
    if !resp.status().is_success() {
        warn!(
            "VOID bootstrap URL {}: HTTP {}",
            url,
            resp.status()
        );
        return None;
    }
    let mut buf = Vec::new();
    match resp
        .take(VOID_BOOTSTRAP_HTTP_MAX_BODY.saturating_add(1))
        .read_to_end(&mut buf)
    {
        Ok(n) if n as u64 <= VOID_BOOTSTRAP_HTTP_MAX_BODY => String::from_utf8(buf).ok(),
        Ok(_) => {
            warn!(
                "VOID bootstrap URL {}: тело ответа больше {} байт — отказ.",
                url, VOID_BOOTSTRAP_HTTP_MAX_BODY
            );
            None
        }
        Err(e) => {
            warn!("VOID bootstrap URL {}: чтение тела: {}", url, e);
            None
        }
    }
}

/// Разбирает ввод «войти в сеть»: полный multiaddr, `IP`, `IP:PORT`. Возвращает multiaddr и (опц.) PeerId.
pub(crate) fn parse_seed_input(raw: &str) -> Option<(Multiaddr, Option<PeerId>)> {
    let (addrs, pid) = parse_seed_dial_addrs(raw)?;
    Some((addrs.into_iter().next()?, pid))
}

/// PeerId из вставки: голый id, multiaddr `/p2p/…`, кавычки, невидимые символы.
pub(crate) fn parse_peer_id_loose(raw: &str) -> Option<PeerId> {
    let mut t = raw.trim().to_string();
    for ch in ['\u{200b}', '\u{200c}', '\u{200d}', '\u{feff}', '\u{00a0}'] {
        t = t.replace(ch, "");
    }
    let t = t
        .trim()
        .trim_matches(|c: char| {
            matches!(c, '"' | '\'' | '`' | '«' | '»' | '“' | '”' | '‹' | '›')
        })
        .trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(pid) = t.parse::<PeerId>() {
        return Some(pid);
    }
    if let Some((_, Some(pid))) = parse_seed_input(t) {
        return Some(pid);
    }
    if let Some(idx) = t.find("12D3KooW").or_else(|| t.find("Qm")) {
        let token: String = t[idx..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if let Ok(pid) = token.parse::<PeerId>() {
            return Some(pid);
        }
    }
    None
}

pub(crate) fn addr_endpoint_key(ma: &Multiaddr) -> String {
    let mut ip = String::new();
    let mut trans = String::new();
    let mut port = String::new();
    for p in ma.iter() {
        match p {
            Protocol::Ip4(a) => ip = a.to_string(),
            Protocol::Ip6(a) => ip = a.to_string(),
            Protocol::Tcp(n) => {
                trans = "tcp".into();
                port = n.to_string();
            }
            Protocol::Udp(n) => {
                trans = "udp".into();
                port = n.to_string();
            }
            _ => {}
        }
    }
    format!("{ip}/{trans}/{port}")
}

pub(crate) fn addr_is_quic_v1(ma: &Multiaddr) -> bool {
    ma.iter().any(|p| matches!(p, Protocol::Udp(_))) && ma.to_string().contains("quic-v1")
}

pub(crate) fn addr_is_tcp(ma: &Multiaddr) -> bool {
    ma.iter().any(|p| matches!(p, Protocol::Tcp(_)))
}

/// Параллельный TCP+QUIC к одному пиру часто убивает уже установленный TCP
/// (`yamux Closed` / QUIC `ApplicationClosed`). Если TCP есть — QUIC не набираем.
pub(crate) fn prefer_tcp_if_available(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    if addrs.iter().any(addr_is_tcp) {
        addrs.into_iter().filter(|a| !addr_is_quic_v1(a)).collect()
    } else {
        addrs
    }
}

/// Как [`parse_seed_input`], но для `IP`/`IP:PORT` — TCP (QUIC через NAT/туннель
/// рвёт сессию; полный `/udp/…/quic-v1` по-прежнему принимается как есть).
pub(crate) fn parse_seed_dial_addrs(raw: &str) -> Option<(Vec<Multiaddr>, Option<PeerId>)> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with('/') {
        let ma: Multiaddr = t.parse().ok()?;
        let pid = peer_id_from_multiaddr(&ma);
        let mut addrs = expand_transport_variants(&ma);
        if addrs.is_empty() {
            addrs.push(ma);
        }
        return Some((prefer_tcp_if_available(addrs), pid));
    }
    let (host, port) = if let Some((h, p)) = t.rsplit_once(':') {
        let port: u16 = p.parse().ok()?;
        (h.to_string(), port)
    } else {
        (t.to_string(), 4001u16)
    };
    let ip: std::net::IpAddr = host.parse().ok()?;
    let tcp_s = match ip {
        std::net::IpAddr::V4(v4) => format!("/ip4/{v4}/tcp/{port}"),
        std::net::IpAddr::V6(v6) => format!("/ip6/{v6}/tcp/{port}"),
    };
    let ma: Multiaddr = tcp_s.parse().ok()?;
    Some((vec![ma], None))
}

/// Если в multiaddr только QUIC — добавить TCP-запас (тот же порт, `/p2p/` сохраняем).
/// Обратное (TCP→QUIC) не делаем: двойной dial рвёт TCP-сессию.
pub(crate) fn expand_transport_variants(ma: &Multiaddr) -> Vec<Multiaddr> {
    let s = ma.to_string();
    let mut out = vec![ma.clone()];
    if !addr_is_quic_v1(ma) {
        return out;
    }
    let pid_suffix = s
        .rfind("/p2p/")
        .map(|i| s[i..].to_string())
        .unwrap_or_default();

    if let Some(rest) = s.strip_prefix("/ip4/") {
        if let Some((ip, after)) = rest.split_once('/') {
            if let Some(udp_port) = after.strip_prefix("udp/") {
                let port = udp_port.split('/').next().unwrap_or("").to_string();
                if !port.is_empty() {
                    let alt = format!("/ip4/{ip}/tcp/{port}{pid_suffix}");
                    if let Ok(ma2) = alt.parse() {
                        if !out.contains(&ma2) {
                            out.push(ma2);
                        }
                    }
                }
            }
        }
    } else if let Some(rest) = s.strip_prefix("/ip6/") {
        if let Some((ip, after)) = rest.split_once('/') {
            if let Some(udp_port) = after.strip_prefix("udp/") {
                let port = udp_port.split('/').next().unwrap_or("").to_string();
                if !port.is_empty() {
                    let alt = format!("/ip6/{ip}/tcp/{port}{pid_suffix}");
                    if let Ok(ma2) = alt.parse() {
                        if !out.contains(&ma2) {
                            out.push(ma2);
                        }
                    }
                }
            }
        }
    }
    prefer_tcp_if_available(out)
}

pub(crate) fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let t = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if t.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn hex_decode_64(s: &str) -> Option<[u8; 64]> {
    let t = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if t.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `VOID_BOOTSTRAP_TLS_LEAF_SHA256` — SHA-256 DER листового сертификата (64 hex), через запятую.
fn parse_void_bootstrap_tls_leaf_pins() -> Option<HashSet<[u8; 32]>> {
    let raw = std::env::var("VOID_BOOTSTRAP_TLS_LEAF_SHA256").ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    let mut set = HashSet::new();
    for part in raw.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        let h = hex_decode_32(t)?;
        set.insert(h);
    }
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

#[derive(Debug)]
struct VoidBootstrapLeafPinVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: HashSet<[u8; 32]>,
}

impl ServerCertVerifier for VoidBootstrapLeafPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if !self.pins.contains(&digest) {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn void_bootstrap_rustls_config_with_pins(
    pins: HashSet<[u8; 32]>,
) -> Result<rustls::ClientConfig, String> {
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let mut root_store = RootCertStore::empty();
    let _ = root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let roots = Arc::new(root_store);
    let inner = WebPkiServerVerifier::builder_with_provider(roots, crypto.clone())
        .build()
        .map_err(|e| format!("tls webpki verifier: {:?}", e))?;
    let verifier = Arc::new(VoidBootstrapLeafPinVerifier { inner, pins });
    Ok(
        rustls::ClientConfig::builder_with_provider(crypto)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("tls versions: {:?}", e))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    )
}

fn void_bootstrap_blocking_client(url: &reqwest::Url) -> Option<reqwest::blocking::Client> {
    let is_https = url.scheme() == "https";
    let pins = parse_void_bootstrap_tls_leaf_pins();
    let use_pins = is_https && pins.as_ref().is_some_and(|p| !p.is_empty());
    let timeout = Duration::from_secs(12);
    if use_pins {
        let p = pins?;
        let tls = match void_bootstrap_rustls_config_with_pins(p) {
            Ok(c) => c,
            Err(e) => {
                warn!(target: "void_net", "VOID bootstrap TLS: {}", e);
                return None;
            }
        };
        return reqwest::blocking::Client::builder()
            .timeout(timeout)
            .use_preconfigured_tls(Arc::new(tls))
            .build()
            .ok();
    }
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .ok()
}

fn void_bootstrap_signing_pubkey_from_env() -> Option<ed25519::PublicKey> {
    let hex = std::env::var("VOID_BOOTSTRAP_SIGNING_PUB_HEX").ok()?;
    let bytes = hex_decode_32(&hex)?;
    ed25519::PublicKey::try_from_bytes(&bytes).ok()
}

/// Если задан `VOID_BOOTSTRAP_SIGNING_PUB_HEX`, проверяет detached-подпись файла `path` + `<stem>.sig`.
fn verify_void_bootstrap_file(path: &Path, text: &str) -> Result<(), String> {
    let Some(pk) = void_bootstrap_signing_pubkey_from_env() else {
        return Ok(());
    };
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("void-bootstrap");
    let sig_path = path.with_file_name(format!("{stem}.sig"));
    let sig = std::fs::read(&sig_path).map_err(|e| {
        format!(
            "VOID bootstrap: нет подписи {} ({})",
            sig_path.display(),
            e
        )
    })?;
    if sig.len() != 64 {
        return Err(format!(
            "VOID bootstrap: {} — ожидается 64 байта Ed25519, получено {}",
            sig_path.display(),
            sig.len()
        ));
    }
    if !pk.verify(text.as_bytes(), &sig) {
        return Err(
            "VOID bootstrap: подпись void-bootstrap не совпала с VOID_BOOTSTRAP_SIGNING_PUB_HEX"
                .into(),
        );
    }
    Ok(())
}

/// `true` — можно добавлять строки; `false` — источник пропущен (например, нет URL-подписи).
fn verify_void_bootstrap_http_body(body: &str, source: &str) -> Result<bool, String> {
    let Some(pk) = void_bootstrap_signing_pubkey_from_env() else {
        return Ok(true);
    };
    let Ok(hex) = std::env::var("VOID_BOOTSTRAP_URL_SIG_HEX") else {
        warn!(
            "VOID bootstrap: пропуск {}: задан VOID_BOOTSTRAP_SIGNING_PUB_HEX, но нет VOID_BOOTSTRAP_URL_SIG_HEX (128 hex)",
            source
        );
        return Ok(false);
    };
    let sig_bytes = hex_decode_64(&hex).ok_or_else(|| {
        "VOID bootstrap: VOID_BOOTSTRAP_URL_SIG_HEX должен быть 128 hex-символов (64 байта)".to_string()
    })?;
    if !pk.verify(body.as_bytes(), &sig_bytes) {
        return Err(format!(
            "VOID bootstrap: подпись тела для {source} не совпала с VOID_BOOTSTRAP_SIGNING_PUB_HEX"
        ));
    }
    Ok(true)
}

/// Собирает полный список bootstrap: сначала из vault, затем встроенные/URL/env.
pub fn void_bootstrap_multiaddrs(vault_bootstraps: &[String]) -> Vec<Multiaddr> {
    let mut out = Vec::new();

    for s in vault_bootstraps {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<Multiaddr>() {
            Ok(ma) => {
                if peer_id_from_multiaddr(&ma).is_some() {
                    out.push(ma);
                } else {
                    warn!("vault bootstrap: нет /p2p/, пропуск: {}", t);
                }
            }
            Err(_) => warn!("vault bootstrap: пропуск: {}", t),
        }
    }

    append_global_bootstraps(&mut out);

    out.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    out.dedup_by(|a, b| a == b);
    out
}

fn append_global_bootstraps(out: &mut Vec<Multiaddr>) {
    append_global_bootstraps_body(out);
}

fn append_global_bootstraps_body(out: &mut Vec<Multiaddr>) {
    for s in BUILTIN_VOID_BOOTSTRAP {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<Multiaddr>() {
            Ok(ma) => out.push(ma),
            Err(_) => warn!("BUILTIN_VOID_BOOTSTRAP: пропуск: {}", t),
        }
    }

    if let Some(s) = option_env!("VOID_BUILTIN_BOOTSTRAP") {
        append_bootstraps_from_comma_separated(out, s, "VOID_BUILTIN_BOOTSTRAP (сборка)");
    }

    let mut urls: Vec<String> = Vec::new();
    if let Ok(u) = std::env::var("VOID_BOOTSTRAP_URL") {
        let t = u.trim().to_string();
        if !t.is_empty() {
            urls.push(t);
        }
    }
    if std::env::var("VOID_SKIP_PUBLIC_BOOTSTRAP_LIST").is_err() {
        let u = VOID_BOOTSTRAP_PUBLIC_LIST_URL.trim();
        if !u.is_empty() {
            urls.push(u.to_string());
        }
    }
    urls.sort();
    urls.dedup();
    for url in urls {
        if let Some(body) = fetch_void_bootstrap_list(&url) {
            let src = format!("GET {}", url);
            match verify_void_bootstrap_http_body(&body, &src) {
                Ok(true) => append_bootstraps_from_lines(out, &body, &src),
                Ok(false) => {}
                Err(e) => warn!("{}", e),
            }
        }
    }

    if let Ok(s) = std::env::var("VOID_BOOTSTRAP") {
        append_bootstraps_from_comma_separated(out, &s, "VOID_BOOTSTRAP");
    }
}

#[cfg(test)]
mod tests {
    use super::parse_peer_id_loose;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;

    #[test]
    fn parse_peer_id_loose_accepts_paste_noise() {
        let pid = PeerId::from(Keypair::generate_ed25519().public());
        let raw = pid.to_string();
        assert_eq!(parse_peer_id_loose(&raw), Some(pid));
        assert_eq!(parse_peer_id_loose(&format!("  {raw}  ")), Some(pid));
        assert_eq!(parse_peer_id_loose(&format!("\"{raw}\"")), Some(pid));
        assert_eq!(parse_peer_id_loose(&format!("/p2p/{raw}")), Some(pid));
        assert_eq!(
            parse_peer_id_loose(&format!("Peer ID:\n{raw}")),
            Some(pid)
        );
        assert!(parse_peer_id_loose("1.2.3.4:4001").is_none());
    }
}
