#!/usr/bin/env python3
"""One-off helper to split main.rs into modules."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"


def sl(lines, a, b):
    return "".join(lines[a - 1 : b])


def read_body(name):
    return (SRC / f"_{name}_body.txt").read_text(encoding="utf-8")


def write_mod(name, header, body, subs=None):
    text = body
    if subs:
        for old, new in subs:
            text = text.replace(old, new)
    (SRC / f"{name}.rs").write_text(header + text, encoding="utf-8")
    print(f"wrote {name}.rs ({len(header) + len(text)} bytes)")


def main():
    main_path = SRC / "main.rs"
    lines = main_path.read_text(encoding="utf-8").splitlines(keepends=True)

    (SRC / "_bootstrap_body.txt").write_text(
        sl(lines, 45, 50) + sl(lines, 125, 533), encoding="utf-8"
    )
    (SRC / "_vault_body.txt").write_text(sl(lines, 566, 913), encoding="utf-8")
    (SRC / "_protocol_body.txt").write_text(sl(lines, 915, 1096), encoding="utf-8")
    (SRC / "_network_body.txt").write_text(
        sl(lines, 63, 121) + sl(lines, 536, 564) + sl(lines, 1098, 1308) + sl(lines, 1920, 3759),
        encoding="utf-8",
    )
    (SRC / "_app_body.txt").write_text(sl(lines, 1310, 1918), encoding="utf-8")
    (SRC / "_main_tail.txt").write_text(sl(lines, 3761, 3956), encoding="utf-8")

    BOOTSTRAP_HEADER = """//! Bootstrap-адреса VOID DHT: встроенные seed, HTTP(S), файл, env, Ed25519-подписи.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libp2p::identity::ed25519;
use libp2p::Multiaddr;
use reqwest;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tracing::warn;

"""

    bootstrap_subs = [
        ("fn peer_id_from_multiaddr", "pub(crate) fn peer_id_from_multiaddr"),
        ("fn void_bootstrap_multiaddrs", "pub fn void_bootstrap_multiaddrs"),
        ("fn parse_seed_input", "pub(crate) fn parse_seed_input"),
    ]
    write_mod("bootstrap", BOOTSTRAP_HEADER, read_body("bootstrap"), bootstrap_subs)

    VAULT_HEADER = """//! Зашифрованный vault (`vault.bin`) и обёртка мастер-ключа (`void.key`).

use std::error::Error;
use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use libp2p::Multiaddr;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::crypto;
use crate::network::{NetworkEvent, UICommand};

"""

    vault_subs = [
        ("struct AddressBookEntry", "pub(crate) struct AddressBookEntry"),
        ("struct Storage;", "pub(crate) struct Storage;"),
        ("fn detect_vault_unlock_kind", "pub(crate) fn detect_vault_unlock_kind"),
    ]
    write_mod("vault", VAULT_HEADER, read_body("vault"), vault_subs)

    PROTOCOL_HEADER = """//! Протокол чата `/void/chat/1.0.0`: Hello, E2EE-пакеты, лимиты JSON.

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::crypto;

"""

    protocol_subs = [
        ("struct ChatMessage", "pub(crate) struct ChatMessage"),
        ("fn parse_decrypted_chat_json", "pub(crate) fn parse_decrypted_chat_json"),
        ("enum V1Packet", "pub(crate) enum V1Packet"),
        ("fn build_v1_hello", "pub(crate) fn build_v1_hello"),
        # FileTransferProgress already pub(crate) in source
        ("pub(crate) pub(crate) struct FileTransferProgress", "pub(crate) struct FileTransferProgress"),
    ]
    write_mod("protocol", PROTOCOL_HEADER, read_body("protocol"), protocol_subs)

    NETWORK_HEADER = """//! libp2p swarm, сетевой цикл и события UI ↔ сеть.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::{
    autonat, dcutr, identify, kad, mdns, noise, ping, relay,
    swarm::{
        behaviour::toggle::Toggle,
        dial_opts::DialOpts,
        NetworkBehaviour, SwarmEvent,
    },
    tcp, upnp, yamux, Multiaddr, PeerId, StreamProtocol,
};
use rand::RngCore;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::bootstrap::{parse_seed_input, peer_id_from_multiaddr, void_bootstrap_multiaddrs};
use crate::crypto;
use crate::file_transfer;
use crate::protocol::{
    build_v1_hello, parse_decrypted_chat_json, ChatMessage, FileTransferProgress, V1Packet,
};

"""

    network_subs = [
        ("enum NetworkEvent", "pub(crate) enum NetworkEvent"),
        ("enum UICommand", "pub(crate) enum UICommand"),
        ("async fn run_chat_network", "pub async fn run_chat_network"),
        ("fn env_flag_true", "pub fn env_flag_true"),
    ]
    write_mod("network", NETWORK_HEADER, read_body("network"), network_subs)

    APP_HEADER = """//! Состояние приложения, vault unlock и логика повторной отправки.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use eframe::egui;
use libp2p::Multiaddr;
use libp2p::PeerId;
use rand::RngCore;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto;
use crate::file_transfer;
use crate::network::{run_chat_network, NetworkEvent, UICommand};
use crate::protocol::ChatMessage;
use crate::ui::{setup_custom_style, truncate_text, Toast, ToastKind, TOAST_TTL_LONG, TOAST_TTL_SHORT};
use crate::vault::{
    AddressBookEntry, DeferredNetworkSpawn, Storage, VaultUnlockKind, VaultUnlockState,
};

"""

    app_subs = [
        ("struct PendingSend", "pub(crate) struct PendingSend"),
        ("const RESEND_GRACE", "pub(crate) const RESEND_GRACE"),
        ("struct App", "pub(crate) struct App"),
    ]
    write_mod("app", APP_HEADER, read_body("app"), app_subs)

    MAIN_HEADER = """mod crypto;
mod file_transfer;
mod ui;

mod app;
mod bootstrap;
mod network;
mod protocol;
mod vault;

pub(crate) use app::{App, PendingSend, RESEND_GRACE, RESEND_DELAY, MAX_ATTEMPTS};
pub(crate) use bootstrap::parse_seed_input;
pub(crate) use protocol::ChatMessage;
pub(crate) use network::{FileTransferProgress, NetworkEvent, UICommand};

use std::collections::HashMap;
use std::error::Error;

use eframe::egui;
use libp2p::PeerId;
use rand::RngCore;
use tokio::sync::mpsc;
use tracing::info;

use app::App;
use bootstrap::void_bootstrap_multiaddrs;
use network::env_flag_true;
use vault::{detect_vault_unlock_kind, DeferredNetworkSpawn, VaultUnlockState};

"""

    main_tail = (SRC / "_main_tail.txt").read_text(encoding="utf-8")
    (SRC / "main.rs").write_text(MAIN_HEADER + main_tail, encoding="utf-8")
    print("wrote main.rs")


if __name__ == "__main__":
    main()
