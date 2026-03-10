mod crypto;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use chrono;
use eframe::egui;
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, identify, kad, mdns, noise, ping, relay,
    swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmEvent},
    tcp, upnp, yamux, Multiaddr, PeerId,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Serialize, Deserialize)]
struct StorageData {
    nickname: String,
    keypair_bytes: Vec<u8>,
    static_secret_bytes: [u8; 32],
}

struct Storage;
impl Storage {
    const FILE: &'static str = "vault.bin";
    const KEY_FILE: &'static str = "void.key";

    fn get_master_key() -> [u8; 32] {
        if let Ok(k) = std::fs::read(Self::KEY_FILE) {
            if k.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&k);
                return key;
            }
        }
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let _ = std::fs::write(Self::KEY_FILE, &key);
        key
    }

    fn save(
        nickname: &str,
        keypair: Option<&libp2p::identity::Keypair>,
        static_secret: Option<&crypto::StaticSecret>,
    ) -> Result<(), Box<dyn Error>> {
        let current = Self::load().ok();

        let keypair_bytes = if let Some(kp) = keypair {
            kp.to_protobuf_encoding()?
        } else {
            current
                .as_ref()
                .map(|c| c.keypair_bytes.clone())
                .unwrap_or_default()
        };

        let static_secret_bytes = if let Some(ss) = static_secret {
            ss.to_bytes()
        } else {
            current
                .as_ref()
                .map(|c| c.static_secret_bytes)
                .unwrap_or([0u8; 32])
        };

        let data = StorageData {
            nickname: nickname.to_string(),
            keypair_bytes,
            static_secret_bytes,
        };
        let plaintext = serde_json::to_vec(&data)?;

        let master_key = Self::get_master_key();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("Encryption error: {}", e))?;

        let mut final_data = nonce_bytes.to_vec();
        final_data.extend(ciphertext);
        std::fs::write(Self::FILE, final_data)?;
        Ok(())
    }

    fn load() -> Result<StorageData, Box<dyn Error>> {
        if !std::path::Path::new(Self::FILE).exists() {
            return Err("Vault file not found".into());
        }
        let data = std::fs::read(Self::FILE)?;
        if data.len() < 12 {
            return Err("Invalid vault".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let master_key = Self::get_master_key();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption error: {}", e))?;

        let storage: StorageData = serde_json::from_slice(&plaintext)?;
        Ok(storage)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    sender_id: String,
    sender_name: String,
    recipient_id: Option<String>, // Some(peer_id) for private, None for global
    text: String,
    timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum V1Packet {
    Hello {
        public_key: [u8; 32],
    },
    Encrypted {
        header: crypto::MessageHeader,
        ciphertext: Vec<u8>,
    },
    Plain(ChatMessage),
}

enum NetworkEvent {
    NewListenAddr(Multiaddr),
    MdnsDiscovered(PeerId, Multiaddr),
    MdnsExpired(PeerId),
    Connected(PeerId),
    Disconnected(PeerId),
    ChatMessage(ChatMessage),
    Status(String),
}

enum UICommand {
    Dial(String),
    DialPeer(PeerId, Vec<Multiaddr>),
    SearchPeer(PeerId),
    SendMessage {
        sender_name: String,
        text: String,
        recipient: Option<PeerId>,
        is_retry: bool,
    },
}

#[derive(NetworkBehaviour)]
struct ChatBehaviour {
    request_response: libp2p::request_response::json::Behaviour<V1Packet, V1Packet>,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    relay: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    autonat: autonat::Behaviour,
    upnp: upnp::tokio::Behaviour,
}

struct App {
    local_peer_id: PeerId,
    local_nickname: String,
    listen_addrs: Vec<String>,
    connected_peers: usize,
    dial_address: String,
    chat_input: String,
    // Storage: "GLOBAL" or PeerId string
    messages: HashMap<String, Vec<ChatMessage>>,
    known_peers: HashMap<PeerId, String>,
    selected_chat: String, // "GLOBAL" or PeerId string
    status_log: Vec<String>,
    show_logs: bool,
    show_sidebar: bool,
    command_tx: mpsc::Sender<UICommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    _sessions: HashMap<libp2p::PeerId, crypto::SecureSession>,
    _local_static: crypto::StaticSecret,
}

impl App {
    fn new(
        cc: &eframe::CreationContext<'_>,
        local_peer_id: PeerId,
        local_nickname: String,
        local_static: crypto::StaticSecret,
        command_tx: mpsc::Sender<UICommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
    ) -> Self {
        setup_custom_style(&cc.egui_ctx);
        let mut messages = HashMap::new();
        messages.insert("GLOBAL".to_string(), Vec::new());

        Self {
            local_peer_id,
            local_nickname,
            listen_addrs: Vec::new(),
            connected_peers: 0,
            dial_address: String::new(),
            chat_input: String::new(),
            messages,
            known_peers: HashMap::new(),
            selected_chat: "GLOBAL".to_string(),
            status_log: Vec::new(),
            show_logs: false,
            show_sidebar: true,
            command_tx,
            event_rx,
            _sessions: HashMap::new(),
            _local_static: local_static,
        }
    }

    fn add_status(&mut self, msg: String) {
        let ts = chrono::Local::now().format("%H:%M").to_string();
        self.status_log.push(format!("[{}] {}", ts, msg));
        if self.status_log.len() > 30 {
            self.status_log.remove(0);
        }
    }

    fn ui_sidebar(&mut self, ui: &mut egui::Ui, accent_color: egui::Color32) {
        let shadow_light = egui::Color32::from_rgba_premultiplied(45, 45, 48, 255);
        let shadow_dark = egui::Color32::from_rgba_premultiplied(12, 12, 14, 255);
        let bg_color = egui::Color32::from_rgb(26, 26, 28);

        ui.vertical(|ui| {
            // --- SECTION: IDENTITY ---
            egui::Frame::none()
                .fill(bg_color)
                .rounding(15.0)
                .shadow(egui::Shadow {
                    offset: egui::vec2(-3.0, -3.0),
                    blur: 8.0,
                    spread: 0.0,
                    color: shadow_light,
                })
                .show(ui, |ui| {
                    egui::Frame::none()
                        .fill(bg_color)
                        .rounding(15.0)
                        .shadow(egui::Shadow {
                            offset: egui::vec2(3.0, 3.0),
                            blur: 6.0,
                            spread: 0.0,
                            color: shadow_dark,
                        })
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            egui::CollapsingHeader::new(
                                egui::RichText::new("👤 МОЙ ПРОФИЛЬ")
                                    .strong()
                                    .color(accent_color),
                            )
                            .default_open(false)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("Имя:");
                                    if ui
                                        .add(
                                            egui::TextEdit::singleline(&mut self.local_nickname)
                                                .desired_width(120.0),
                                        )
                                        .changed()
                                    {
                                        let _ = Storage::save(&self.local_nickname, None, None);
                                    }
                                });
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new(&self.local_peer_id.to_string()[..16])
                                            .size(12.0)
                                            .monospace()
                                            .weak(),
                                    );
                                    if ui
                                        .button("📋")
                                        .on_hover_text("Копировать Peer ID")
                                        .clicked()
                                    {
                                        ui.output_mut(|o| {
                                            o.copied_text = self.local_peer_id.to_string()
                                        });
                                    }
                                });
                            });
                        });
                });

            ui.add_space(15.0);

            // --- SECTION: NETWORK ---
            egui::Frame::none()
                .fill(bg_color)
                .rounding(15.0)
                .shadow(egui::Shadow {
                    offset: egui::vec2(-3.0, -3.0),
                    blur: 8.0,
                    spread: 0.0,
                    color: shadow_light,
                })
                .show(ui, |ui| {
                    egui::Frame::none()
                        .fill(bg_color)
                        .rounding(15.0)
                        .shadow(egui::Shadow {
                            offset: egui::vec2(3.0, 3.0),
                            blur: 6.0,
                            spread: 0.0,
                            color: shadow_dark,
                        })
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                egui::RichText::new("СЕТЬ")
                                    .size(14.0)
                                    .strong()
                                    .color(accent_color),
                            );
                            ui.label(format!("🌐 Подключено: {}", self.connected_peers));

                            if !self.listen_addrs.is_empty() {
                                ui.add_space(5.0);
                                egui::CollapsingHeader::new(
                                    egui::RichText::new("📍 МОИ АДРЕСА").size(12.0).weak(),
                                )
                                .show(ui, |ui| {
                                    for addr in &self.listen_addrs {
                                        ui.horizontal(|ui| {
                                            let short_addr = if addr.len() > 20 {
                                                format!("{}...", &addr[..17])
                                            } else {
                                                addr.clone()
                                            };
                                            ui.label(
                                                egui::RichText::new(short_addr).small().weak(),
                                            );
                                            if ui.button("📋").clicked() {
                                                ui.output_mut(|o| o.copied_text = addr.clone());
                                            }
                                        });
                                    }
                                });
                            }
                        });
                });

            ui.add_space(15.0);

            // --- SECTION: CHATS ---
            egui::Frame::none()
                .fill(bg_color)
                .rounding(15.0)
                .shadow(egui::Shadow {
                    offset: egui::vec2(-3.0, -3.0),
                    blur: 8.0,
                    spread: 0.0,
                    color: shadow_light,
                })
                .show(ui, |ui| {
                    egui::Frame::none()
                        .fill(bg_color)
                        .rounding(15.0)
                        .shadow(egui::Shadow {
                            offset: egui::vec2(3.0, 3.0),
                            blur: 6.0,
                            spread: 0.0,
                            color: shadow_dark,
                        })
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                egui::RichText::new("ЧАТЫ")
                                    .size(14.0)
                                    .strong()
                                    .color(accent_color),
                            );

                            let is_global = self.selected_chat == "GLOBAL";
                            if ui
                                .selectable_label(is_global, "🌍 Общий поток (все)")
                                .clicked()
                            {
                                self.selected_chat = "GLOBAL".to_string();
                            }

                            ui.add_space(10.0);
                            ui.label(egui::RichText::new("ЛИЧНЫЕ").size(12.0).weak());

                            let mut peers_to_remove = Vec::new();
                            let mut known_peers_list: Vec<_> = self.known_peers.iter().collect();
                            known_peers_list.sort_by(|a, b| a.1.cmp(b.1));

                            for (peer_id, name) in known_peers_list {
                                let peer_str = peer_id.to_string();
                                let is_selected = self.selected_chat == peer_str;

                                ui.horizontal(|ui| {
                                    if ui
                                        .selectable_label(is_selected, format!("👤 {}", name))
                                        .clicked()
                                    {
                                        self.selected_chat = peer_str.clone();
                                        self.messages.entry(peer_str.clone()).or_insert(Vec::new());
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .button("🗑")
                                                .on_hover_text("Удалить диалог")
                                                .clicked()
                                            {
                                                peers_to_remove.push(*peer_id);
                                            }
                                        },
                                    );
                                });
                            }

                            for pid in peers_to_remove {
                                let p_str = pid.to_string();
                                self.known_peers.remove(&pid);
                                self.messages.remove(&p_str);
                                if self.selected_chat == p_str {
                                    self.selected_chat = "GLOBAL".to_string();
                                }
                            }
                        });
                });

            ui.add_space(15.0);

            // --- SECTION: DIAL ---
            egui::Frame::none()
                .fill(bg_color)
                .rounding(15.0)
                .shadow(egui::Shadow {
                    offset: egui::vec2(-3.0, -3.0),
                    blur: 8.0,
                    spread: 0.0,
                    color: shadow_light,
                })
                .show(ui, |ui| {
                    egui::Frame::none()
                        .fill(bg_color)
                        .rounding(15.0)
                        .shadow(egui::Shadow {
                            offset: egui::vec2(3.0, 3.0),
                            blur: 6.0,
                            spread: 0.0,
                            color: shadow_dark,
                        })
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                egui::RichText::new("ПОДКЛЮЧЕНИЕ")
                                    .size(14.0)
                                    .strong()
                                    .color(accent_color),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut self.dial_address)
                                    .hint_text("Peer ID или Multiaddr")
                                    .desired_width(ui.available_width()),
                            );
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                if ui
                                    .add(egui::Button::new(
                                        egui::RichText::new("ПОДКЛЮЧИТЬ").size(14.0),
                                    ))
                                    .clicked()
                                    && !self.dial_address.is_empty()
                                {
                                    let input = self.dial_address.trim().to_string();
                                    if let Ok(peer_id) = input.parse::<PeerId>() {
                                        let _ = self
                                            .command_tx
                                            .try_send(UICommand::SearchPeer(peer_id));
                                    } else {
                                        let _ = self.command_tx.try_send(UICommand::Dial(input));
                                    }
                                    self.dial_address.clear();
                                }

                                if ui.button("📋 СВОЙ ID").clicked() {
                                    ui.output_mut(|o| {
                                        o.copied_text = self.local_peer_id.to_string()
                                    });
                                }
                            });
                        });
                });

            ui.add_space(20.0);
            if ui
                .add(egui::Button::new(
                    egui::RichText::new("📋 СИСТЕМНАЯ КОНСОЛЬ").size(14.0),
                ))
                .clicked()
            {
                self.show_logs = true;
            }
        });
    }
}

fn setup_custom_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    let bg_color = egui::Color32::from_rgb(26, 26, 28); // #1A1A1C
    let text_color = egui::Color32::from_rgb(209, 209, 209); // #D1D1D1
    let accent_color = egui::Color32::from_rgb(0, 195, 255); // Cyan accent

    visuals.panel_fill = bg_color;
    visuals.window_fill = bg_color;
    visuals.widgets.noninteractive.bg_fill = bg_color;
    visuals.widgets.inactive.bg_fill = bg_color;
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(34, 34, 37);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(18, 18, 20);

    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, text_color);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, text_color);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.5, accent_color);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.5, accent_color);

    visuals.selection.bg_fill = egui::Color32::from_rgb(60, 60, 70);
    visuals.window_rounding = 40.0.into();
    visuals.widgets.noninteractive.rounding = 15.0.into();
    visuals.widgets.inactive.rounding = 15.0.into();

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(15.0, 15.0);
    style.spacing.window_margin = egui::Margin::same(30.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    ctx.set_style(style);
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.known_peers.remove(&self.local_peer_id);
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::NewListenAddr(addr) => {
                    let full = format!("{}/p2p/{}", addr, self.local_peer_id);
                    if !self.listen_addrs.contains(&full) {
                        self.add_status(format!("🚀 Listen: {}", addr));
                        self.listen_addrs.push(full);
                    }
                }
                NetworkEvent::MdnsDiscovered(peer, addr) => {
                    self.add_status(format!(
                        "🔍 Найдён пир: {} на {}",
                        &peer.to_string()[..8],
                        addr
                    ));
                    // Добавляем в список известных, если это не мы сами
                    if peer != self.local_peer_id {
                        self.known_peers
                            .entry(peer)
                            .or_insert_with(|| format!("Peer_{}", &peer.to_string()[..8]));
                    }
                }
                NetworkEvent::MdnsExpired(peer) => {
                    self.add_status(format!("⏳ Оффлайн (MDNS): {}", &peer.to_string()[..8]));
                }
                NetworkEvent::Connected(peer) => {
                    self.connected_peers += 1;
                    self.add_status(format!("✅ Подключено: {}...", &peer.to_string()[..8]));
                }
                NetworkEvent::Disconnected(peer) => {
                    self.connected_peers = self.connected_peers.saturating_sub(1);
                    self.add_status(format!("❌ Отключено: {}...", &peer.to_string()[..8]));
                }
                NetworkEvent::ChatMessage(msg) => {
                    // Update known peers for display names
                    if let Ok(peer_id) = msg.sender_id.parse::<PeerId>() {
                        if peer_id != self.local_peer_id {
                            self.known_peers.insert(peer_id, msg.sender_name.clone());
                        }
                    }

                    // Route message
                    let bucket = if let Some(ref target) = msg.recipient_id {
                        if target == &self.local_peer_id.to_string() {
                            Some(msg.sender_id.clone())
                        } else if msg.sender_id == self.local_peer_id.to_string() {
                            Some(target.clone())
                        } else {
                            None
                        }
                    } else {
                        Some("GLOBAL".to_string())
                    };

                    if let Some(b) = bucket {
                        self.messages.entry(b).or_default().push(msg);
                    }
                }
                NetworkEvent::Status(msg) => {
                    self.add_status(msg);
                }
            }
        }

        let bg_color = egui::Color32::from_rgb(26, 26, 28);
        let text_color = egui::Color32::from_rgb(209, 209, 209);
        let shadow_light = egui::Color32::from_rgba_premultiplied(45, 45, 48, 255);
        let shadow_dark = egui::Color32::from_rgba_premultiplied(12, 12, 14, 255);
        let accent_color = egui::Color32::from_rgb(0, 195, 255);

        // --- Log Window ---
        if self.show_logs {
            egui::Window::new("СИСТЕМНАЯ КОНСОЛЬ")
                .open(&mut self.show_logs)
                .resizable(true)
                .default_size([400.0, 300.0])
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new("ЛОКАЛЬНЫЕ АДРЕСА")
                            .strong()
                            .color(accent_color),
                    );
                    for addr in &self.listen_addrs {
                        ui.label(egui::RichText::new(addr).small().monospace());
                    }
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new("ЛОГ СОБЫТИЙ")
                            .strong()
                            .color(accent_color),
                    );
                    egui::ScrollArea::vertical()
                        .id_salt("log_scroll")
                        .show(ui, |ui| {
                            for log in &self.status_log {
                                ui.label(egui::RichText::new(log).size(11.0).weak());
                            }
                        });
                });
        }

        // --- Top Bar (Header) ---
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::none().fill(bg_color).inner_margin(20.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(
                            egui::RichText::new(if self.show_sidebar { "⬅" } else { "☰" })
                                .size(22.0),
                        ))
                        .clicked()
                    {
                        self.show_sidebar = !self.show_sidebar;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new("VOID P2P DARK")
                                .size(32.0)
                                .color(accent_color)
                                .strong(),
                        );
                    });
                });
            });

        // --- Sidebar (Collapsible) ---
        if self.show_sidebar {
            egui::SidePanel::left("sidebar")
                .frame(egui::Frame::none().fill(bg_color).inner_margin(20.0))
                .resizable(true)
                .default_width(280.0)
                .width_range(200.0..=400.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.ui_sidebar(ui, accent_color);
                    });
                });
        }

        // --- Main Chat Area ---
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(bg_color).inner_margin(20.0))
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    // Chat bubbles container
                    egui::Frame::none()
                        .fill(bg_color)
                        .rounding(30.0)
                        .shadow(egui::Shadow {
                            offset: egui::vec2(-6.0, -6.0),
                            blur: 16.0,
                            spread: 0.0,
                            color: shadow_light,
                        })
                        .show(ui, |ui| {
                            egui::Frame::none()
                                .fill(bg_color)
                                .rounding(30.0)
                                .shadow(egui::Shadow {
                                    offset: egui::vec2(6.0, 6.0),
                                    blur: 12.0,
                                    spread: 0.0,
                                    color: shadow_dark,
                                })
                                .inner_margin(30.0)
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.set_height(ui.available_height() - 100.0);

                                    egui::ScrollArea::vertical()
                                        .id_salt("chat_stream")
                                        .stick_to_bottom(true)
                                        .auto_shrink([false, false])
                                        .show(ui, |ui| {
                                            ui.set_width(ui.available_width());
                                            let current_messages = self
                                                .messages
                                                .get(&self.selected_chat)
                                                .cloned()
                                                .unwrap_or_default();
                                            for msg in &current_messages {
                                                let is_me =
                                                    msg.sender_id == self.local_peer_id.to_string();
                                                ui.add_space(20.0);
                                                ui.horizontal(|ui| {
                                                    if is_me {
                                                        ui.add_space(ui.available_width() * 0.1);
                                                    }

                                                    egui::Frame::none()
                                                        .fill(if is_me {
                                                            egui::Color32::from_rgb(45, 45, 50)
                                                        } else {
                                                            egui::Color32::from_rgb(33, 33, 36)
                                                        })
                                                        .rounding(22.0)
                                                        .inner_margin(18.0)
                                                        .show(ui, |ui| {
                                                            ui.vertical(|ui| {
                                                                if !is_me {
                                                                    ui.label(
                                                                        egui::RichText::new(
                                                                            &msg.sender_name,
                                                                        )
                                                                        .size(14.0)
                                                                        .color(accent_color)
                                                                        .strong(),
                                                                    );
                                                                }
                                                                ui.label(
                                                                    egui::RichText::new(&msg.text)
                                                                        .size(20.0)
                                                                        .color(text_color),
                                                                );
                                                                ui.with_layout(
                                                                    egui::Layout::right_to_left(
                                                                        egui::Align::BOTTOM,
                                                                    ),
                                                                    |ui| {
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                &msg.timestamp,
                                                                            )
                                                                            .size(11.0)
                                                                            .weak(),
                                                                        );
                                                                    },
                                                                );
                                                            });
                                                        });

                                                    if !is_me {
                                                        ui.add_space(ui.available_width() * 0.1);
                                                    }
                                                });
                                            }
                                        });
                                });
                        });

                    ui.add_space(20.0);

                    // --- Input Bar ---
                    egui::Frame::none()
                        .fill(bg_color)
                        .rounding(30.0)
                        .shadow(egui::Shadow {
                            offset: egui::vec2(-6.0, -6.0),
                            blur: 16.0,
                            spread: 0.0,
                            color: shadow_light,
                        })
                        .show(ui, |ui| {
                            egui::Frame::none()
                                .fill(bg_color)
                                .rounding(30.0)
                                .shadow(egui::Shadow {
                                    offset: egui::vec2(6.0, 6.0),
                                    blur: 12.0,
                                    spread: 0.0,
                                    color: shadow_dark,
                                })
                                .inner_margin(18.0)
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        let res = ui.add(
                                            egui::TextEdit::singleline(&mut self.chat_input)
                                                .hint_text("Сообщение...")
                                                .desired_width(ui.available_width() - 110.0)
                                                .font(egui::TextStyle::Body),
                                        );

                                        if (ui
                                            .add_sized(
                                                [100.0, 40.0],
                                                egui::Button::new(
                                                    egui::RichText::new("ОТПРАВИТЬ").size(16.0),
                                                ),
                                            )
                                            .clicked()
                                            || (res.lost_focus()
                                                && ctx.input(|i| i.key_pressed(egui::Key::Enter))))
                                            && !self.chat_input.is_empty()
                                        {
                                            let recipient = if self.selected_chat == "GLOBAL" {
                                                None
                                            } else {
                                                self.selected_chat.parse::<PeerId>().ok()
                                            };
                                            let _ =
                                                self.command_tx.try_send(UICommand::SendMessage {
                                                    sender_name: self.local_nickname.clone(),
                                                    text: self.chat_input.clone(),
                                                    recipient,
                                                    is_retry: false,
                                                });
                                            self.chat_input.clear();
                                        }
                                    });
                                });
                        });
                });
            });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Включаем логи для отладки
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // === Автоматически добавляем правило файрвола ===
    #[allow(unused_variables)]
    let exe_path = std::env::current_exe().unwrap_or_default();
    #[allow(unused_variables)]
    let exe = exe_path.display().to_string();

    #[cfg(target_os = "windows")]
    {
        // Проверяем, запущены ли мы уже от Администратора
        let is_admin = std::process::Command::new("net")
            .args(["session"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if is_admin {
            println!("Настраиваю файрвол Windows (Admin Mode)...");
            let _ = std::process::Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", "name=VOID P2P"])
                .output();
            let tcp_r = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=VOID P2P",
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    "localport=50001",
                    "profile=any",
                    "enable=yes",
                ])
                .output();
            let udp_r = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=VOID P2P",
                    "dir=in",
                    "action=allow",
                    "protocol=UDP",
                    "localport=50001",
                    "profile=any",
                    "edge=yes",
                    "enable=yes",
                ])
                .output();
            match (tcp_r, udp_r) {
                (Ok(t), Ok(u)) if t.status.success() && u.status.success() => {
                    println!("✅ Файрвол настроен (TCP + UDP разрешены)")
                }
                _ => println!("⚠ Не удалось настроить файрвол"),
            }
        } else {
            // Пишем команды в временный .bat файл, запускаем от админа через UAC
            let bat = format!(
                "@echo off\r\n\
                 netsh advfirewall firewall delete rule name=\"VOID P2P\"\r\n\
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=TCP localport=50001 profile=any enable=yes\r\n\
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=UDP localport=50001 profile=any edge=yes enable=yes\r\n"
            );
            let bat_path = std::env::temp_dir().join("void_p2p_firewall.bat");
            if std::fs::write(&bat_path, bat).is_ok() {
                println!("Настраиваю файрвол (запрос UAC)...");
                // ShellExecute runas — самый надёжный способ UAC-элевации
                let result = std::process::Command::new("powershell")
                    .args([
                        "-NoProfile",
                        "-Command",
                        &format!(
                            "Start-Process -FilePath '{}' -Verb RunAs -Wait",
                            bat_path.display()
                        ),
                    ])
                    .status();
                match result {
                    Ok(s) if s.success() => println!("✅ Файрвол настроен"),
                    _ => {
                        println!("⚠ UAC отклонён. Запустите вручную от Админастратора:");
                        println!("  {}", bat_path.display());
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        println!("Настраиваю файрвол macOS...");
        let _ = std::process::Command::new("sudo")
            .args([
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                "--add",
                &exe,
            ])
            .output();
        let _ = std::process::Command::new("sudo")
            .args([
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                "--unblockapp",
                &exe,
            ])
            .output();
        println!("✅ Файрвол macOS настроен");
    }

    let (local_key, local_nickname, static_secret) = if let Ok(storage) = Storage::load() {
        let key = libp2p::identity::Keypair::from_protobuf_encoding(&storage.keypair_bytes)
            .expect("Failed to decode saved keypair");
        let static_secret = crypto::StaticSecret::from(storage.static_secret_bytes);
        (key, storage.nickname, static_secret)
    } else {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let static_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
        let nickname = format!("User_{}", &PeerId::from(key.public()).to_string()[..4]);
        let _ = Storage::save(&nickname, Some(&key), Some(&static_secret));
        (key, nickname, static_secret)
    };
    let local_peer_id = PeerId::from(local_key.public());

    println!("=== VOID P2P Chat ===");
    println!("Ваш Peer ID: {}", local_peer_id);
    println!("Ваш никнейм: {}", local_nickname);

    let (event_tx, event_rx) = mpsc::channel(256);
    let (command_tx, mut command_rx) = mpsc::channel(256);

    let event_tx_clone = event_tx.clone();
    let command_tx_for_mdns = command_tx.clone(); // для delayed dial из mDNS

    let static_secret_net = static_secret.clone();
    tokio::spawn(async move {
        let event_tx = event_tx_clone;
        let command_tx_for_mdns = command_tx_for_mdns;
        let local_static = static_secret_net;
        let mut sessions: HashMap<PeerId, crypto::SecureSession> = HashMap::new();
        let my_public_key = crypto::PublicKey::from(&local_static);

        // Swarm: TCP + noise + yamux + Relay Client
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_quic()
            .with_dns()
            .unwrap()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|key, relay_client| {
                let local_peer_id = key.public().to_peer_id();

                // Kademlia: хранилище в памяти
                let kad_store = kad::store::MemoryStore::new(local_peer_id);
                let kad_config = kad::Config::default();
                let mut kad = kad::Behaviour::with_config(local_peer_id, kad_store, kad_config);
                // Включаем серверный режим на самом поведении
                kad.set_mode(Some(libp2p::kad::Mode::Server));

                // Добавляем бутстрап-ноды IPFS/libp2p
                let bootstrap = [
                    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNQP97ZByia9h9YFmbSNoBeC7pQYQSppN1C8S2B75SXC6u",
                    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcSTwsrmMvFUXS7uK9z1V64p99C8ndn4y2K8w8f3z",
                    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMo9UFwv9V9QdfyLc4Dn91S2AnkkL8Vat4DTHiV4f",
                    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi7U4S6n32FRV9RmrHnoz6L8N9ndBnd6u",
                    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvLcZunBNqv9U7Z8hSAt79S99JcyG316w8nL62m9",
                    // Дополнительные надежные ноды
                    "/ip4/147.75.101.139/tcp/4001/p2p/QmQCU2EcSTwsrmMvFUXS7uK9z1V64p99C8ndn4y2K8w8f3z",
                    "/ip4/147.75.83.83/tcp/4001/p2p/QmbLHAnMo9UFwv9V9QdfyLc4Dn91S2AnkkL8Vat4DTHiV4f",
                    "/ip4/147.75.109.213/tcp/4001/p2p/QmNnoo2uR3GuwhvBqyM4tTDp6NoS7wB9G9o9wE5pS9Y6mY",
                    "/ip4/147.75.77.187/tcp/4001/p2p/QmNQP97ZByia9h9YFmbSNoBeC7pQYQSppN1C8S2B75SXC6u",
                ];
                for addr in bootstrap {
                    if let Ok(ma) = addr.parse::<Multiaddr>() {
                        if let Some(peer_id) = ma.clone().pop().and_then(|p| {
                            if let libp2p::multiaddr::Protocol::P2p(peer_id) = p { Some(peer_id) } else { None }
                        }) {
                             kad.add_address(&peer_id, ma);
                        }
                    }
                }
                let _ = kad.bootstrap();

                let rr_config = libp2p::request_response::Config::default();
                let rr_protocol = libp2p::StreamProtocol::new("/void/chat/1.0.0");
                let rr_behaviour = libp2p::request_response::json::Behaviour::<V1Packet, V1Packet>::new(
                    [(rr_protocol, libp2p::request_response::ProtocolSupport::Full)],
                    rr_config,
                );

                Ok(ChatBehaviour {
                    request_response: rr_behaviour,
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                        .unwrap(),
                    ping: ping::Behaviour::default(),
                    identify: identify::Behaviour::new(identify::Config::new(
                        "/void/id/1.0.0".into(),
                        key.public(),
                    )),
                    kad,
                    relay: relay_client,
                    dcutr: dcutr::Behaviour::new(local_peer_id),
                    autonat: autonat::Behaviour::new(local_peer_id, Default::default()),
                    upnp: upnp::tokio::Behaviour::default(),
                })
            })
            .unwrap()
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(Duration::from_secs(60))
                    .with_per_connection_event_buffer_size(256)
            })
            .build();

        // Слушаем TCP. Сначала пробуем 50001 (согласно правилам файрвола).
        let tcp_addr: Multiaddr = "/ip4/0.0.0.0/tcp/50001".parse().unwrap();

        if let Err(e) = swarm.listen_on(tcp_addr.clone()) {
            println!("⚠️ TCP порт 50001 занят ({:?}). Срочно ЗАКРОЙТЕ старые процессы или проверьте настройки.", e);
            let _ = event_tx
                .send(NetworkEvent::Status(
                    "⚠️ ПОРТ 50001 ЗАНЯТ! Закройте старые копии программы.".into(),
                ))
                .await;
            swarm
                .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
                .unwrap();
        }

        // Слушаем QUIC.
        let quic_addr: Multiaddr = "/ip4/0.0.0.0/udp/50001/quic-v1".parse().unwrap();
        match swarm.listen_on(quic_addr.clone()) {
            Ok(_) => println!("🚀 QUIC слушаю на 50001"),
            Err(e) => {
                println!(
                    "⚠️ QUIC ошибка на 50001 ({:?}). Пробую случайный порт...",
                    e
                );
                let _ = swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap());
            }
        }

        // Слушаем через Relay для работы за NAT
        let _ = swarm.listen_on("/p2p-circuit".parse().unwrap());

        let _ = event_tx
            .send(NetworkEvent::Status(
                "🚀 Запущен. Ищу пиров через mDNS...".into(),
            ))
            .await;

        let mut kad_bootstrap_timer = tokio::time::interval(Duration::from_secs(300)); // 5 минут
        let mut peer_addrs: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        let mut pending_dials: HashSet<PeerId> = HashSet::new();
        let mut dial_backoff: HashMap<PeerId, Instant> = HashMap::new();
        let mut local_listen_addrs: HashSet<Multiaddr> = HashSet::new();

        loop {
            tokio::select! {
                cmd = command_rx.recv() => {
                    if let Some(c) = cmd {
                        match c {
                            UICommand::Dial(addr_str) => {
                                match addr_str.parse::<Multiaddr>() {
                                    Ok(addr) => {
                                        let _ = event_tx.send(NetworkEvent::Status(
                                            format!("📞 Подключаюсь к {}...", &addr_str[..addr_str.len().min(50)])
                                        )).await;
                                        match swarm.dial(addr) {
                                            Ok(_) => {
                                                let _ = event_tx.send(NetworkEvent::Status("⏳ Dial отправлен...".into())).await;
                                            }
                                            Err(e) => {
                                                let _ = event_tx.send(NetworkEvent::Status(
                                                    format!("❌ Ошибка подключения: {}", e)
                                                )).await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let _ = event_tx.send(NetworkEvent::Status(
                                            format!("❌ Неверный адрес: {}", e)
                                        )).await;
                                    }
                                }
                            }
                            UICommand::SearchPeer(peer_id) => {
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("🔍 Ищу пира {} в Kademlia...", &peer_id.to_string()[..16])
                                )).await;
                                swarm.behaviour_mut().kad.get_closest_peers(peer_id);
                            }
                            UICommand::DialPeer(peer_id, addrs) => {
                                 let short = &peer_id.to_string()[..16];
                                 println!("🔌 UI_COMMAND: DialPeer {} ({} addresses)", short, addrs.len());

                                 // Добавляем только не-loopback адреса в Kad
                                 for addr in &addrs {
                                     let s = addr.to_string();
                                     if !s.contains("127.0.0.1") && !s.contains("::1") {
                                         swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                     }
                                 }

                                  let opts = DialOpts::peer_id(peer_id)
                                     .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                                     .addresses(addrs)
                                     .build();

                                 if let Err(e) = swarm.dial(opts) {
                                      let err_str = format!("{:?}", e);
                                      if !err_str.contains("Condition") {
                                          println!("❌ Dial ERROR для {}: {:?}", short, e);
                                      }
                                      pending_dials.remove(&peer_id);
                                 }
                             }
                            UICommand::SendMessage { sender_name, text, recipient, is_retry: _is_retry } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                println!("[{}] 📤 UI_SEND: '{}' (To: {:?})", now, text, recipient);
                                let msg = ChatMessage {
                                    sender_id: local_peer_id.to_string(),
                                    sender_name: sender_name.clone(),
                                    recipient_id: recipient.map(|p| p.to_string()),
                                    text: text.clone(),
                                    timestamp: chrono::Local::now().format("%H:%M").to_string(),
                                };

                                let json_data = serde_json::to_vec(&msg).unwrap();
                                let mut packet = V1Packet::Plain(msg.clone());

                                if let Some(peer_id) = recipient {
                                    if let Some(session) = sessions.get_mut(&peer_id) {
                                        if let Ok((header, ciphertext)) = session.encrypt_payload(json_data.as_slice()) {
                                            packet = V1Packet::Encrypted { header, ciphertext };
                                            println!("[{}] 🔒 E2EE: Сообщение зашифровано для {}", now, &peer_id.to_string()[..8]);
                                        }
                                    } else {
                                        let hello = V1Packet::Hello { public_key: my_public_key.to_bytes() };
                                        let _ = swarm.behaviour_mut().request_response.send_request(&peer_id, hello);
                                        println!("[{}] 🤝 E2EE: Сессии нет, направлен Hello пиру {}", now, &peer_id.to_string()[..8]);
                                    }

                                    // Отправляем конкретному пиру
                                    let _ = swarm.behaviour_mut().request_response.send_request(&peer_id, packet);
                                    println!("[{}] 📨 RequestResponse: Отправка пиру {}", now, &peer_id.to_string()[..8]);
                                } else {
                                    // "Общий поток" в безмешовой сети - шлем всем ПОДКЛЮЧЕННЫМ
                                    let connected: Vec<_> = swarm.connected_peers().cloned().collect();
                                    if connected.is_empty() {
                                        println!("[{}] ⚠️ Нет подключений для рассылки сообщения", now);
                                    }
                                    for peer in connected {
                                        let _ = swarm.behaviour_mut().request_response.send_request(&peer, packet.clone());
                                    }
                                    println!("[{}] 📢 Рассылка сообщения всем подключенным ({})", now, swarm.connected_peers().count());
                                }
                                let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                            }
                        }
                    }
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            let s = address.to_string();
                            local_listen_addrs.insert(address.clone());
                            println!("📡 СЛУШАЮ: {}", address);

                            let is_external = !s.contains("/ip6/") && !s.contains("/0.0.0.0") && !s.contains("/127.0.0.1") || s.contains("p2p-circuit");

                            if is_external {
                                println!("  (Внешний/Relay): {}/p2p/{}", address, local_peer_id);
                                let _ = event_tx.send(NetworkEvent::NewListenAddr(address.clone())).await;
                                swarm.add_external_address(address);
                            }

                            if s.contains("p2p-circuit") {
                                let _ = event_tx.send(NetworkEvent::Status(
                                    "✨ СВЯЗЬ ЧЕРЕЗ RELAY: Вы доступны через посредника (за NAT)!".into()
                                )).await;
                            }
                        },

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, addr) in list {
                                if peer_id == local_peer_id { continue; }
                                println!("🔍 mDNS: найден пир {} на {}. Подключаюсь (Local)...", &peer_id.to_string()[..8], addr);
                                // Регистрация адреса в Kademlia для возможности прямого вызова (Request-Response)
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                // АВТО-ПОДКЛЮЧЕНИЕ для mDNS (локальная сеть)
                                let _ = swarm.dial(addr.clone());
                                let _ = event_tx.send(NetworkEvent::MdnsDiscovered(peer_id, addr.clone())).await;
                                peer_addrs.entry(peer_id).or_default().push(addr);
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                            for (peer_id, _) in peers {
                                let _ = event_tx.send(NetworkEvent::MdnsExpired(peer_id)).await;
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::RequestResponse(libp2p::request_response::Event::Message { peer, message, .. })) => {
                            let now = chrono::Local::now().format("%H:%M:%S").to_string();
                            let packet = match message {
                                libp2p::request_response::Message::Request { request, .. } => request,
                                libp2p::request_response::Message::Response { response, .. } => response,
                            };

                            match packet {
                                V1Packet::Hello { public_key } => {
                                    if peer != local_peer_id {
                                        let session_exists = sessions.contains_key(&peer);
                                        let is_initiator = local_peer_id < peer;
                                        let role_str = if is_initiator { "Initiator" } else { "Responder" };

                                        println!("[{}] 🤝 E2EE: RequestResponse Hello от {}. Роль: {}. Создаю сессию.", now, &peer.to_string()[..8], role_str);

                                        let remote_key = crypto::PublicKey::from(public_key);
                                        let session = if is_initiator {
                                            crypto::SecureSession::new_initiator(&local_static, &remote_key)
                                        } else {
                                            crypto::SecureSession::new_responder(&local_static, &remote_key)
                                        };
                                        sessions.insert(peer, session);

                                        if !session_exists {
                                            let my_hello = V1Packet::Hello { public_key: my_public_key.to_bytes() };
                                            let _ = swarm.behaviour_mut().request_response.send_request(&peer, my_hello);
                                        }
                                    }
                                }
                                V1Packet::Encrypted { header, ciphertext } => {
                                    if let Some(session) = sessions.get_mut(&peer) {
                                        if let Ok(plaintext) = session.decrypt_payload(&header, &ciphertext) {
                                            if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&plaintext) {
                                                println!("[{}] 🔒 E2EE: Сообщение ДЕШИФРОВАНО от {}", now, &peer.to_string()[..8]);
                                                let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                            }
                                        } else {
                                            println!("[{}] ❌ E2EE: Ошибка дешифровки от {}", now, &peer.to_string()[..8]);
                                        }
                                    } else {
                                        println!("[{}] ⚠️ E2EE: Получен шифрованный RR-пакет, но сессия не найдена для {}", now, &peer.to_string()[..8]);
                                    }
                                }
                                V1Packet::Plain(msg) => {
                                    if peer != local_peer_id {
                                        println!("[{}] 📖 Текст RR (открытый): {}", now, msg.text);
                                        let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                    }
                                }
                            }
                        }
                        SwarmEvent::ExternalAddrConfirmed { address } => {
                            println!("🌍 ВНЕШНИЙ АДРЕС ПОДТВЕРЖДЕН: {}", address);
                            let _ = event_tx.send(NetworkEvent::Status(
                                format!("🌍 ГЛОБАЛЬНЫЙ АДРЕС: Вы доступны из интернета!")
                            )).await;
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            let connected_count = swarm.connected_peers().count();
                            println!("✅ СОЕДИНЕНО: {}. Endpoint: {:?}. Всего пиров: {}", peer_id, endpoint, connected_count);
                            pending_dials.remove(&peer_id);

                             if peer_id != local_peer_id {
                                 let _ = event_tx.send(NetworkEvent::Connected(peer_id)).await;
                             }
                        },
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            let connected_count = swarm.connected_peers().count();
                            println!("❌ СОЕДИНЕНИЕ ЗАКРЫТО: {}. Причина: {:?}. Осталось: {}", peer_id, cause, connected_count);
                            let _ = event_tx.send(NetworkEvent::Disconnected(peer_id)).await;
                        }
                        SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                            println!("📥 Входящее соединение: from {:?} to {:?}", send_back_addr, local_addr);
                        },

                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            let now = chrono::Local::now().format("%H:%M:%S").to_string();
                            let peer_str = peer_id
                                .map(|p| format!("{}...", &p.to_string()[..8]))
                                .unwrap_or_else(|| "?".into());

                             let err_str = error.to_string();
                             // 10048 (AddrInUse), Timeout, Handshake, DNS Resolve — игнорируем в UI
                             let is_noise = err_str.contains("64000") ||
                                           err_str.contains("10048") ||
                                           err_str.contains("Timeout") ||
                                           err_str.contains("Handshake") ||
                                           err_str.contains("ResolveError") ||
                                           err_str.contains("No Matching Records Found");

                             if !is_noise {
                                 println!("❌ ОШИБКА ИСХОДЯЩЕГО СОЕДИНЕНИЯ (peer: {}): {:?}", peer_str, error);
                                 let _ = event_tx.send(NetworkEvent::Status(
                                     format!("❌ Ошибка подключения: {}", peer_str)
                                 )).await;
                             } else {
                                 // В консоли пишем кратко
                                 if err_str.contains("Timeout") || err_str.contains("Handshake") {
                                     println!("ℹ️ [{}] Тайм-аут с {}. Проверьте ФАЙРВОЛ на обоих сторонах!", now, peer_str);
                                 } else if err_str.contains("10048") {
                                     println!("ℹ️ [{}] Ошибка 10048 (нормально для Windows): {}", now, peer_str);
                                 } else {
                                     println!("ℹ️ [{}] Техническая задержка/отказ (peer: {}): {}", now, peer_str, err_str);
                                 }
                             }

                            if let Some(p) = peer_id {
                                pending_dials.remove(&p);
                                dial_backoff.insert(p, std::time::Instant::now());
                            }
                        },
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            let err_str = error.to_string();
                            if !err_str.contains("Handshake") && !err_str.contains("Timeout") {
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ Входящее подключение отклонено: {}", error)
                                )).await;
                            }
                        },

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            let now = chrono::Local::now().format("%H:%M:%S").to_string();
                            println!("[{}] 🆔 Identify: Получено от {}: protocols={:?}", now, peer_id, info.protocols);


                             // Добавляем внешние адреса пира в DHT
                             for addr in info.listen_addrs {
                                 swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                             }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Sent { peer_id, .. })) => {
                            println!("🆔 Identify: Отправлена информация пиру {}", peer_id);
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Error { peer_id, error, .. })) => {
                            let err_str = error.to_string();
                            let err_lower = err_str.to_lowercase();
                            if err_lower.contains("negotiat") || err_lower.contains("failed to negotiate") || err_lower.contains("support") {
                                println!("❌ [КРИТИЧНО] Identify: Несовпадение версий с {}.", peer_id);
                                println!("🔥 Срочно ОБНОВИТЕ другое приложение и ЗАКРОЙТЕ старые процессы!");
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ ОШИБКА: Пир {}... использует СТАРУЮ ВЕРСИЮ!", &peer_id.to_string()[..8])
                                )).await;
                            } else {
                                println!("🆔 Identify: Ошибка с пиром {}: {:?}", peer_id, error);
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { result, .. })) => {
                            match result {
                                 libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                                    println!("🔍 Kademlia: поиск завершен. Найдено {} узлов.", ok.peers.len());
                                    for peer in ok.peers {
                                        if !peer.addrs.is_empty() {
                                            println!("📍 Найдено: {} ({} адресов)", &peer.peer_id.to_string()[..8], peer.addrs.len());
                                            // Если среди найденных есть тот, кого мы искали - подключаемся
                                            let _ = command_tx_for_mdns.try_send(UICommand::DialPeer(peer.peer_id, peer.addrs));
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, addresses, .. })) => {
                            println!("📍 Kademlia: маршрут обновлен для {}: {:?}", peer, addresses);
                        }

                        _ => {}
                    }
                },
                _ = kad_bootstrap_timer.tick() => {
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                }
            }
        }
    });

    eframe::run_native(
        &format!("VOID Chat [{}]", local_peer_id.to_string()[..8].to_string()),
        eframe::NativeOptions::default(),
        Box::new(move |cc| {
            Ok(Box::new(App::new(
                cc,
                local_peer_id,
                local_nickname,
                static_secret,
                command_tx,
                event_rx,
            )))
        }),
    )
    .map_err(|e| Box::new(e) as Box<dyn Error>)
}
