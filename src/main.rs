mod crypto;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use chrono;
use eframe::egui;
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, noise, ping, relay,
    swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmEvent},
    tcp, upnp, yamux, Multiaddr, PeerId,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::time::Duration;
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
    MeshPeers(usize),
    ChatMessage(ChatMessage),
    Status(String),
}

enum UICommand {
    Dial(String),
    DialPeer(PeerId, Vec<Multiaddr>),
    SendMessage {
        sender_name: String,
        text: String,
        recipient: Option<PeerId>,
    },
}

#[derive(NetworkBehaviour)]
struct ChatBehaviour {
    gossipsub: gossipsub::Behaviour,
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
    mesh_peers: usize,
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
            mesh_peers: 0,
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
                                ui.label(
                                    egui::RichText::new(&self.local_peer_id.to_string()[..16])
                                        .size(12.0)
                                        .monospace()
                                        .weak(),
                                );
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
                            ui.label(format!("📡 В сети (Mesh): {}", self.mesh_peers));

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
                                .selectable_label(is_global, "🌍 Глобальный чат")
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
                                    .hint_text("/ip4/...")
                                    .desired_width(ui.available_width()),
                            );
                            ui.add_space(8.0);
                            if ui
                                .add(egui::Button::new(
                                    egui::RichText::new("ПОДКЛЮЧИТЬ").size(14.0),
                                ))
                                .clicked()
                                && !self.dial_address.is_empty()
                            {
                                let _ = self
                                    .command_tx
                                    .try_send(UICommand::Dial(self.dial_address.clone()));
                                self.dial_address.clear();
                            }
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
                    // Добавляем в список известных, если еще нет
                    self.known_peers
                        .entry(peer)
                        .or_insert_with(|| format!("Peer_{}", &peer.to_string()[..4]));
                }
                NetworkEvent::MdnsExpired(peer) => {
                    self.add_status(format!("⏳ Оффлайн (MDNS): {}", &peer.to_string()[..8]));
                }
                NetworkEvent::Connected(peer) => {
                    self.connected_peers += 1;
                    self.add_status(format!("✅ Подключено: {}...", &peer.to_string()[..8]));
                    // Добавляем в список известных, если еще нет
                    self.known_peers
                        .entry(peer)
                        .or_insert_with(|| format!("Peer_{}", &peer.to_string()[..4]));
                }
                NetworkEvent::Disconnected(peer) => {
                    self.connected_peers = self.connected_peers.saturating_sub(1);
                    self.add_status(format!("❌ Отключено: {}...", &peer.to_string()[..8]));
                }
                NetworkEvent::MeshPeers(count) => {
                    self.mesh_peers = count;
                }
                NetworkEvent::ChatMessage(msg) => {
                    // Update known peers for display names
                    if let Ok(peer_id) = msg.sender_id.parse::<PeerId>() {
                        self.known_peers.insert(peer_id, msg.sender_name.clone());
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
                    &format!("program=\"{}\"", exe),
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
                    &format!("program=\"{}\"", exe),
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
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=TCP localport=50001 profile=any enable=yes program=\"\\\"{}\\\"\"\r\n\
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=UDP localport=50001 profile=any edge=yes enable=yes program=\"\\\"{}\\\"\"\r\n",
                exe, exe
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
            .with_dns()
            .unwrap()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|key, relay_client| {
                let local_peer_id = key.public().to_peer_id();

                // Gossipsub: оптимизированные параметры для Windows
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(500))
                    .validation_mode(gossipsub::ValidationMode::Permissive)
                    .mesh_n_low(2) // Минимум 2 пира для меша
                    .mesh_n(3) // Цель - 3
                    .mesh_n_high(6)
                    .flood_publish(true)
                    .max_transmit_size(262144) // 256KB
                    .build()
                    .unwrap();

                // Kademlia: хранилище в памяти
                let kad_store = kad::store::MemoryStore::new(local_peer_id);
                let mut kad = kad::Behaviour::new(local_peer_id, kad_store);

                // Добавляем бутстрап-ноды IPFS (надежные)
                let bootstrap = [
                    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnoo2uR3GuwhvBqyM4tTDp6NoS7wB9G9o9wE5pS9Y6mY",
                    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcSTwsrmMvFUXS7uK9z1V64p9C8ndn4y2K8w8f3z",
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

                Ok(ChatBehaviour {
                    gossipsub: gossipsub::Behaviour::new(
                        gossipsub::MessageAuthenticity::Signed(key.clone()),
                        gossipsub_config,
                    )
                    .unwrap(),
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                        .unwrap(),
                    ping: ping::Behaviour::default(),
                    identify: identify::Behaviour::new(identify::Config::new(
                        "/ipfs/id/1.0.0".into(),
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

        // Подписываемся на топик
        let topic = gossipsub::IdentTopic::new("void-chat-v1");
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

        // Слушаем TCP. Сначала пробуем 50001, если занято - берем любой свободный.
        let tcp_addr: Multiaddr = "/ip4/0.0.0.0/tcp/50001".parse().unwrap();

        if let Err(e) = swarm.listen_on(tcp_addr.clone()) {
            println!("⚠️ TCP порт 50001 занят ({:?}), пробую случайный...", e);
            swarm
                .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
                .unwrap();
        }

        // Слушаем через Relay для работы за NAT
        let _ = swarm.listen_on("/p2p-circuit".parse().unwrap());

        let _ = event_tx
            .send(NetworkEvent::Status(
                "🚀 Запущен. Ищу пиров через mDNS...".into(),
            ))
            .await;

        let mut mesh_check = tokio::time::interval(Duration::from_secs(5));
        let mut hello_broadcast = tokio::time::interval(Duration::from_secs(30));
        let mut kad_bootstrap_timer = tokio::time::interval(Duration::from_secs(300)); // 5 минут
                                                                                       // Кэш адресов для mDNS: пир → все его адреса (TCP + QUIC)
        let mut peer_addrs: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        // Пиры, к которым уже запущен или идёт dial (избегаем дубликат)
        let mut pending_dials: HashSet<PeerId> = HashSet::new();

        loop {
            tokio::select! {
                _ = hello_broadcast.tick() => {
                    let hello = V1Packet::Hello { public_key: my_public_key.to_bytes() };
                    if let Ok(json) = serde_json::to_vec(&hello) {
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), json);
                    }
                }
                _ = mesh_check.tick() => {
                    let mesh = swarm.behaviour().gossipsub.all_mesh_peers().count();
                    let _ = event_tx.send(NetworkEvent::MeshPeers(mesh)).await;
                }
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
                             UICommand::DialPeer(peer_id, addrs) => {
                                 let short = &peer_id.to_string()[..16];
                                 println!("🔌 UI_COMMAND: DialPeer {} ({} addresses)", short, addrs.len());

                                 // Добавляем адреса в Kad перед дозвоном
                                 for addr in addrs {
                                     swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                                 }

                                 let opts = DialOpts::peer_id(peer_id)
                                     .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                                     .build();

                                 if let Err(e) = swarm.dial(opts) {
                                      println!("❌ Dial ERROR для {}: {:?}", short, e);
                                 }
                             }
                            UICommand::SendMessage { sender_name, text, recipient } => {
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
                                        let h_json = serde_json::to_vec(&hello).unwrap();
                                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), h_json);
                                        println!("[{}] 🤝 E2EE: Сессии нет, отправлен Hello пиру {}", now, &peer_id.to_string()[..8]);
                                    }
                                }

                                let final_json = serde_json::to_vec(&packet).unwrap();

                                match swarm.behaviour_mut().gossipsub.publish(topic.clone(), final_json.clone()) {
                                    Ok(id) => println!("[{}] ✅ Gossipsub: Опубликовано, ID: {:?}", now, id),
                                    Err(e) => {
                                        println!("[{}] ❌ Gossipsub ERROR: {:?}. Рефреш пиров...", now, e);
                                        // Форсируем добавление всех подключенных
                                        let connected: Vec<_> = swarm.connected_peers().cloned().collect();
                                        for peer in connected {
                                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                                        }
                                        // Пробуем еще раз через секунду, если это была ошибка пустой подписки
                                        // Важно: swarm не может быть перемещен, так как он используется дальше в цикле.
                                        // Вместо этого, мы можем отправить команду на повторную публикацию через command_tx (clone).
                                        // Однако, для простоты и избежания рефакторинга всего цикла,
                                        // мы просто отправляем повторную команду в канал.
                                        // Если меш пуст, то это может быть `NotSubscribed` или `NoMesh`
                                        if swarm.behaviour().gossipsub.all_mesh_peers().count() == 0 {
                                            println!("[{}] ⚠️ Gossipsub: Меш пуст, повтор будет через 2с (лимит 1 раз)...", now);
                                            let command_tx_clone = command_tx_for_mdns.clone();
                                            let sender_name_clone = sender_name.clone();
                                            let text_clone = text.clone();
                                            let recipient_clone = recipient;
                                            tokio::spawn(async move {
                                                tokio::time::sleep(Duration::from_secs(2)).await;
                                                let _ = command_tx_clone.send(UICommand::SendMessage {
                                                    sender_name: sender_name_clone,
                                                    text: text_clone,
                                                    recipient: recipient_clone,
                                                }).await;
                                            });
                                        }
                                    }
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
                            if !s.contains("/ip6/") && !s.contains("/0.0.0.0") && !s.contains("/127.0.0.1") {
                                println!("Слушаю: {}/p2p/{}", address, local_peer_id);
                                let _ = event_tx.send(NetworkEvent::NewListenAddr(address.clone())).await;
                                // Объявляем адрес внешним для лучшего дискавери
                                swarm.add_external_address(address);
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                            let mut to_dial: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
                            for (peer_id, addr) in peers {
                                if peer_id == local_peer_id { continue; }
                                let a_str = addr.to_string();

                                // Профилактическая чистка: если мы видим этого пира, удаляем старые записи 64000 из его кэша
                                let p_addrs = peer_addrs.entry(peer_id).or_default();
                                p_addrs.retain(|a| !a.to_string().contains(":64000") && !a.to_string().contains("/64000"));

                                // Игнорируем QUIC и старые порты (64000) для стабильности
                                if a_str.contains("quic") { continue; }
                                if a_str.contains("/tcp/64000") {
                                    continue;
                                }

                                println!("mDNS: найден {} на {}", peer_id, addr);
                                let _ = event_tx.send(NetworkEvent::MdnsDiscovered(peer_id, addr.clone())).await;
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                if swarm.is_connected(&peer_id) || pending_dials.contains(&peer_id) {
                                    continue;
                                }
                                to_dial.entry(peer_id).or_default().push(addr);
                            }

                            for (peer_id, addrs) in to_dial {
                                let all_addrs = peer_addrs.entry(peer_id).or_default();
                                for a in &addrs {
                                    if !all_addrs.contains(a) {
                                        all_addrs.push(a.clone());
                                    }
                                }

                                let is_leader = local_peer_id.to_string() < peer_id.to_string();
                                let delay_ms = if is_leader { 500 } else { 10000 };

                                pending_dials.insert(peer_id);
                                let cmd_tx2 = command_tx_for_mdns.clone();
                                let dial_addrs = all_addrs.clone();
                                let tx = event_tx.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                    let type_str = if is_leader { "Leader" } else { "Follower" };
                                    // Ослабляем спам, отправляем только если еще не подключены
                                    let _ = tx.send(NetworkEvent::Status(
                                        format!("🔄 [{}] Попытка соединения с {}...", type_str, &peer_id.to_string()[..8])
                                    )).await;
                                    let _ = cmd_tx2.send(UICommand::DialPeer(peer_id, dial_addrs)).await;
                                });
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                            for (peer_id, _) in peers {
                                let _ = event_tx.send(NetworkEvent::MdnsExpired(peer_id)).await;
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                            let now = chrono::Local::now().format("%H:%M:%S").to_string();
                            if let Ok(packet) = serde_json::from_slice::<V1Packet>(&message.data) {
                                match packet {
                                    V1Packet::Hello { public_key } => {
                                        if let Some(src) = message.source {
                                            if src != local_peer_id {
                                                println!("[{}] 🤝 E2EE: Получен Hello от {}. Создаю сессию.", now, &src.to_string()[..8]);
                                                let remote_key = crypto::PublicKey::from(public_key);
                                                let session = crypto::SecureSession::new_responder(&local_static, &remote_key);
                                                sessions.insert(src, session);

                                                // Отвечаем своим Hello, если сессии с ним еще не было
                                                let my_hello = V1Packet::Hello { public_key: my_public_key.to_bytes() };
                                                let h_json = serde_json::to_vec(&my_hello).unwrap();
                                                let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), h_json);
                                            }
                                        }
                                    }
                                    V1Packet::Encrypted { header, ciphertext } => {
                                        if let Some(src) = message.source {
                                            if let Some(session) = sessions.get_mut(&src) {
                                                if let Ok(plaintext) = session.decrypt_payload(&header, &ciphertext) {
                                                    if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&plaintext) {
                                                        println!("[{}]  E2EE: Сообщение ДЕШИФРОВАНО от {}", now, &src.to_string()[..8]);
                                                        let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                                    }
                                                } else {
                                                    println!("[{}] ❌ E2EE: Ошибка дешифровки от {}", now, &src.to_string()[..8]);
                                                }
                                            } else {
                                                println!("[{}] ⚠️ E2EE: Получен шифрованный пакет, но сессия не найдена для {}", now, &src.to_string()[..8]);
                                            }
                                        }
                                    }
                                    V1Packet::Plain(msg) => {
                                        if message.source != Some(local_peer_id) {
                                            println!("[{}] 📖 Текст сообщения (отрытый): {}", now, msg.text);
                                            let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                        }
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                            println!("📡 Gossipsub: {}... ПОДПИСАЛСЯ на топик ({})", &peer_id.to_string()[..8], topic);
                            let _ = event_tx.send(NetworkEvent::Status(
                                format!("📡 {}... присоединился к чату ({})", &peer_id.to_string()[..8], topic)
                            )).await;
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic })) => {
                            println!("📡 Gossipsub: {}... ОТПИСАЛСЯ от топика ({})", &peer_id.to_string()[..8], topic);
                        }

                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            let mesh_count = swarm.behaviour().gossipsub.all_mesh_peers().count();
                            println!("✅ СОЕДИНЕНО: {}. Endpoint: {:?}. В меше: {}", peer_id, endpoint, mesh_count);
                            pending_dials.remove(&peer_id);

                            // Принудительно добавляем и подписываем (для надежности)
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            let topic = gossipsub::IdentTopic::new("void-chat-v1");
                            let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);

                            let _ = event_tx.send(NetworkEvent::Connected(peer_id)).await;
                            let _ = event_tx.send(NetworkEvent::MeshPeers(mesh_count)).await;
                        }
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            let mesh = swarm.behaviour().gossipsub.all_mesh_peers().count();
                            println!("❌ СОЕДИНЕНИЕ ЗАКРЫТО: {}. Причина: {:?}", peer_id, cause);
                            let _ = event_tx.send(NetworkEvent::Disconnected(peer_id)).await;
                            let _ = event_tx.send(NetworkEvent::MeshPeers(mesh)).await;
                        }
                        SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                            let s_addr = send_back_addr.to_string();
                            if s_addr.contains("64000") {
                                println!("⚠️ [ВНИМАНИЕ] Входящее от СТАРОЙ ВЕРСИИ (порт 64000): from {:?}. Ожидайте ошибку Identify.", send_back_addr);
                                let _ = event_tx.send(NetworkEvent::Status(
                                    "⚠️ ВНИМАНИЕ: Подключился старый пир. Сообщения НЕ БУДУТ работать до его обновления!".into()
                                )).await;
                            } else {
                                println!("📥 Входящее соединение: from {:?} to {:?}", send_back_addr, local_addr);
                            }
                        }

                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            let peer_str = peer_id
                                .map(|p| format!("{}...", &p.to_string()[..8]))
                                .unwrap_or_else(|| "?".into());

                            let err_str = error.to_string();
                            // Игнорируем технический шум и старые порты
                            if !err_str.contains("64000") && !err_str.contains("HandshakeTimedOut") && !err_str.contains("Timeout") {
                                println!("❌ ОШИБКА ИСХОДЯЩЕГО СОЕДИНЕНИЯ (peer: {}): {:?}", peer_str, error);
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ Не удалось подключиться к {}: {}", peer_str, error)
                                )).await;
                            }

                            if let Some(p) = peer_id {
                                pending_dials.remove(&p);
                            }
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            let err_str = error.to_string();
                            if !err_str.contains("Handshake") && !err_str.contains("Timeout") {
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ Входящее подключение отклонено: {}", error)
                                )).await;
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            let now = chrono::Local::now().format("%H:%M:%S").to_string();
                            println!("[{}] 🆔 Identify: Получено от {}: protocols={:?}", now, peer_id, info.protocols);

                            // Добавляем внешние адреса пира в DHT
                            for addr in info.listen_addrs {
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                            }

                            if info.protocols.iter().any(|p| p.to_string().contains("gossipsub")) {
                                println!("[{}] ✨ Пир {} поддерживает Gossipsub. Добавляю принудительно.", now, peer_id);
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Sent { peer_id, .. })) => {
                            println!("🆔 Identify: Отправлена информация пиру {}", peer_id);
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Error { peer_id, error, .. })) => {
                            let err_str = error.to_string();
                            if err_str.contains("NegotiationFailed") {
                                println!("❌ [КРИТИЧНО] Identify: Несовпадение версий с {}.", peer_id);
                                println!("🔥 Срочно ОБНОВИТЕ другое приложение и ЗАКРОЙТЕ старые процессы!");
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ ОШИБКА: Пир {}... использует СТАРУЮ ВЕРСИЮ!", &peer_id.to_string()[..8])
                                )).await;
                            } else {
                                println!("🆔 Identify: Ошибка с пиром {}: {:?}", peer_id, error);
                            }
                        }

                        _ => {}
                    }
                }
                _ = kad_bootstrap_timer.tick() => {
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                }
            }
        }
    });

    eframe::run_native(
        "VOID P2P Chat",
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
