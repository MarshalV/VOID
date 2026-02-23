use chrono;
use eframe::egui;
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, upnp, yamux, Multiaddr, PeerId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

// Фильтр адресов: убираем только IPv6 и 0.0.0.0
fn is_bad_addr(addr: &Multiaddr) -> bool {
    let s = addr.to_string();
    // Игнорируем IPv6 (на Windows часто ведет в никуда)
    if s.contains("/ip6/") {
        return true;
    }
    s.contains("/::1") || s.contains("/0.0.0.0")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    sender: String,
    text: String,
    timestamp: String,
}

enum NetworkEvent {
    NewListenAddr(Multiaddr),
    PeerDiscovered(PeerId),
    IdentifyReceived {
        peer_id: PeerId,
        protocols: Vec<String>,
    },
    PingResult {
        peer_id: PeerId,
        rtt: Duration,
    },
    RelayStatus {
        connected: bool,
        relay_id: PeerId,
    },
    NetworkError(String),
    ConnectionAttempt(String),
    TotalPeers(usize),
    MeshPeers(usize),
    NatStatus(String),
    ChatMessage(ChatMessage),
}

enum UICommand {
    Dial(String),
    SendMessage(String),
    RefreshBootstrap,
}

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    ping: ping::Behaviour,
    mdns: mdns::tokio::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    autonat: autonat::Behaviour,
    upnp: upnp::tokio::Behaviour,
    gossipsub: gossipsub::Behaviour,
}

struct P2pApp {
    local_peer_id: PeerId,
    listen_addrs: Vec<Multiaddr>,
    all_listen_addrs: Vec<Multiaddr>,
    peers: HashMap<PeerId, PeerInfo>,
    dial_address: String,
    chat_input: String,
    chat_messages: Vec<ChatMessage>,
    command_tx: mpsc::Sender<UICommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,

    relay_connected: bool,
    active_relay_id: Option<PeerId>,
    total_peers: usize,
    mesh_peers: usize,
    last_error: Option<String>,
    network_log: Vec<String>,
    nat_status: String,
}

struct PeerInfo {
    rtt: Option<Duration>,
    protocols: Vec<String>,
}

impl P2pApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        local_peer_id: PeerId,
        command_tx: mpsc::Sender<UICommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
    ) -> Self {
        cc.egui_ctx.set_pixels_per_point(1.2);
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = egui::Color32::from_rgb(10, 10, 15);
        cc.egui_ctx.set_visuals(visuals);

        Self {
            local_peer_id,
            listen_addrs: Vec::new(),
            all_listen_addrs: Vec::new(),
            peers: HashMap::new(),
            dial_address: String::new(),
            chat_input: String::new(),
            chat_messages: Vec::new(),
            command_tx,
            event_rx,
            relay_connected: false,
            active_relay_id: None,
            total_peers: 0,
            mesh_peers: 0,
            last_error: None,
            network_log: Vec::new(),
            nat_status: "Определение...".to_string(),
        }
    }
}

fn add_to_log(log: &mut Vec<String>, msg: String) {
    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
    log.push(format!("[{}] {}", ts, msg));
    if log.len() > 30 {
        log.remove(0);
    }
}

impl eframe::App for P2pApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::NewListenAddr(addr) => {
                    if !self.all_listen_addrs.contains(&addr) {
                        self.all_listen_addrs.push(addr.clone());
                        // Показываем все адреса кроме p2p-circuit (relay)
                        let s = addr.to_string();
                        if !s.contains("p2p-circuit")
                            && !s.contains("/ip6/")
                            && !s.contains("/0.0.0.0")
                        {
                            if !self.listen_addrs.contains(&addr) {
                                self.listen_addrs.push(addr.clone());
                            }
                        }
                    }
                }
                NetworkEvent::PeerDiscovered(peer_id) => {
                    self.peers.entry(peer_id).or_insert(PeerInfo {
                        rtt: None,
                        protocols: Vec::new(),
                    });
                }
                NetworkEvent::IdentifyReceived { peer_id, protocols } => {
                    if let Some(info) = self.peers.get_mut(&peer_id) {
                        info.protocols = protocols;
                    }
                    add_to_log(
                        &mut self.network_log,
                        format!("Peer ID: {}...", &peer_id.to_string()[..8]),
                    );
                }
                NetworkEvent::PingResult { peer_id, rtt } => {
                    if let Some(info) = self.peers.get_mut(&peer_id) {
                        info.rtt = Some(rtt);
                    }
                }
                NetworkEvent::RelayStatus {
                    connected,
                    relay_id,
                } => {
                    self.relay_connected = connected;
                    self.active_relay_id = if connected { Some(relay_id) } else { None };
                }
                NetworkEvent::NetworkError(err) => {
                    self.last_error = Some(err.clone());
                    add_to_log(&mut self.network_log, format!("! Error: {}", err));
                }
                NetworkEvent::ConnectionAttempt(msg) => {
                    add_to_log(&mut self.network_log, msg);
                }
                NetworkEvent::TotalPeers(count) => {
                    self.total_peers = count;
                }
                NetworkEvent::MeshPeers(count) => {
                    self.mesh_peers = count;
                }
                NetworkEvent::NatStatus(status) => {
                    self.nat_status = status;
                }
                NetworkEvent::ChatMessage(msg) => {
                    self.chat_messages.push(msg);
                }
            }
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading(
                    egui::RichText::new("VOID P2P 🌀 Quantum")
                        .color(egui::Color32::from_rgb(0, 255, 255)),
                );
                ui.separator();
                let status_color = if self.total_peers > 0 {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::RED
                };
                ui.label(
                    egui::RichText::new(format!("NET: {}", self.total_peers))
                        .color(status_color)
                        .strong(),
                );
                let mesh_color = if self.mesh_peers > 0 {
                    egui::Color32::from_rgb(0, 255, 127)
                } else {
                    egui::Color32::GRAY
                };
                ui.label(
                    egui::RichText::new(format!("CHAT: {}", self.mesh_peers))
                        .color(mesh_color)
                        .strong(),
                );
                ui.separator();
                ui.label(format!("NAT: {}", self.nat_status));
                if ui.button("🔄 RECONNECT").clicked() {
                    let _ = self.command_tx.try_send(UICommand::RefreshBootstrap);
                }
            });
            ui.add_space(8.0);
        });

        egui::SidePanel::left("left").show(ctx, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label("ID:");
                ui.label(
                    egui::RichText::new(&self.local_peer_id.to_string()[..12])
                        .small()
                        .monospace(),
                );
                if ui.button("📋").clicked() {
                    ui.output_mut(|o| o.copied_text = self.local_peer_id.to_string());
                }
            });
            ui.add_space(5.0);
            ui.separator();
            // === Подключение к пиру ===
            ui.label(egui::RichText::new("ПОДКЛЮЧИТЬСЯ:").strong());
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.dial_address)
                        .hint_text("Вставьте адрес..."),
                );
                if ui.button("➡ Join").clicked() && !self.dial_address.is_empty() {
                    let _ = self
                        .command_tx
                        .try_send(UICommand::Dial(self.dial_address.clone()));
                    self.dial_address.clear();
                }
            });

            ui.add_space(10.0);
            ui.separator();
            ui.label(egui::RichText::new("ВАШИ АДРЕСА (для другого клиента):").strong());
            ui.label(
                egui::RichText::new("Скопируйте любой адрес и вставьте в поле на другом клиенте")
                    .small()
                    .weak(),
            );
            egui::ScrollArea::vertical()
                .id_salt("addrs")
                .max_height(200.0)
                .show(ui, |ui| {
                    for addr in &self.listen_addrs {
                        // Полный адрес с /p2p/ для подключения
                        let full_addr = format!("{}/p2p/{}", addr, self.local_peer_id);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(&full_addr).small().monospace());
                            if ui.button("📋").on_hover_text("Копировать").clicked() {
                                ui.output_mut(|o| o.copied_text = full_addr.clone());
                            }
                        });
                    }
                });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                ui.label("GLOBAL CHANNEL (Gossipsub)");
                egui::ScrollArea::vertical()
                    .id_salt("chat_scroll")
                    .stick_to_bottom(true)
                    .max_height(ui.available_height() - 60.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for msg in &self.chat_messages {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    let is_me = msg.sender == self.local_peer_id.to_string();
                                    let color = if is_me {
                                        egui::Color32::from_rgb(0, 255, 127)
                                    } else {
                                        egui::Color32::from_rgb(255, 215, 0)
                                    };
                                    ui.label(
                                        egui::RichText::new(format!("<{}>", &msg.sender[..6]))
                                            .color(color)
                                            .monospace(),
                                    );
                                    ui.label(&msg.text);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                egui::RichText::new(&msg.timestamp).small().weak(),
                                            );
                                        },
                                    );
                                });
                            });
                        }
                    });
                ui.separator();
                ui.horizontal(|ui| {
                    let res = ui.add(
                        egui::TextEdit::singleline(&mut self.chat_input)
                            .desired_width(ui.available_width() - 80.0),
                    );
                    if (ui.button("SEND").clicked()
                        || (res.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter))))
                        && !self.chat_input.is_empty()
                    {
                        let _ = self
                            .command_tx
                            .try_send(UICommand::SendMessage(self.chat_input.clone()));
                        self.chat_input.clear();
                    }
                });
            });
        });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("error,libp2p_gossipsub=off,quinn_udp=off,libp2p_mdns=off")
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    let (event_tx, event_rx) = mpsc::channel(100);
    let (command_tx, mut command_rx) = mpsc::channel(100);

    // --- QUANTUM LEAP NODES (DNSaddr + IPs) ---
    let bootstrap_nodes = [
        // Официальные IPFS bootstrap-узлы с корректными PeerID
        "/dnsaddr/bootstrap.libp2p.io",
        "/dnsaddr/am6.bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
        "/dnsaddr/sg1.bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
        "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV3nyYQYMj26wBXxeDzHkGb86u78YJms5S4F8Nj",
        "/ip4/147.75.109.213/tcp/4001/p2p/QmNnooDu7bfjPFoNZSjzFBf4BLGEaKzxBBxFfPBsnn1CWi",
    ];

    tokio::spawn(async move {
        // --- 0.56 HIGH-LEVEL SWARM BUILDER ---
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_quic() // UDP Transport (часто пробивает там, где TCP виснет)
            .with_dns()
            .unwrap()
            .with_websocket(noise::Config::new, yamux::Config::default)
            .await
            .unwrap()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|key, relay_client| {
                let local_peer_id = key.public().to_peer_id();
                // Оптимизируем Gossipsub для работы даже с 1-2 пионами (Low Mesh)
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .mesh_n_low(1) // Работаем даже с одним пиром
                    .mesh_n(2) // Целевое количество
                    .mesh_n_high(4)
                    .build()
                    .unwrap();
                Ok(MyBehaviour {
                    ping: ping::Behaviour::default(),
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                        .unwrap(),
                    kad: kad::Behaviour::new(
                        local_peer_id,
                        kad::store::MemoryStore::new(local_peer_id),
                    ),
                    identify: identify::Behaviour::new(identify::Config::new(
                        "p2p/1.0".into(),
                        key.public(),
                    )),
                    relay_client,
                    dcutr: dcutr::Behaviour::new(local_peer_id),
                    autonat: autonat::Behaviour::new(local_peer_id, autonat::Config::default()),
                    upnp: upnp::tokio::Behaviour::default(),
                    gossipsub: gossipsub::Behaviour::new(
                        gossipsub::MessageAuthenticity::Signed(key.clone()),
                        gossipsub_config,
                    )
                    .unwrap(),
                })
            })
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(90)))
            .build();

        let topic = gossipsub::IdentTopic::new("global-chat");
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

        // Слушаем на TCP и QUIC
        let _ = swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap());
        let _ = swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap());

        // Агрессивный старт
        for addr_str in bootstrap_nodes {
            if let Ok(maddr) = addr_str.parse::<Multiaddr>() {
                let _ = swarm.dial(maddr);
            }
        }

        // Работаем в режиме сервера DHT — активно отвечаем на запросы
        swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));

        let chat_key = kad::RecordKey::new(&b"void-chat-v1".to_vec());
        // Объявляем себя как чат-пир в DHT
        let _ = swarm.behaviour_mut().kad.start_providing(chat_key.clone());

        let mut bootstrap_interval = tokio::time::interval(Duration::from_secs(30));
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = bootstrap_interval.tick() => {
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                    // Ищем других чат-пиров в DHT
                    swarm.behaviour_mut().kad.get_providers(chat_key.clone());
                    // Обновляем счетчик меш-пиров
                    let mesh = swarm.behaviour().gossipsub.all_mesh_peers().count();
                    let _ = event_tx.send(NetworkEvent::MeshPeers(mesh)).await;
                }
                _ = heartbeat_interval.tick() => {
                    // Keepalive: поддерживаем gossipsub-меш в живом состоянии
                    let mesh = swarm.behaviour().gossipsub.all_mesh_peers().count();
                    let _ = event_tx.send(NetworkEvent::MeshPeers(mesh)).await;
                    if mesh > 0 {
                        let heartbeat = ChatMessage {
                            sender: "__system__".to_string(),
                            text: "__heartbeat__".to_string(),
                            timestamp: String::new(),
                        };
                        let json = serde_json::to_vec(&heartbeat).unwrap();
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), json);
                    }
                }
                cmd = command_rx.recv() => {
                    if let Some(c) = cmd {
                        match c {
                            UICommand::Dial(addr) => {
                                match addr.parse::<Multiaddr>() {
                                    Ok(m) => {
                                        let _ = event_tx.send(NetworkEvent::ConnectionAttempt(
                                            format!("📞 Подключаюсь к {}...", &addr[..addr.len().min(40)])
                                        )).await;
                                        if let Err(e) = swarm.dial(m) {
                                            let _ = event_tx.send(NetworkEvent::NetworkError(
                                                format!("Ошибка dial: {:?}", e)
                                            )).await;
                                        }
                                    }
                                    Err(e) => {
                                        let _ = event_tx.send(NetworkEvent::NetworkError(
                                            format!("Неверный адрес: {:?}", e)
                                        )).await;
                                    }
                                }
                            }
                            UICommand::SendMessage(text) => {
                                let msg = ChatMessage {
                                    sender: local_peer_id.to_string(),
                                    text,
                                    timestamp: chrono::Local::now().format("%H:%M").to_string(),
                                };
                                let json = serde_json::to_vec(&msg).unwrap();
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), json) {
                                    let _ = event_tx.send(NetworkEvent::NetworkError(format!("Gossip fail: {:?}", e))).await;
                                }
                                let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                            }
                            UICommand::RefreshBootstrap => {
                                for addr_str in bootstrap_nodes {
                                    if let Ok(maddr) = addr_str.parse::<Multiaddr>() {
                                        let _ = swarm.dial(maddr);
                                    }
                                }
                                let _ = swarm.behaviour_mut().kad.bootstrap();
                            }
                        }
                    }
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            // Отправляем ВСЕ адреса в UI, включая /p2p-circuit
                            let _ = event_tx.send(NetworkEvent::NewListenAddr(address)).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                            if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&message.data) {
                                // Фильтруем системные heartbeat-сообщения — не показываем в чате
                                if msg.sender != "__system__" {
                                    let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                }
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic: t })) => {
                            let _ = event_tx.send(NetworkEvent::ConnectionAttempt(
                                format!("📡 Пир {}... подписался на {}", &peer_id.to_string()[..8], t)
                            )).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted { relay_peer_id, .. })) => {
                            let _ = event_tx.send(NetworkEvent::RelayStatus { connected: true, relay_id: relay_peer_id }).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. })) => {
                            let status = match new {
                                autonat::NatStatus::Public(addr) => format!("Public ({})", addr),
                                autonat::NatStatus::Private => "Private (NAT)".into(),
                                autonat::NatStatus::Unknown => "Unknown".into(),
                            };
                            let _ = event_tx.send(NetworkEvent::NatStatus(status)).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            let _ = event_tx.send(NetworkEvent::PeerDiscovered(peer_id)).await;
                            let _ = event_tx.send(NetworkEvent::IdentifyReceived {
                                peer_id, protocols: info.protocols.iter().map(|p| p.to_string()).collect()
                            }).await;

                            // Добавляем адреса пира в Kademlia для маршрутизации
                            for addr in info.listen_addrs {
                                if !is_bad_addr(&addr) {
                                    swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                }
                            }
                        }
                        // === mDNS: обнаружение пиров в локальной сети ===
                        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                            for (peer_id, addr) in peers {
                                let _ = event_tx.send(NetworkEvent::ConnectionAttempt(
                                    format!("🔍 mDNS: найден {}... ({})", &peer_id.to_string()[..8], addr)
                                )).await;
                                let _ = event_tx.send(NetworkEvent::PeerDiscovered(peer_id)).await;
                                // Добавляем в Kademlia
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                // Добавляем в Gossipsub как явный пир
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                // Подключаемся
                                let _ = swarm.dial(addr);
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                            for (peer_id, _addr) in peers {
                                let _ = event_tx.send(NetworkEvent::ConnectionAttempt(
                                    format!("⏳ mDNS: пир {}... ушёл", &peer_id.to_string()[..8])
                                )).await;
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                            result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, .. })),
                            ..
                        })) => {
                            for peer in providers {
                                // Нашли другого чат-пира! Подключаемся к нему.
                                let _ = event_tx.send(NetworkEvent::ConnectionAttempt(format!("🎯 Chat peer found: {}...", &peer.to_string()[..8]))).await;
                                let _ = swarm.dial(peer);
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Ping(ping::Event { peer, result: Ok(rtt), .. })) => {
                            let _ = event_tx.send(NetworkEvent::PingResult { peer_id: peer, rtt }).await;
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            let total = swarm.connected_peers().count();
                            let mesh = swarm.behaviour().gossipsub.all_mesh_peers().count();
                            let _ = event_tx.send(NetworkEvent::TotalPeers(total)).await;
                            let _ = event_tx.send(NetworkEvent::MeshPeers(mesh)).await;
                            let _ = event_tx.send(NetworkEvent::ConnectionAttempt(format!("✅ CONNECTED: {}...", &peer_id.to_string()[..8]))).await;
                            // Переобъявляем себя в DHT при каждом новом соединении
                            let _ = swarm.behaviour_mut().kad.start_providing(chat_key.clone());
                        }
                        SwarmEvent::ConnectionClosed { .. } => {
                            let total = swarm.connected_peers().count();
                            let mesh = swarm.behaviour().gossipsub.all_mesh_peers().count();
                            let _ = event_tx.send(NetworkEvent::TotalPeers(total)).await;
                            let _ = event_tx.send(NetworkEvent::MeshPeers(mesh)).await;
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    eframe::run_native(
        "P2P Messenger",
        eframe::NativeOptions::default(),
        Box::new(move |cc| {
            Ok(Box::new(P2pApp::new(
                cc,
                local_peer_id,
                command_tx,
                event_rx,
            )))
        }),
    )
    .map_err(|e| Box::new(e) as Box<dyn Error>)
}
