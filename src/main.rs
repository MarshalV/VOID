use eframe::egui;
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, identify, kad, mdns, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, upnp, yamux, Multiaddr, PeerId, Transport,
};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use chrono;

async fn add_to_log_tx(tx: &tokio::sync::mpsc::Sender<NetworkEvent>, msg: String) {
    let _ = tx.send(NetworkEvent::ConnectionAttempt(msg)).await;
}

// Глобальный фильтр локальных/приватных адресов для Windows (защита от os error 10048)
fn is_local_addr(addr: &Multiaddr) -> bool {
    let s = addr.to_string();
    s.contains("/127.0.0.1") || s.contains("/localhost") || s.contains("/::1") ||
    s.contains("/192.168.") || s.contains("/10.") || s.contains("/172.16.") || 
    s.contains("/172.17.") || s.contains("/172.18.") || s.contains("/172.19.") ||
    s.contains("/172.20.") || s.contains("/172.21.") || s.contains("/172.22.") ||
    s.contains("/172.23.") || s.contains("/172.24.") || s.contains("/172.25.") ||
    s.contains("/172.26.") || s.contains("/172.27.") || s.contains("/172.28.") ||
    s.contains("/172.29.") || s.contains("/172.30.") || s.contains("/172.31.") ||
    s.contains("/0.0.0.0") || s.contains("/::")
}

// Сообщения от сетевого слоя к UI
enum NetworkEvent {
    NewListenAddr(Multiaddr),
    PeerDiscovered(PeerId),
    IdentifyReceived { peer_id: PeerId, protocols: Vec<String> },
    PingResult { peer_id: PeerId, rtt: Duration },
    DhtUpdated,
    RelayStatus { connected: bool, relay_id: PeerId },
    RelayError(String),
    NetworkError(String),
    ConnectionAttempt(String),
    TotalPeers(usize),
    NatStatus(String),
}

// Сообщения от UI к сетевому слою
enum UICommand {
    Dial(String),
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
}

struct P2pApp {
    local_peer_id: PeerId,
    listen_addrs: Vec<Multiaddr>,
    peers: HashMap<PeerId, PeerInfo>,
    dial_address: String,
    command_tx: mpsc::Sender<UICommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    // Новые метрики сети
    relay_connected: bool,
    active_relay_id: Option<PeerId>,
    total_peers: usize,
    last_error: Option<String>,
    last_attempt: Option<String>,
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
        visuals.panel_fill = egui::Color32::from_rgb(18, 18, 22);
        visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(24, 24, 30);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(34, 34, 42);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(44, 44, 55);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(54, 54, 68);
        
        visuals.selection.bg_fill = egui::Color32::from_rgb(99, 102, 241); // Indigo
        visuals.window_rounding = 12.0.into();
        visuals.widgets.inactive.rounding = 8.0.into();
        visuals.widgets.hovered.rounding = 8.0.into();
        visuals.widgets.active.rounding = 8.0.into();
        
        cc.egui_ctx.set_visuals(visuals);

        let mut style = (*cc.egui_ctx.style()).clone();
        use egui::{FontId, TextStyle};
        style.text_styles = [
            (TextStyle::Heading, FontId::new(24.0, egui::FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(16.0, egui::FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(14.0, egui::FontFamily::Monospace)),
            (TextStyle::Button, FontId::new(16.0, egui::FontFamily::Proportional)),
            (TextStyle::Small, FontId::new(13.0, egui::FontFamily::Proportional)),
        ].into();

        style.spacing.item_spacing = egui::vec2(12.0, 12.0);
        style.spacing.button_padding = egui::vec2(12.0, 8.0);
        style.spacing.indent = 20.0;
        
        cc.egui_ctx.set_style(style);

        Self {
            local_peer_id,
            listen_addrs: Vec::new(),
            peers: HashMap::new(),
            dial_address: String::new(),
            command_tx,
            event_rx,
            relay_connected: false,
            active_relay_id: None,
            total_peers: 0,
            last_error: None,
            last_attempt: None,
            network_log: Vec::new(),
            nat_status: "Определение...".to_string(),
        }
    }
}

fn add_to_log(log: &mut Vec<String>, msg: String) {
    let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
    log.push(format!("[{}] {}", timestamp, msg));
    if log.len() > 10 {
        log.remove(0);
    }
}

impl eframe::App for P2pApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::NewListenAddr(addr) => {
                    if !self.listen_addrs.contains(&addr) {
                        self.listen_addrs.push(addr.clone());
                        add_to_log(&mut self.network_log, format!("Listen on {}", addr));
                    }
                }
                NetworkEvent::PeerDiscovered(peer_id) => {
                    self.peers.entry(peer_id).or_insert(PeerInfo { rtt: None, protocols: Vec::new() });
                    add_to_log(&mut self.network_log, format!("Found peer {}", peer_id));
                }
                NetworkEvent::IdentifyReceived { peer_id, protocols } => {
                    if let Some(info) = self.peers.get_mut(&peer_id) {
                        info.protocols = protocols;
                    }
                }
                NetworkEvent::PingResult { peer_id, rtt } => {
                    if let Some(info) = self.peers.get_mut(&peer_id) {
                        info.rtt = Some(rtt);
                    }
                }
                NetworkEvent::DhtUpdated => {}
                NetworkEvent::RelayStatus { connected, relay_id } => {
                    self.relay_connected = connected;
                    if connected {
                        self.active_relay_id = Some(relay_id);
                        self.last_error = None;
                        add_to_log(&mut self.network_log, "Relay connected!".to_string());
                    }
                }
                NetworkEvent::RelayError(err) => {
                    self.relay_connected = false;
                    self.last_error = Some(format!("Ошибка реле: {}", err));
                    add_to_log(&mut self.network_log, format!("Relay Error: {}", err));
                }
                NetworkEvent::NetworkError(err) => {
                    // Не показываем ошибки рукопожатия как критические, если мы уже в сети
                    if self.total_peers > 0 && (err.contains("authentication failed") || err.contains("compliance")) {
                        add_to_log(&mut self.network_log, format!("Заметка: {}", err));
                    } else {
                        self.last_error = Some(err.clone());
                        add_to_log(&mut self.network_log, format!("Net Error: {}", err));
                    }
                }
                NetworkEvent::ConnectionAttempt(msg) => {
                    self.last_attempt = Some(msg.clone());
                    add_to_log(&mut self.network_log, msg);
                }
                NetworkEvent::TotalPeers(count) => {
                    self.total_peers = count;
                }
                NetworkEvent::NatStatus(status) => {
                    self.nat_status = status;
                }
            }
        }

        egui::TopBottomPanel::bottom("status_bar")
            .resizable(false)
            .show(ctx, |ui| {
            ui.add_space(4.0);
            
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("СЕТЬ:").strong().small());
                    
                    // Статус Реле
                    let (status_text, color) = if self.relay_connected {
                        ("● ЗАРЕГИСТРИРОВАН (ДОСТУПЕН)", egui::Color32::from_rgb(100, 255, 100))
                    } else {
                        ("○ ПОИСК РЕЛЕ (ОЖИДАНИЕ...)", egui::Color32::from_rgb(255, 100, 100))
                    };
                    let resp = ui.label(egui::RichText::new(status_text).small().color(color));
                    if let Some(rid) = self.active_relay_id {
                        resp.on_hover_text(format!("Идентификатор реле:\n{}", rid));
                    }

                    ui.separator();

                    if self.total_peers > 0 {
                        ui.label(egui::RichText::new(format!("Активно: {} пир(ов)", self.total_peers)).small().color(egui::Color32::from_rgb(100, 255, 100)));
                    } else {
                        ui.label(egui::RichText::new("Поиск пиров...").small().weak());
                    }
                    
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).small().weak());
                    });
                });

                ui.add_space(2.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("Статус NAT: {}", self.nat_status)).small().weak());
                    ui.separator();
                    
                    if let Some(err) = &self.last_error {
                        let display_err = if err.len() > 70 { format!("{}...", &err[..67]) } else { err.clone() };
                        ui.label(egui::RichText::new(format!("Ошибка: {}", display_err)).small().color(egui::Color32::from_rgb(255, 150, 150)))
                          .on_hover_text(err);
                        if ui.link("Сбросить").clicked() {
                            self.last_error = None;
                        }
                    } else if let Some(attempt) = &self.last_attempt {
                        ui.label(egui::RichText::new(format!("Действие: {}", attempt)).small().weak().italics());
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(320.0)
            .min_width(250.0)
            .show(ctx, |ui| {
            ui.add_space(10.0);
            ui.vertical_centered(|ui| {
                ui.heading("P2P Messenger");
            });
            ui.add_space(20.0);

            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("ВАШ ПРОФИЛЬ").small().weak());
                    ui.label(egui::RichText::new(format!("ID: {}", &self.local_peer_id.to_string()[..12])).monospace());
                    if ui.button("📋 Копировать полный ID").clicked() {
                        ui.output_mut(|o| o.copied_text = self.local_peer_id.to_string());
                    }
                });
            });
            
            ui.add_space(15.0);
            ui.label(egui::RichText::new("ВАШИ АДРЕСА").small().weak());
            egui::ScrollArea::vertical().id_salt("addrs").max_height(200.0).show(ui, |ui| {
                for addr in &self.listen_addrs {
                    let full_addr = format!("{}/p2p/{}", addr, self.local_peer_id);
                    ui.horizontal(|ui| {
                        let addr_str = addr.to_string();
                        ui.label(egui::RichText::new(addr_str).monospace().small().color(egui::Color32::from_rgb(150, 255, 150)));
                        if ui.button("📎").on_hover_text("Копировать полный адрес").clicked() {
                            ui.output_mut(|o| o.copied_text = full_addr);
                        }
                    });
                }
            });

            ui.add_space(20.0);
            ui.label(egui::RichText::new("ПИРЫ В СЕТИ").small().weak());
            ui.separator();
            
            egui::ScrollArea::vertical().id_salt("peers").show(ui, |ui| {
                for (peer_id, info) in &self.peers {
                    ui.add_space(4.0);
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(format!("Peer {}", &peer_id.to_string()[..8])).strong());
                                if let Some(rtt) = info.rtt {
                                    ui.label(egui::RichText::new(format!("RTT: {:?}", rtt)).small().weak());
                                } else {
                                    ui.label(egui::RichText::new("Поиск маршрута...").small().italics());
                                }
                            });
                        });
                    });
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);
            ui.heading("Общение");
            ui.add_space(10.0);
            
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    let edit_width = (ui.available_width() - 130.0).max(0.0);
                    let res = ui.add(egui::TextEdit::singleline(&mut self.dial_address)
                        .hint_text("Вставьте /ip4/ или /dnsaddr/ адрес...")
                        .desired_width(edit_width));
                    
                    if ui.add_sized([100.0, 30.0], egui::Button::new("Соединить")).clicked() || (res.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter))) {
                        let _ = self.command_tx.try_send(UICommand::Dial(self.dial_address.clone()));
                        self.dial_address.clear();
                    }
                });
            });

            ui.add_space(20.0);
            
            // Основная область (логотип и приветствие)
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.label(egui::RichText::new("📡").size(64.0));
                ui.heading("Сервис глобальной связи активен");
                ui.label(egui::RichText::new("Ищем маршруты через NAT...").weak());
            });

            ui.add_space(20.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("СОБЫТИЯ СЕТИ").small().strong().weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🗑 Очистить").clicked() {
                        self.network_log.clear();
                    }
                });
            });
            
            // Лог занимает все оставшееся пространство
            egui::ScrollArea::vertical()
                .id_salt("net_log")
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    for entry in &self.network_log {
                        ui.add(egui::Label::new(egui::RichText::new(entry).small().weak()).wrap());
                    }
                });
        });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Настройка логирования: принудительно INFO, если не задано иное
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,libp2p=info,libp2p_relay=debug,p2p_messenger=debug"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
    
    tracing::info!("--- ЗАПУСК ПРИЛОЖЕНИЯ ---");

    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    let (event_tx, event_rx) = mpsc::channel(100);
    let (command_tx, mut command_rx) = mpsc::channel(100);

    let rt = tokio::runtime::Runtime::new()?;
    rt.spawn(async move {
        // 1. Создаем релей-клиент
        let (relay_transport, relay_client) = relay::client::new(local_peer_id);

        // 2. Строим транспорт вручную для максимальной гибкости
        let transport = {
            let tcp = tcp::tokio::Transport::new(tcp::Config::default());
            let quic = libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(&local_key));
            let ws = libp2p::websocket::Config::new(tcp::tokio::Transport::new(tcp::Config::default()));
            
            let base_transport = tcp
               .or_transport(ws)
               .or_transport(relay_transport)
               .upgrade(libp2p::core::upgrade::Version::V1)
               .authenticate(noise::Config::new(&local_key).unwrap())
               .multiplex(yamux::Config::default())
               .timeout(Duration::from_secs(60))
               .map(|(p, c), _| (p, libp2p::core::muxing::StreamMuxerBox::new(c)))
               .boxed();

            base_transport
               .or_transport(quic.map(|(p, c), _| (p, libp2p::core::muxing::StreamMuxerBox::new(c))).boxed())
               .map(|either, _| match either {
                   libp2p::futures::future::Either::Left((p, m)) => (p, m),
                   libp2p::futures::future::Either::Right((p, m)) => (p, m),
               })
               .boxed()
        };

        // 3. Используем DNS для всей связки
        let dns_transport = libp2p::dns::tokio::Transport::system(transport).expect("Ошибка создания DNS-транспорта").boxed();

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_other_transport(|_| dns_transport).expect("Ошибка конфигурации Swarm транспорта")
            .with_behaviour(|key: &libp2p::identity::Keypair| {
                let local_peer_id = key.public().to_peer_id();
                Ok(MyBehaviour {
                    ping: ping::Behaviour::default(),
                    mdns: mdns::tokio::Behaviour::new(
                        mdns::Config::default(),
                        local_peer_id,
                    ).expect("Не удалось запустить mDNS (проверьте права доступа к сети)"),
                    kad: kad::Behaviour::new(
                        local_peer_id,
                        kad::store::MemoryStore::new(local_peer_id),
                    ),
                    identify: identify::Behaviour::new(identify::Config::new(
                        "/p2p-messenger/1.0.0".to_string(),
                        key.public(),
                    )),
                    relay_client,
                    dcutr: dcutr::Behaviour::new(local_peer_id),
                    autonat: autonat::Behaviour::new(local_peer_id, autonat::Config::default()),
                    upnp: upnp::tokio::Behaviour::default(),
                })
            }).unwrap()
            .with_swarm_config(|c: libp2p::swarm::Config| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Слушаем TCP и QUIC
        if let Err(e) = swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()) {
            tracing::error!("Ошибка прослушивания TCP: {}", e);
        }
        if let Err(e) = swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap()) {
            tracing::error!("Ошибка прослушивания QUIC: {}", e);
        }
        
        // Радикально расширенный список публичных реле и бутстрап-узлов для обхода блокировок
        let public_relays = [
            // --- Cloudflare / DigitalOcean ---
            "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGv3nyYQYMj26wBXxeDzHkGb86u78YJms5S4F8N",
            "/ip4/104.236.179.241/tcp/4001/p2p/QmSoLP6zccNaTgnayRLneNFaQCLv969S7p7TCD36G3z3w",
            "/ip4/128.199.219.111/tcp/4001/p2p/QmSoLSafvU76un4MwvV9SWhpLAsC4D568fPKiT2tXfF9rI",
            
            // --- Linode ---
            "/ip4/139.178.91.71/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
            "/ip4/139.178.69.197/tcp/4001/p2p/QmSoLMeWqB7YGVL2ox6qAoYskTCvH4zUjXhS27E2H7M2V8",

            // --- Protocol Labs (WSS / TCP) ---
            "/ip4/147.75.109.213/tcp/443/wss/p2p/QmNnooDN2uYkB1DURgnzsE9qztqcS1Scy1uW91P98fXSDj",
            "/ip4/147.75.80.143/tcp/443/wss/p2p/QmQCU2EcNm3unvTMpe2Y5rS61hZ8v8z9tM5S1qU7U9zD",
            "/ip4/147.75.80.110/tcp/4001/p2p/QmbLHAnMo9UFnmWSznqreSTXpXGLmdYpY8pMUMfE6MqyS6",
        ];

        // Регистрация на реле и добавление в Kademlia
        for addr in public_relays {
            if let Ok(maddr) = addr.parse::<Multiaddr>() {
                if let Some(peer_id) = maddr.iter().find_map(|p| match p {
                    libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
                    _ => None,
                }) {
                    // ПРОВЕРКА: запрет на само-диалы и локальные адреса
                    if peer_id != local_peer_id && !is_local_addr(&maddr) {
                        // Добавляем в Kademlia
                        swarm.behaviour_mut().kad.add_address(&peer_id, maddr.clone());
                        
                        // Для гарантированных узлов сразу инициируем dial
                        let _ = swarm.dial(maddr);
                    }
                }
            }
        }

        // Ускоряем бутстрап до 15 секунд для более агрессивного поиска
        let mut bootstrap_interval = tokio::time::interval(Duration::from_secs(15));
        
        loop {
            tokio::select! {
                _ = bootstrap_interval.tick() => {
                    // Если нет активных соединений, пробуем переподключиться к реле
                    let connected_count = swarm.connected_peers().count();
                    if connected_count == 0 {
                        let _ = event_tx.send(NetworkEvent::ConnectionAttempt("Поиск узлов (периодический)...".to_string())).await;
                        for addr in public_relays {
                            if let Ok(maddr) = addr.parse::<Multiaddr>() {
                                // ПРОВЕРКА ПЕРЕД ДИАЛОМ
                                if !is_local_addr(&maddr) {
                                    let _ = swarm.dial(maddr);
                                }
                            }
                        }
                    }
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            tracing::info!(">>> НОВЫЙ АДРЕС ПРОСЛУШИВАНИЯ: {}", address);
                            let _ = event_tx.send(NetworkEvent::NewListenAddr(address)).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Ping(ping::Event { peer, result: Ok(rtt), .. })) => {
                            let _ = event_tx.send(NetworkEvent::PingResult { peer_id: peer, rtt }).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, multiaddr) in list {
                                if !is_local_addr(&multiaddr) {
                                    swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr);
                                    let _ = event_tx.send(NetworkEvent::PeerDiscovered(peer_id)).await;
                                }
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::RelayClient(event)) => {
                            match event {
                                relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } => {
                                    tracing::info!("Резервирование на реле {:?} подтверждено!", relay_peer_id);
                                    let _ = event_tx.send(NetworkEvent::RelayStatus { connected: true, relay_id: relay_peer_id }).await;
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            let is_relay = info.protocols.iter().any(|p| p.to_string().contains("/libp2p/relay/2.0.0/stop"));
                            
                            let _ = event_tx.send(NetworkEvent::IdentifyReceived { 
                                peer_id, 
                                protocols: info.protocols.iter().map(|p| p.to_string()).collect() 
                            }).await;

                            for addr in info.listen_addrs {
                                // ФИЛЬТРАЦИЯ ЛОКАЛЬНЫХ АДРЕСОВ (защита от os error 10048)
                                if is_local_addr(&addr) {
                                    continue;
                                }
                                let addr_str = addr.to_string();

                                swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                
                                // Формируем адрес для прослушивания через реле корректно
                                if is_relay && !addr_str.contains("p2p-circuit") {
                                    // Адрес должен содержать PeerId реле ПЕРЕД /p2p-circuit
                                    let mut relay_addr = addr.clone();
                                    if !relay_addr.to_string().contains(&peer_id.to_string()) {
                                        relay_addr = relay_addr.with(libp2p::multiaddr::Protocol::P2p(peer_id));
                                    }
                                    let full_relay_addr = relay_addr.with(libp2p::multiaddr::Protocol::P2pCircuit);
                                    
                                    // Проверяем, не слушаем ли мы уже на этом реле
                                    let is_already_listening = swarm.listeners().any(|l: &Multiaddr| l.to_string().contains(&peer_id.to_string()));
                                    if !is_already_listening {
                                        tracing::info!("Попытка регистрации на реле: {}", full_relay_addr);
                                        let _ = swarm.listen_on(full_relay_addr);
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Autonat(autonat::Event::StatusChanged { old: _, new })) => {
                            let status = match new {
                                autonat::NatStatus::Public(addr) => format!("Публичный ({})", addr),
                                autonat::NatStatus::Private => "За NAT (Закрыт)".to_string(),
                                autonat::NatStatus::Unknown => "Определяется...".to_string(),
                            };
                            tracing::info!(">>> СТАТУС NAT ИЗМЕНЕН: {}", status);
                            let _ = event_tx.send(NetworkEvent::NatStatus(status)).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::RoutingUpdated { .. })) => {
                            let _ = event_tx.send(NetworkEvent::DhtUpdated).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(addr))) => {
                            tracing::info!("UPnP: New external address mapped: {}", addr);
                            let _ = event_tx.send(NetworkEvent::NewListenAddr(addr)).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Upnp(upnp::Event::GatewayNotFound)) => {
                            tracing::warn!("UPnP: Gateway not found (роутер не поддерживает или UPnP выключен)");
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Upnp(upnp::Event::NonRoutableGateway)) => {
                            tracing::warn!("UPnP: Gateway is not routable (вы за двойным NAT или у роутера нет внешнего IP)");
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Upnp(upnp::Event::ExpiredExternalAddr(addr))) => {
                            tracing::info!("UPnP: External address expired: {}", addr);
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            tracing::info!("+++ НОВОЕ СОЕДИНЕНИЕ: {:?} (через {:?})", peer_id, endpoint);
                            let _ = event_tx.send(NetworkEvent::TotalPeers(swarm.connected_peers().count())).await;
                            let _ = event_tx.send(NetworkEvent::PeerDiscovered(peer_id)).await;
                            let _ = event_tx.send(NetworkEvent::ConnectionAttempt(format!("Connected to {}", peer_id))).await;
                        }
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            tracing::info!("--- СОЕДИНЕНИЕ ЗАКРЫТО: {:?} (причина: {:?})", peer_id, cause);
                            let _ = event_tx.send(NetworkEvent::TotalPeers(swarm.connected_peers().count())).await;
                        }
                        SwarmEvent::ListenerError { listener_id, error } => {
                            tracing::error!("Ошибка слушателя {:?}: {}", listener_id, error);
                            let _ = event_tx.send(NetworkEvent::NetworkError(format!("Ошибка сети: {}", error))).await;
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            let err_str = error.to_string();
                            
                            // Игнорируем специфические для Windows ошибки занятых портов при массовом сканировании
                            if err_str.contains("10048") || err_str.contains("10049") {
                                tracing::debug!("Игнорируемая сетевая заминка: {}", err_str);
                                return;
                            }

                            let msg = if let Some(peer) = peer_id {
                                format!("Ошибка к {:?}: {}", peer, error)
                            } else {
                                format!("Ошибка: {}", error)
                            };
                            
                            tracing::warn!("{}", msg);
                            
                            // Не забиваем основной статус мелкими ошибками, если мы уже подключены
                            let swarm_peers = swarm.connected_peers().count();
                            if swarm_peers < 3 {
                                let _ = event_tx.send(NetworkEvent::ConnectionAttempt(msg.clone())).await;
                            } else {
                                // Просто пишем в лог без обновления статуса
                                let _ = event_tx.send(NetworkEvent::ConnectionAttempt(format!("Диалог: {}", msg))).await;
                            }
                            
                            // Только если это один из наших бутстрап-реле И ошибка касается именно связи с ним
                            let is_bootstrap = if let Some(pid) = peer_id {
                                public_relays.iter().any(|r| r.contains(&pid.to_string()))
                            } else {
                                false
                            };

                            if is_bootstrap && !err_str.contains("p2p-circuit") {
                                // Если мы НЕ МОЖЕМ достучаться до самого реле
                                tracing::error!("!!! КРИТИЧЕСКАЯ ОШИБКА РЕЛЕ-УЗЛА {:?}: {}", peer_id, err_str);
                                let _ = event_tx.send(NetworkEvent::RelayError(msg)).await;
                            } else if is_bootstrap && err_str.contains("p2p-circuit") {
                                // Ошибка при попытке пройти ЧЕРЕЗ реле к кому-то другому
                                tracing::warn!("Заметка: транзит через реле не удался ({:?}): {}", peer_id, err_str);
                                add_to_log_tx(&event_tx, format!("Транзит (реле): {}", msg)).await;
                            }
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            tracing::debug!("Ошибка входящего соединения: {}", error);
                        }
                        SwarmEvent::Dialing { peer_id, .. } => {
                            if let Some(peer) = peer_id {
                                tracing::info!(">>> ПОПЫТКА ПОДКЛЮЧЕНИЯ К: {:?}", peer);
                                let _ = event_tx.send(NetworkEvent::ConnectionAttempt(format!("Подключение к {:?}...", peer))).await;
                            }
                        }
                        _ => {}
                    }
                }
                command = command_rx.recv() => {
                    if let Some(UICommand::Dial(addr)) = command {
                        if let Ok(multiaddr) = addr.trim().parse::<Multiaddr>() {
                            if !is_local_addr(&multiaddr) {
                                let _ = swarm.dial(multiaddr.clone());
                            }
                            if let Some(peer_id) = multiaddr.iter().find_map(|p| match p {
                                libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
                                _ => None,
                            }) {
                                swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr);
                                swarm.behaviour_mut().kad.bootstrap().ok();
                            }
                        }
                    }
                }
            }
        }
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "P2P Messenger",
        options,
        Box::new(move |cc| Ok(Box::new(P2pApp::new(cc, local_peer_id, command_tx, event_rx)))),
    ).map_err(|e| Box::new(e) as Box<dyn Error>)?;

    Ok(())
}
