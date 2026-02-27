use chrono;
use eframe::egui;
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise, ping,
    swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    sender: String,
    text: String,
    timestamp: String,
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
    SendMessage(String),
}

#[derive(NetworkBehaviour)]
struct ChatBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
}

struct App {
    local_peer_id: PeerId,
    listen_addrs: Vec<String>,
    connected_peers: usize,
    mesh_peers: usize,
    dial_address: String,
    chat_input: String,
    chat_messages: Vec<ChatMessage>,
    status_log: Vec<String>,
    command_tx: mpsc::Sender<UICommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
}

impl App {
    fn new(
        _cc: &eframe::CreationContext<'_>,
        local_peer_id: PeerId,
        command_tx: mpsc::Sender<UICommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
    ) -> Self {
        Self {
            local_peer_id,
            listen_addrs: Vec::new(),
            connected_peers: 0,
            mesh_peers: 0,
            dial_address: String::new(),
            chat_input: String::new(),
            chat_messages: Vec::new(),
            status_log: Vec::new(),
            command_tx,
            event_rx,
        }
    }

    fn add_status(&mut self, msg: String) {
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        self.status_log.push(format!("[{}] {}", ts, msg));
        if self.status_log.len() > 20 {
            self.status_log.remove(0);
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Обрабатываем все события из сети
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::NewListenAddr(addr) => {
                    let full = format!("{}/p2p/{}", addr, self.local_peer_id);
                    if !self.listen_addrs.contains(&full) {
                        self.add_status(format!("Слушаю: {}", addr));
                        self.listen_addrs.push(full);
                    }
                }
                NetworkEvent::MdnsDiscovered(peer, addr) => {
                    self.add_status(format!(
                        "🔍 Найден: {}... ({})",
                        &peer.to_string()[..8],
                        addr
                    ));
                }
                NetworkEvent::MdnsExpired(peer) => {
                    self.add_status(format!("⏳ Ушёл: {}...", &peer.to_string()[..8]));
                }
                NetworkEvent::Connected(peer) => {
                    self.connected_peers += 1;
                    self.add_status(format!("✅ Подключён: {}...", &peer.to_string()[..8]));
                }
                NetworkEvent::Disconnected(peer) => {
                    self.connected_peers = self.connected_peers.saturating_sub(1);
                    self.add_status(format!("❌ Отключён: {}...", &peer.to_string()[..8]));
                }
                NetworkEvent::MeshPeers(count) => {
                    self.mesh_peers = count;
                }
                NetworkEvent::ChatMessage(msg) => {
                    self.chat_messages.push(msg);
                }
                NetworkEvent::Status(msg) => {
                    self.add_status(msg);
                }
            }
        }

        // === ВЕРХНЯЯ ПАНЕЛЬ ===
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(
                    egui::RichText::new("VOID P2P Chat")
                        .color(egui::Color32::from_rgb(0, 255, 255)),
                );
                ui.separator();
                let color = if self.mesh_peers > 0 {
                    egui::Color32::GREEN
                } else if self.connected_peers > 0 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };
                ui.label(
                    egui::RichText::new(format!(
                        "Подключено: {}  |  В чате: {}",
                        self.connected_peers, self.mesh_peers
                    ))
                    .color(color)
                    .strong(),
                );
            });
            ui.add_space(6.0);
        });

        // === ЛЕВАЯ ПАНЕЛЬ ===
        egui::SidePanel::left("left")
            .min_width(320.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);

                // ID
                ui.horizontal(|ui| {
                    ui.label("Ваш ID:");
                    let id_short = &self.local_peer_id.to_string()[..16];
                    ui.label(egui::RichText::new(id_short).monospace().strong());
                    if ui
                        .button("📋")
                        .on_hover_text("Копировать полный ID")
                        .clicked()
                    {
                        ui.output_mut(|o| o.copied_text = self.local_peer_id.to_string());
                    }
                });

                ui.add_space(8.0);
                ui.separator();

                // ПОДКЛЮЧЕНИЕ
                ui.label(egui::RichText::new("➡ ПОДКЛЮЧИТЬСЯ К ПИРУ:").strong());
                ui.label(
                    egui::RichText::new("Вставьте адрес другого клиента")
                        .small()
                        .weak(),
                );
                ui.horizontal(|ui| {
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.dial_address)
                            .hint_text("/ip4/.../tcp/.../p2p/...")
                            .desired_width(ui.available_width() - 60.0),
                    );
                    if (ui.button("Join").clicked()
                        || (response.lost_focus()
                            && ctx.input(|i| i.key_pressed(egui::Key::Enter))))
                        && !self.dial_address.is_empty()
                    {
                        let _ = self
                            .command_tx
                            .try_send(UICommand::Dial(self.dial_address.clone()));
                        self.dial_address.clear();
                    }
                });

                ui.add_space(8.0);
                ui.separator();

                // ВАШИ АДРЕСА
                ui.label(egui::RichText::new("📋 ВАШИ АДРЕСА (скопируйте другу):").strong());
                egui::ScrollArea::vertical()
                    .id_salt("addrs")
                    .max_height(120.0)
                    .show(ui, |ui| {
                        if self.listen_addrs.is_empty() {
                            ui.label(egui::RichText::new("Ожидание...").weak());
                        }
                        for addr in &self.listen_addrs {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(addr).small().monospace());
                                if ui.button("📋").clicked() {
                                    ui.output_mut(|o| o.copied_text = addr.clone());
                                }
                            });
                        }
                    });

                ui.add_space(8.0);
                ui.separator();

                // СТАТУС
                ui.label(egui::RichText::new("📊 СТАТУС:").strong());
                egui::ScrollArea::vertical()
                    .id_salt("status")
                    .max_height(200.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for log in &self.status_log {
                            ui.label(egui::RichText::new(log).small().weak());
                        }
                    });
            });

        // === ЦЕНТРАЛЬНАЯ ПАНЕЛЬ — ЧАТ ===
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                if self.mesh_peers == 0 {
                    ui.label(
                        egui::RichText::new("⚠ Нет собеседников. Скопируйте адрес и отправьте другу, или вставьте его адрес в поле ПОДКЛЮЧИТЬСЯ.")
                            .color(egui::Color32::YELLOW),
                    );
                    ui.separator();
                }

                egui::ScrollArea::vertical()
                    .id_salt("chat")
                    .stick_to_bottom(true)
                    .max_height(ui.available_height() - 50.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for msg in &self.chat_messages {
                            let is_me = msg.sender == self.local_peer_id.to_string();
                            let color = if is_me {
                                egui::Color32::from_rgb(100, 255, 150)
                            } else {
                                egui::Color32::from_rgb(255, 215, 0)
                            };
                            let name = if is_me {
                                "Вы".to_string()
                            } else {
                                format!("{}...", &msg.sender[..6])
                            };
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("[{}] <{}>", msg.timestamp, name))
                                        .color(color)
                                        .monospace(),
                                );
                                ui.label(&msg.text);
                            });
                        }
                    });

                ui.separator();
                ui.horizontal(|ui| {
                    let res = ui.add(
                        egui::TextEdit::singleline(&mut self.chat_input)
                            .hint_text("Введите сообщение...")
                            .desired_width(ui.available_width() - 80.0),
                    );
                    if (ui.button("Отправить").clicked()
                        || (res.lost_focus()
                            && ctx.input(|i| i.key_pressed(egui::Key::Enter))))
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
    // Без логов — чистая консоль
    let _ = tracing_subscriber::fmt().with_env_filter("off").try_init();

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
            println!("Настраиваю файрвол Windows...");
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
                    "localport=64000",
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
                    "localport=64000",
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
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=TCP localport=64000 profile=any enable=yes\r\n\
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=UDP localport=64000 profile=any edge=yes enable=yes\r\n"
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

    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    println!("=== VOID P2P Chat ===");
    println!("Ваш Peer ID: {}", local_peer_id);

    let (event_tx, event_rx) = mpsc::channel(256);
    let (command_tx, mut command_rx) = mpsc::channel(256);

    let event_tx_clone = event_tx.clone();
    let command_tx_for_mdns = command_tx.clone(); // для delayed dial из mDNS

    tokio::spawn(async move {
        let event_tx = event_tx_clone;
        let command_tx_for_mdns = command_tx_for_mdns;

        // Swarm: TCP + QUIC (UDP) + noise + yamux
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_quic()
            .with_behaviour(|key| {
                let local_peer_id = key.public().to_peer_id();

                // Gossipsub: работает даже с 1 пиром
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Permissive)
                    .mesh_n_low(1)
                    .mesh_n(2)
                    .mesh_n_high(4)
                    .build()
                    .unwrap();

                Ok(ChatBehaviour {
                    gossipsub: gossipsub::Behaviour::new(
                        gossipsub::MessageAuthenticity::Signed(key.clone()),
                        gossipsub_config,
                    )
                    .unwrap(),
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                        .unwrap(),
                    ping: ping::Behaviour::default(),
                })
            })
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
            .build();

        // Подписываемся на топик
        let topic = gossipsub::IdentTopic::new("void-chat-v1");
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

        // Слушаем TCP и QUIC (UDP) на фиксированном порту 64000
        swarm
            .listen_on("/ip4/0.0.0.0/tcp/64000".parse().unwrap())
            .unwrap();
        swarm
            .listen_on("/ip4/0.0.0.0/udp/64000/quic-v1".parse().unwrap())
            .unwrap();

        let _ = event_tx
            .send(NetworkEvent::Status(
                "🚀 Запущен. Ищу пиров через mDNS...".into(),
            ))
            .await;

        let mut mesh_check = tokio::time::interval(Duration::from_secs(5));
        // Кэш адресов для mDNS: пир → все его адреса (TCP + QUIC)
        let mut peer_addrs: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        // Пиры, к которым уже запущен или идёт dial (избегаем дубликат)
        let mut pending_dials: HashSet<PeerId> = HashSet::new();

        loop {
            tokio::select! {
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
                                // Delayed mDNS dial — пришёл из tokio::spawn после задержки
                                if swarm.is_connected(&peer_id) {
                                    pending_dials.remove(&peer_id);
                                } else {
                                    let short = &peer_id.to_string()[..16];
                                    match swarm.dial(
                                        DialOpts::peer_id(peer_id)
                                            .addresses(addrs.clone())
                                            .build()
                                    ) {
                                        Ok(_) => {
                                            let _ = event_tx.send(NetworkEvent::Status(
                                                format!("📞 Подключаюсь к {}... ({} адресов)", short, addrs.len())
                                            )).await;
                                        }
                                        Err(e) => {
                                            pending_dials.remove(&peer_id);
                                            let err_str = e.to_string();
                                            if !err_str.contains("Pending") && !err_str.contains("already") {
                                                let _ = event_tx.send(NetworkEvent::Status(
                                                    format!("❌ dial ошибка: {}", e)
                                                )).await;
                                            }
                                        }
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
                                match swarm.behaviour_mut().gossipsub.publish(topic.clone(), json) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        let _ = event_tx.send(NetworkEvent::Status(
                                            format!("❌ Не удалось отправить: {:?}", e)
                                        )).await;
                                    }
                                }
                                // Показываем своё сообщение в чате
                                let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                            }
                        }
                    }
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            let s = address.to_string();
                            // Только IPv4, не 0.0.0.0, не 127.0.0.1
                            if !s.contains("/ip6/") && !s.contains("/0.0.0.0") && !s.contains("/127.0.0.1") {
                                println!("Слушаю: {}/p2p/{}", address, local_peer_id);
                                let _ = event_tx.send(NetworkEvent::NewListenAddr(address)).await;
                            }
                        }

                        // === mDNS: автоматическое обнаружение в локальной сети ===
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                            let mut to_dial: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
                            for (peer_id, addr) in peers {
                                if peer_id == local_peer_id { continue; }
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

                                // Стратегия Leader/Follower:
                                // Пир с меньшим ID (leader) dial-ит почти сразу (200ms).
                                // Пир с большим ID (follower) ждёт 4 секунды и dial-ит только если не подключился.
                                // Это гарантирует, что Windows Firewall не увидит "одновременный" dial.
                                let is_leader = local_peer_id.to_string() < peer_id.to_string();
                                let delay_ms = if is_leader { 200 } else { 4000 };

                                pending_dials.insert(peer_id);
                                let cmd_tx2 = command_tx_for_mdns.clone();
                                let dial_addrs = all_addrs.clone();
                                let tx = event_tx.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                    let type_str = if is_leader { "Leader" } else { "Follower" };
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

                        // === Gossipsub: входящие сообщения ===
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                            if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&message.data) {
                                let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                            let _ = event_tx.send(NetworkEvent::Status(
                                format!("📡 {}... присоединился к чату ({})", &peer_id.to_string()[..8], topic)
                            )).await;
                        }

                        // === Соединения ===
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            println!("Подключён: {}", peer_id);
                            pending_dials.remove(&peer_id);
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            let mesh = swarm.behaviour().gossipsub.all_mesh_peers().count();
                            let _ = event_tx.send(NetworkEvent::Connected(peer_id)).await;
                            let _ = event_tx.send(NetworkEvent::MeshPeers(mesh)).await;
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            let mesh = swarm.behaviour().gossipsub.all_mesh_peers().count();
                            let _ = event_tx.send(NetworkEvent::Disconnected(peer_id)).await;
                            let _ = event_tx.send(NetworkEvent::MeshPeers(mesh)).await;
                        }

                        // === Ошибки соединений ===
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            let peer_str = peer_id
                                .map(|p| format!("{}...", &p.to_string()[..8]))
                                .unwrap_or_else(|| "?".into());
                            // Очищаем pending_dials — без этого mDNS не сможет повторить
                            if let Some(p) = peer_id {
                                pending_dials.remove(&p);
                                peer_addrs.remove(&p); // сброс: при следующем mDNS попробуем свежие адреса
                            }
                            let _ = event_tx.send(NetworkEvent::Status(
                                format!("❌ Не удалось подключиться к {}: {}", peer_str, error)
                            )).await;
                            println!("Ошибка подключения к {}: {}", peer_str, error);
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            // Молча игнорируем входящие ошибки — это часто повторные попытки libp2p
                            let err_str = error.to_string();
                            if !err_str.contains("Handshake") && !err_str.contains("Timeout") {
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ Входящее подключение отклонено: {}", error)
                                )).await;
                            }
                        }

                        _ => {}
                    }
                }
            }
        }
    });

    eframe::run_native(
        "VOID P2P Chat",
        eframe::NativeOptions::default(),
        Box::new(move |cc| Ok(Box::new(App::new(cc, local_peer_id, command_tx, event_rx)))),
    )
    .map_err(|e| Box::new(e) as Box<dyn Error>)
}
