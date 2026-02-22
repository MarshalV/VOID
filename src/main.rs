use anyhow::Result;
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

// Сообщения от сетевого слоя к UI
enum NetworkEvent {
    NewListenAddr(Multiaddr),
    PeerDiscovered(PeerId),
    IdentifyReceived { peer_id: PeerId, protocols: Vec<String> },
    PingResult { peer_id: PeerId, rtt: Duration },
    DhtUpdated,
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
        }
    }
}

impl eframe::App for P2pApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::NewListenAddr(addr) => {
                    if !self.listen_addrs.contains(&addr) {
                        self.listen_addrs.push(addr);
                    }
                }
                NetworkEvent::PeerDiscovered(peer_id) => {
                    self.peers.entry(peer_id).or_insert(PeerInfo { rtt: None, protocols: Vec::new() });
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
            }
        }

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
                    let res = ui.add(egui::TextEdit::singleline(&mut self.dial_address)
                        .hint_text("Вставьте /ip4/ или /dnsaddr/ адрес...")
                        .desired_width(ui.available_width() - 120.0));
                    
                    if ui.add_sized([100.0, 30.0], egui::Button::new("Соединить")).clicked() || (res.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter))) {
                        let _ = self.command_tx.try_send(UICommand::Dial(self.dial_address.clone()));
                        self.dial_address.clear();
                    }
                });
            });

            ui.add_space(20.0);
            
            ui.vertical_centered(|ui| {
                ui.add_space(100.0);
                ui.label(egui::RichText::new("📡").size(60.0));
                ui.label(egui::RichText::new("Сервис глобальной связи активен").strong());
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Если вы в разных сетях, просто скопируйте свой адрес").weak());
                ui.label(egui::RichText::new("и передайте его через любой мессенджер.").weak());
                ui.label(egui::RichText::new("Технологии Relay и DCUtR помогут пробить NAT.").small().weak());
            });
        });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    let (event_tx, event_rx) = mpsc::channel(100);
    let (command_tx, mut command_rx) = mpsc::channel(100);

    let rt = tokio::runtime::Runtime::new()?;
    rt.spawn(async move {
        // Создаем релей-клиент до сборки Swarm
        let (relay_transport, relay_client) = relay::client::new(local_peer_id);

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            ).unwrap()
            .with_quic()
            .with_other_transport(|key| {
                relay_transport
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise::Config::new(key).unwrap())
                    .multiplex(yamux::Config::default())
                    .map(|(p, c), _| (p, libp2p::core::muxing::StreamMuxerBox::new(c)))
            }).unwrap()
            .with_dns().unwrap()
            .with_behaviour(|key: &libp2p::identity::Keypair| {
                let local_peer_id = key.public().to_peer_id();
                Ok(MyBehaviour {
                    ping: ping::Behaviour::default(),
                    mdns: mdns::tokio::Behaviour::new(
                        mdns::Config::default(),
                        local_peer_id,
                    ).unwrap(),
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

        // Слушаем TCP, QUIC и Relay
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap()).unwrap();
        
        // Расширенный список публичных реле-узлов
        let public_relays = [
            "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDN2uYkB1DURgnzsE9qztqcS1Scy1uW91P98fXSDj",
            "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcNm3unvTMpe2Y5rS61hZ8v8z9tM5S1qU7U9zD",
            "/ip4/147.75.109.213/tcp/4001/p2p/QmNnooDN2uYkB1DURgnzsE9qztqcS1Scy1uW91P98fXSDj",
            "/ip4/147.75.80.143/tcp/4001/p2p/QmQCU2EcNm3unvTMpe2Y5rS61hZ8v8z9tM5S1qU7U9zD",
        ];

        for addr in public_relays {
            if let Ok(maddr) = addr.parse::<Multiaddr>() {
                if let Some(peer_id) = maddr.iter().find_map(|p| match p {
                    libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
                    _ => None,
                }) {
                    swarm.behaviour_mut().kad.add_address(&peer_id, maddr.clone());
                    let _ = swarm.dial(maddr.clone());
                    // Пытаемся слушать через это реле
                    let listen_addr = maddr.with(libp2p::multiaddr::Protocol::P2pCircuit);
                    let _ = swarm.listen_on(listen_addr);
                }
            }
        }

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            let _ = event_tx.send(NetworkEvent::NewListenAddr(address)).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Ping(ping::Event { peer, result: Ok(rtt), .. })) => {
                            let _ = event_tx.send(NetworkEvent::PingResult { peer_id: peer, rtt }).await;
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, multiaddr) in list {
                                swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr);
                                let _ = event_tx.send(NetworkEvent::PeerDiscovered(peer_id)).await;
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            // Проверяем поддержку Relay Server ДО того, как переместим протоколы
                            let is_relay = info.protocols.iter().any(|p| p.to_string().contains("/libp2p/relay/2.0.0/stop"));
                            
                            let _ = event_tx.send(NetworkEvent::IdentifyReceived { 
                                peer_id, 
                                protocols: info.protocols.into_iter().map(|p| p.to_string()).collect() 
                            }).await;

                            for addr in info.listen_addrs {
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                if is_relay {
                                    let relay_addr = addr.with(libp2p::multiaddr::Protocol::P2pCircuit);
                                    let _ = swarm.listen_on(relay_addr);
                                }
                            }
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
                        _ => {}
                    }
                }
                command = command_rx.recv() => {
                    if let Some(UICommand::Dial(addr)) = command {
                        if let Ok(multiaddr) = addr.trim().parse::<Multiaddr>() {
                            let _ = swarm.dial(multiaddr.clone());
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
