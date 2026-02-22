use anyhow::Result;
use eframe::egui;
use futures::StreamExt;
use libp2p::{
    identify, kad, mdns, noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId,
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
        // Настройка визуального стиля (темная тема)
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

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
        // Обработка входящих событий от сети
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::NewListenAddr(addr) => self.listen_addrs.push(addr),
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

        // Боковая панель
        egui::SidePanel::left("left_panel").show(ctx, |ui| {
            ui.heading("P2P Messenger");
            ui.separator();

            ui.label(format!("Ваш ID:"));
            ui.small(self.local_peer_id.to_string());
            
            ui.separator();
            ui.label("Ваши адреса (нажмите, чтобы скопировать):");
            for addr in &self.listen_addrs {
                let full_addr = format!("{}/p2p/{}", addr, self.local_peer_id);
                if ui.button(full_addr.clone()).on_hover_text("Нажмите, чтобы скопировать").clicked() {
                    ui.output_mut(|o| o.copied_text = full_addr);
                }
            }

            ui.separator();
            ui.heading("Пиры в сети");
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (peer_id, info) in &self.peers {
                    ui.group(|ui| {
                        ui.label(format!("Peer: {}", &peer_id.to_string()[..8]));
                        if let Some(rtt) = info.rtt {
                            ui.label(format!("Ping: {:?}", rtt));
                        }
                    });
                }
            });
        });

        // Центральная панель
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Управление");
            
            ui.horizontal(|ui| {
                ui.label("Подключиться к адресу:");
                ui.text_edit_singleline(&mut self.dial_address);
                if ui.button("Подключиться").clicked() {
                    let _ = self.command_tx.try_send(UICommand::Dial(self.dial_address.clone()));
                }
            });

            ui.separator();
            ui.label("Тут будет история сообщений в следующей фазе...");
        });

        // Постоянное обновление кадра для получения событий
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

    // Запуск сетевого слоя в отдельном рантайме tokio
    let rt = tokio::runtime::Runtime::new()?;
    rt.spawn(async move {
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            ).unwrap()
            .with_behaviour(|key| {
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
                })
            }).unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

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
                            let _ = event_tx.send(NetworkEvent::IdentifyReceived { 
                                peer_id, 
                                protocols: info.protocols.into_iter().map(|p| p.to_string()).collect() 
                            }).await;
                            for addr in info.listen_addrs {
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::RoutingUpdated { .. })) => {
                            let _ = event_tx.send(NetworkEvent::DhtUpdated).await;
                        }
                        _ => {}
                    }
                }
                command = command_rx.recv() => {
                    if let Some(UICommand::Dial(addr)) = command {
                        if let Ok(multiaddr) = addr.parse::<Multiaddr>() {
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

    // Запуск GUI в главном потоке
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "P2P Messenger",
        options,
        Box::new(move |cc| Ok(Box::new(P2pApp::new(cc, local_peer_id, command_tx, event_rx)))),
    ).map_err(|e| Box::new(e) as Box<dyn Error>)?;

    Ok(())
}
