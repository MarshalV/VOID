use libp2p::{PeerId, SwarmBuilder, noise, tcp, yamux};
use std::error::Error;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let _swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()
        .await?
        .with_websocket(noise::Config::new, yamux::Config::default)
        .await?
        .with_behaviour(|_| libp2p::ping::Behaviour::default())?
        .build();
    Ok(())
}
