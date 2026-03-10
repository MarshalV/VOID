import sys
import os

file_path = r'c:\Users\banda\Desktop\VOID\p2p-messenger\src\main.rs'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Part 1: DialPeer handler
# Find the block:
#                              UICommand::DialPeer(peer_id, addrs) => {
#                                  let short = &peer_id.to_string()[..16];
#                                  ...
#                              }

old_dial_peer = """                              UICommand::DialPeer(peer_id, addrs) => {
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
                              }"""

new_dial_peer = """                             UICommand::DialPeer(peer_id, addrs) => {
                                 let short = &peer_id.to_string()[..8];
                                 // Добавляем адреса в Kad перед дозвоном
                                 for addr in addrs {
                                     swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                                 }

                                 let opts = DialOpts::peer_id(peer_id)
                                     .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                                     .build();

                                 if let Err(e) = swarm.dial(opts) {
                                     match e {
                                         libp2p::swarm::DialError::DialPeerConditionFalse(_) => {
                                             // Игнорируем: это значит, что мы уже подключены или в процессе
                                         }
                                         _ => {
                                             println!("❌ Dial ERROR для {}: {:?}", short, e);
                                         }
                                     }
                                 }
                             }"""

if old_dial_peer in content:
    content = content.replace(old_dial_peer, new_dial_peer)
    print("Renamed and silenced DialPeer handler.")
else:
    # Try with slightly different indentation if it fails
    print("Could not find exact DialPeer handler block.")

# Part 2: OutgoingConnectionError handler
old_oce = """                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            let peer_str = peer_id
                                .map(|p| format!("{}...", &p.to_string()[..8]))
                                .unwrap_or_else(|| "?".into());

                            let err_str = error.to_string();
                            // Игнорируем технический шум (DNS, Handshake, Timeout)
                            let is_noise = err_str.contains("64000") ||
                                          err_str.contains("HandshakeTimedOut") ||
                                          err_str.contains("Timeout") ||
                                          err_str.contains("No Matching Records Found") ||
                                          err_str.contains("ResolveError");

                            if !is_noise {
                                println!("❌ ОШИБКА ИСХОДЯЩЕГО СОЕДИНЕНИЯ (peer: {}): {:?}", peer_str, error);
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ Не удалось подключиться к {}: {}", peer_str, error)
                                )).await;
                            }

                            if let Some(p) = peer_id {
                                pending_dials.remove(&p);
                            }
                        }"""

new_oce = """                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            let peer_str = peer_id
                                .map(|p| format!("{}...", &p.to_string()[..8]))
                                .unwrap_or_else(|| "?".into());

                            let err_str = error.to_string();
                            // Игнорируем технический шум (DNS, Handshake, Timeout, AddrInUse, ConditionFalse)
                            let is_noise = err_str.contains("64000") ||
                                          err_str.contains("HandshakeTimedOut") ||
                                          err_str.contains("Timeout") ||
                                          err_str.contains("No Matching Records Found") ||
                                          err_str.contains("ResolveError") ||
                                          err_str.contains("10048") || // AddrInUse on Windows
                                          err_str.contains("DialPeerConditionFalse");

                            if !is_noise {
                                println!("❌ ОШИБКА ИСХОДЯЩЕГО СОЕДИНЕНИЯ (peer: {}): {:?}", peer_str, error);
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ Не удалось подключиться к {}: {}", peer_str, error)
                                )).await;
                            }

                            if let Some(p) = peer_id {
                                pending_dials.remove(&p);
                            }
                        }"""

if old_oce in content:
    content = content.replace(old_oce, new_oce)
    print("Updated OutgoingConnectionError handler.")
else:
    print("Could not find exact OutgoingConnectionError handler block.")

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
鼓,Complexity:1,Description:
