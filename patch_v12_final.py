import os

path = r"c:\Users\banda\Desktop\VOID\p2p-messenger\src\main.rs"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

new_lines = []
skip_dial = 0
for i, line in enumerate(lines):
    if skip_dial > 0:
        skip_dial -= 1
        continue
    
    # Fix DialPeer (Lines 1167-1183 aprox)
    if "UICommand::DialPeer(peer_id, addrs) => {" in line:
        indent = line[:line.find("UICommand")]
        new_lines.append(f"{indent}UICommand::DialPeer(peer_id, addrs) => {{\n")
        new_lines.append(f"{indent}    let short = &peer_id.to_string()[..8];\n")
        new_lines.append(f"{indent}    for addr in addrs {{\n")
        new_lines.append(f"{indent}        swarm.behaviour_mut().kad.add_address(&peer_id, addr);\n")
        new_lines.append(f"{indent}    }}\n")
        new_lines.append(f"{indent}    let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)\n")
        new_lines.append(f"{indent}        .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)\n")
        new_lines.append(f"{indent}        .build();\n")
        new_lines.append(f"{indent}    if let Err(e) = swarm.dial(opts) {{\n")
        new_lines.append(f"{indent}        match e {{\n")
        new_lines.append(f"{indent}            libp2p::swarm::DialError::DialPeerConditionFalse(_) => {{}}\n")
        new_lines.append(f"{indent}            _ => println!(\"❌ Dial ERROR для {{}}: {{:?}}\", short, e),\n")
        new_lines.append(f"{indent}        }}\n")
        new_lines.append(f"{indent}    }}\n")
        new_lines.append(f"{indent}}}\n")
        
        # Skip original block until its closing brace (approx 16 lines)
        j = i + 1
        while j < len(lines) and "UICommand::SendMessage" not in lines[j]:
            j += 1
            skip_dial += 1
        continue

    # Fix OutgoingConnectionError noise filter
    if "// Игнорируем технический шум (DNS, Handshake, Timeout)" in line:
        new_lines.append(line)
        # Replacing the next lines
        new_lines.append("                            let is_noise = err_str.contains(\"64000\") ||\n")
        new_lines.append("                                          err_str.contains(\"HandshakeTimedOut\") ||\n")
        new_lines.append("                                          err_str.contains(\"Timeout\") ||\n")
        new_lines.append("                                          err_str.contains(\"No Matching Records Found\") ||\n")
        new_lines.append("                                          err_str.contains(\"ResolveError\") ||\n")
        new_lines.append("                                          err_str.contains(\"10048\") ||\n")
        new_lines.append("                                          err_str.contains(\"DialPeerConditionFalse\");\n")
        skip_dial = 5 # Skip original is_noise definition
        continue

    # Fix Unused warning
    if "let err_str = error.to_string();" in line and i > 1450:
        new_lines.append(line.replace("let err_str", "let _err_str"))
        continue

    new_lines.append(line)

with open(path, "w", encoding="utf-8") as f:
    f.writelines(new_lines)
print("PATCH V12 FINAL APPLIED")
鼓,Complexity:1,Description:
