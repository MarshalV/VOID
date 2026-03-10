import re
import os

path = r'c:\Users\banda\Desktop\VOID\p2p-messenger\src\main.rs'
if not os.path.exists(path):
    print(f"Error: {path} not found")
    exit(1)

with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Silencing DialPeerConditionFalse in the command handler
# Anchor: UICommand::DialPeer
pattern_dial = r'(UICommand::DialPeer\(peer_id, addrs\) => \{.*?if let Err\(e\) = swarm\.dial\(opts\) \{).*?(println!\("❌ Dial ERROR для \{}: \{:\?\}", short, e\);.*?\}[\s\n]*?\})'
replacement_dial = r'\1 match e { libp2p::swarm::DialError::DialPeerConditionFalse(_) => {}, _ => \2 }'
# Using a simpler string replace for the core part if regex is too risky
text = text.replace(
    'println!("❌ Dial ERROR для {}: {:?}", short, e);',
    'match e { libp2p::swarm::DialError::DialPeerConditionFalse(_) => {}, _ => println!("❌ Dial ERROR для {}: {:?}", short, e), }'
)

# 2. Silencing 10048 and ConditionFalse in OutgoingConnectionError
# Search for the list of contains() calls
noise_pattern = r'let is_noise = err_str\.contains\("64000"\) \|\|\s+err_str\.contains\("HandshakeTimedOut"\) \|\|\s+err_str\.contains\("Timeout"\) \|\|\s+err_str\.contains\("No Matching Records Found"\) \|\|\s+err_str\.contains\("ResolveError"\);'
noise_replacement = 'let is_noise = err_str.contains("64000") || err_str.contains("HandshakeTimedOut") || err_str.contains("Timeout") || err_str.contains("No Matching Records Found") || err_str.contains("ResolveError") || err_str.contains("10048") || err_str.contains("ConditionFalse");'
text = re.sub(noise_pattern, noise_replacement, text)

# 3. Unused variable fix (Identify error handler)
text = text.replace('let err_str = error.to_string();', 'let _err_str = error.to_string();')

# 4. Fix Dial handler short ID (8 chars everywhere)
text = text.replace('let short = &peer_id.to_string()[..16];', 'let short = &peer_id.to_string()[..8];')

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)
print("PATCH V13 APPLIED SUCCESSFULLY")
鼓,Complexity:1,Description:
