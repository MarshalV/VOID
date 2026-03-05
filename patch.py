import sys
import os

file_path = r'c:\Users\banda\Desktop\VOID\p2p-messenger\src\main.rs'
if not os.path.exists(file_path):
    print(f"Error: {file_path} not found")
    sys.exit(1)

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Part 1: Fix App::update (remove self from known_peers)
old_update = '    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {'
new_update = '    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {\n        // Убираем себя из списка контактов\n        self.known_peers.remove(&self.local_peer_id);'
if old_update in content and 'self.known_peers.remove' not in content:
    content = content.replace(old_update, new_update)

# Part 2: Fix IncomingConnection check (port 64000)
old_port = 'if s_addr.contains("64000") {'
new_port = 'if s_addr.contains("64000") || s_addr.contains(":64000") {'
content = content.replace(old_port, new_port)

# Part 3: Fix Identify error handling (version mismatch)
old_identify = '                            if err_str.contains("NegotiationFailed") {'
new_identify = '                            let err_lower = error.to_string().to_lowercase();\n                            if err_lower.contains("negotiat") || err_lower.contains("failed to negotiate") || err_lower.contains("support") {'
content = content.replace(old_identify, new_identify)

# Part 4: Fix window title
old_title = '"VOID P2P Chat"'
new_title = '&format!("VOID Chat [{}]", local_peer_id.to_string()[..8].to_string())'
if old_title in content:
    content = content.replace(old_title, new_title)

# Part 5: Fix Peer prefix to 8 chars (ensure it's done correctly)
content = content.replace('format!("Peer_{}", &peer.to_string()[..4])', 'format!("Peer_{}", &peer.to_string()[..8])')

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Patch applied successfully")
