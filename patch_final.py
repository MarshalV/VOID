import sys
import os

file_path = r'c:\Users\banda\Desktop\VOID\p2p-messenger\src\main.rs'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Part 1: Fix App::update (remove self from known_peers)
# We find the update function and insert the remove call right after the opening brace
target1 = 'fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {'
if target1 in content and 'self.known_peers.remove(&self.local_peer_id);' not in content:
    content = content.replace(target1, target1 + '\n        self.known_peers.remove(&self.local_peer_id); // Фикс само-сообщений')
    print("Part 1 matched")

# Part 2: Fix Identify error handling
# We make it super broad to catch ANY negotiation failure
target2 = 'let err_lower = error.to_string().to_lowercase();'
new_identify_block = '''                            let err_str = error.to_string();
                            if err_str.contains("Negotiation") || err_str.contains("protocol") || err_str.contains("not supported") {
                                println!("❌ [КРИТИЧНО] Identify: Несовпадение версий с {}.", peer_id);
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ ВЕРСИЯ ПИРА {}... УСТАРЕЛА!", &peer_id.to_string()[..8])
                                )).await;
                            } else {'''
# We find the start of the identify error block and replace it
if target2 in content:
    # Find the line before it
    import re
    search_pattern = r'let err_str = error\.to_string\(\);\s+let err_lower = error\.to_string\(\)\.to_lowercase\(\);\s+if err_lower\.contains\("negotiat"\) \|\| err_lower\.contains\("failed to negotiate"\) \|\| err_lower\.contains\("support"\) \{\s+println!\("❌ \[КРИТИЧНО\] Identify: Несовпадение версий с \{\}\.", peer_id\);\s+println!\("🔥 Срочно ОБНОВИТЕ другое приложение и ЗАКРОЙТЕ старые процессы!"\);\s+let _ = event_tx\.send\(NetworkEvent::Status\(\s+format!\("❌ ОШИБКА: Пир \{\}\.\.\. использует СТАРУЮ ВЕРСИЮ!", &peer_id\.to_string\(\)\[\.\.8\]\)\s+\)\)\.await;\s+\} else \{'
    content = re.sub(search_pattern, new_identify_block, content, flags=re.DOTALL)
    print("Part 2 matched (RE)")

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Patch applied")
鼓,Complexity:1,Description:
