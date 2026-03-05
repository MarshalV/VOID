import sys
import os

file_path = r'c:\Users\banda\Desktop\VOID\p2p-messenger\src\main.rs'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Фикс 1: Убираем себя из списка контактов
if 'fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {' in content:
    content = content.replace(
        'fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {',
        'fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {\n        self.known_peers.remove(&self.local_peer_id); // ФИКС САМО-ЧАТА'
    )

# Фикс 2: Усиливаем ловлю ошибок версии
if 'let err_lower = error.to_string().to_lowercase();' in content:
    content = content.replace(
        'let err_lower = error.to_string().to_lowercase();',
        'let err_lower = error.to_string().to_lowercase();\n                            if err_lower.contains("negotiat") || err_lower.contains("protocol") || err_lower.contains("version") {\n                                println!("❌ [ВНИМАНИЕ] Несовпадение версий с {}.", peer_id);\n                                let _ = event_tx.send(NetworkEvent::Status(format!("❌ ПИР {} УСТАРЕЛ!", &peer_id.to_string()[..8]))).await;\n                                return;\n                            }'
    )

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("PATCH V3 APPLIED")
鼓,Complexity:1,Description:
