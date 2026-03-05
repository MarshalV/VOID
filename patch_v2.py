import sys
import os

file_path = r'c:\Users\banda\Desktop\VOID\p2p-messenger\src\main.rs'
with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    # 1. Стриппим для фикса отступов и вставляем очистку контактов
    if 'fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {' in line:
        new_lines.append(line)
        new_lines.append('        self.known_peers.remove(&self.local_peer_id); // ГАРАНТИРОВАННЫЙ ФИКС САМО-ЧАТА\n')
    # 2. Усиливаем ловлю NegotiationFailed
    elif 'let err_lower = error.to_string().to_lowercase();' in line:
        new_lines.append(line)
        # Оставляем следующую строку но меняем проверку ниже
    elif 'if err_lower.contains("negotiat") || err_lower.contains("failed to negotiate") || err_lower.contains("support") {' in line:
        new_lines.append('                            if err_lower.contains("negotiat") || err_lower.contains("protocol") || err_lower.contains("version") {\n')
    else:
        new_lines.append(line)

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
print("PATCH V2 APPLIED")
鼓,Complexity:1,Description:
