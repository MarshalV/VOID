//! Весь код VOID P2P, отвечающий за отрисовку интерфейса (egui/eframe).
//!
//! Сюда вынесены: космическая палитра, helper'ы отрисовки (аватары,
//! starfield, chat-bg), toast-уведомления, подстройка стиля egui и полный
//! `impl eframe::App` (sidebar, шапка чата, лента сообщений, поле ввода).
//! Бизнес-логика (сеть, хранилище, retry) — в `app`, `network`, `vault`, `protocol`, `bootstrap`.

use eframe::egui;
use libp2p::PeerId;
use std::collections::hash_map::Entry;
use std::time::{Duration, Instant};
use tracing::warn;

use crate::{
    file_transfer, parse_seed_input, new_message_id, App, ChatMessage, FileTransferProgress,
    NetworkEvent, PendingSend, UICommand, RESEND_GRACE,
};

/// TTL для коротких системных toast'ов.
pub(crate) const TOAST_TTL_SHORT: Duration = Duration::from_secs(4);
/// TTL для важных уведомлений (ошибки доставки и т.п.).
pub(crate) const TOAST_TTL_LONG: Duration = Duration::from_secs(7);

/// Плавающее уведомление в правом верхнем углу.
pub(crate) struct Toast {
    pub(crate) text: String,
    pub(crate) expires_at: Instant,
    pub(crate) kind: ToastKind,
}

#[derive(Clone, Copy)]
pub(crate) enum ToastKind {
    Info,
    Warn,
    Error,
}

impl App {
    /// Лениво грузит `static/icon.png` в GPU-текстуру и возвращает её id.
    /// PNG вшит в бинарь, так что отдельный файл при запуске не нужен.
    fn ensure_chat_bg(&mut self, ctx: &egui::Context) -> Option<egui::TextureId> {
        if self.chat_bg_texture.is_none() {
            const BYTES: &[u8] = include_bytes!("../static/icon.png");
            match image::load_from_memory(BYTES) {
                Ok(img) => {
                    let rgba = img.to_rgba8();
                    let size = [rgba.width() as usize, rgba.height() as usize];
                    let pixels = rgba.into_raw();
                    let color_image =
                        egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                    let handle = ctx.load_texture(
                        "chat_bg_icon",
                        color_image,
                        egui::TextureOptions::LINEAR,
                    );
                    self.chat_bg_texture = Some(handle);
                }
                Err(e) => {
                    warn!(target: "void_net", "static/icon.png decode: {}", e);
                }
            }
        }
        self.chat_bg_texture.as_ref().map(|h| h.id())
    }

    /// Рендерит активные toast'ы как floating Area в правом верхнем углу,
    /// стопкой сверху вниз. Каждый toast — закруглённая «пилюля» с акцент-цветом
    /// слева и подписью.
    fn draw_toasts(&mut self, ctx: &egui::Context) {
        if self.toasts.is_empty() {
            return;
        }
        let screen = ctx.screen_rect();
        let anchor = egui::pos2(screen.right() - 16.0, screen.top() + 72.0);
        let now = Instant::now();

        for (i, t) in self.toasts.iter().enumerate() {
            // Прозрачность: плавное затухание в последнюю секунду жизни.
            let remaining = t.expires_at.saturating_duration_since(now).as_secs_f32();
            let alpha = (remaining.min(1.0) * 255.0).clamp(40.0, 255.0) as u8;
            let (accent, bg) = match t.kind {
                ToastKind::Info => (palette::ACCENT_2, palette::BG_CARD),
                ToastKind::Warn => (palette::ACCENT, palette::BG_CARD),
                ToastKind::Error => (
                    egui::Color32::from_rgb(0xff, 0x6a, 0x88),
                    palette::BG_CARD,
                ),
            };
            let accent = egui::Color32::from_rgba_unmultiplied(
                accent.r(),
                accent.g(),
                accent.b(),
                alpha,
            );
            let bg = egui::Color32::from_rgba_unmultiplied(bg.r(), bg.g(), bg.b(), alpha);

            egui::Area::new(egui::Id::new(("toast_area", i)))
                .order(egui::Order::Tooltip)
                .anchor(
                    egui::Align2::RIGHT_TOP,
                    egui::vec2(
                        anchor.x - screen.right(),
                        anchor.y - screen.top() + (i as f32) * 56.0,
                    ),
                )
                .interactable(false)
                .show(ctx, |ui| {
                    egui::Frame::none()
                        .fill(bg)
                        .stroke(egui::Stroke::new(1.0, accent))
                        .rounding(10.0)
                        .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                        .shadow(egui::epaint::Shadow {
                            offset: egui::vec2(0.0, 4.0),
                            blur: 18.0,
                            spread: 0.0,
                            color: egui::Color32::from_rgba_premultiplied(0, 0, 0, 120),
                        })
                        .show(ui, |ui| {
                            ui.set_max_width(360.0);
                            ui.horizontal(|ui| {
                                ui.painter().rect_filled(
                                    egui::Rect::from_min_size(
                                        ui.cursor().left_top(),
                                        egui::vec2(3.0, 18.0),
                                    ),
                                    1.5,
                                    accent,
                                );
                                ui.add_space(10.0);
                                ui.label(
                                    egui::RichText::new(&t.text)
                                        .size(13.0)
                                        .color(egui::Color32::from_rgba_unmultiplied(
                                            palette::TEXT.r(),
                                            palette::TEXT.g(),
                                            palette::TEXT.b(),
                                            alpha,
                                        )),
                                );
                            });
                        });
                });
        }
    }

    /// Кладёт toast в очередь рендера. Дубликаты с тем же текстом не накапливаем.
    pub(crate) fn push_toast(&mut self, text: String, kind: ToastKind, ttl: Duration) {
        if self.toasts.iter().any(|t| t.text == text) {
            return;
        }
        self.toasts.push(Toast {
            text,
            expires_at: Instant::now() + ttl,
            kind,
        });
    }

    // =====================================================================
    //  НОВЫЙ Telegram-подобный sidebar (космическая палитра)
    // =====================================================================
    fn ui_sidebar(&mut self, ui: &mut egui::Ui) {
        let avail = ui.available_width();

        // -------- Шапка профиля --------
        egui::Frame::none()
            .fill(palette::BG_PANEL)
            .inner_margin(egui::Margin {
                left: 16.0,
                right: 16.0,
                top: 16.0,
                bottom: 12.0,
            })
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    draw_avatar(
                        ui,
                        &self.local_peer_id.to_string(),
                        &self.local_nickname,
                        46.0,
                        Some(true),
                    );
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        let inner_w = (avail - 78.0).max(60.0);
                        ui.set_width(inner_w);
                        let nick_resp = ui.add(
                            egui::TextEdit::singleline(&mut self.local_nickname)
                                .desired_width(inner_w)
                                .frame(false)
                                .font(egui::TextStyle::Heading),
                        );
                        if nick_resp.lost_focus() {
                            self.persist_vault();
                        }
                        let pid = self.local_peer_id.to_string();
                        // Полный Peer ID: выделяется мышью (Ctrl+C работает штатно),
                        // переносится по ширине карточки, клик копирует всё целиком.
                        let r = ui.add(
                            egui::Label::new(
                                egui::RichText::new(&pid)
                                    .size(11.5)
                                    .monospace()
                                    .color(palette::TEXT_MUTED),
                            )
                            .wrap()
                            .selectable(true)
                            .sense(egui::Sense::click()),
                        )
                        .on_hover_text("Клик — копировать Peer ID целиком");
                        if r.clicked() {
                            ui.output_mut(|o| o.copied_text = pid.clone());
                            self.add_status("Скопирован Peer ID".into());
                        }
                        if let Some(ip) = &self.public_ip {
                            ui.label(
                                egui::RichText::new(format!("◐ {ip}"))
                                    .size(11.0)
                                    .color(palette::ACCENT_2),
                            );
                        }
                    });
                });
            });

        // -------- Поиск --------
        egui::Frame::none()
            .inner_margin(egui::Margin {
                left: 12.0,
                right: 12.0,
                top: 0.0,
                bottom: 8.0,
            })
            .show(ui, |ui| {
                let id = egui::Id::new("void_search_query");
                let mut buf: String =
                    ui.memory_mut(|m| m.data.get_temp::<String>(id).unwrap_or_default());
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut buf)
                        .hint_text("🔍   Поиск контактов")
                        .desired_width(f32::INFINITY),
                );
                if resp.changed() {
                    ui.memory_mut(|m| m.data.insert_temp(id, buf.clone()));
                }
            });

        // тонкий разделитель
        let sep_rect = ui
            .allocate_space(egui::vec2(ui.available_width(), 1.0))
            .1;
        ui.painter().rect_filled(sep_rect, 0.0, palette::DIVIDER);

        // -------- Список контактов --------
        let search: String = ui
            .memory(|m| m.data.get_temp::<String>(egui::Id::new("void_search_query")))
            .unwrap_or_default()
            .to_lowercase();

        // Резервируем низ сидебара под кнопку «Системная консоль»:
        // ScrollArea контактов не должна перекрывать её.
        let bottom_bar_h: f32 = 56.0;
        let contacts_max_h = (ui.available_height() - bottom_bar_h).max(80.0);

        egui::ScrollArea::vertical()
            .id_salt("contacts_scroll")
            .auto_shrink([false, false])
            .max_height(contacts_max_h)
            .show(ui, |ui| {
                ui.add_space(4.0);

                let mut peers: Vec<(PeerId, String)> = self
                    .known_peers
                    .iter()
                    .map(|(p, n)| (*p, n.clone()))
                    .collect();
                peers.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));

                let mut to_remove: Vec<PeerId> = Vec::new();
                let me_str = self.local_peer_id.to_string();

                if peers.is_empty() {
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("✦")
                                .size(40.0)
                                .color(palette::ACCENT_2),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("Контактов пока нет")
                                .color(palette::TEXT)
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new("Войдите в сеть VOID или\nдобавьте Peer ID вручную")
                                .color(palette::TEXT_MUTED)
                                .size(12.0),
                        );
                    });
                    ui.add_space(20.0);
                }

                for (peer_id, name) in &peers {
                    if !search.is_empty()
                        && !name.to_lowercase().contains(&search)
                        && !peer_id.to_string().to_lowercase().contains(&search)
                    {
                        continue;
                    }
                    let peer_str = peer_id.to_string();
                    let is_selected = self.selected_chat == peer_str;

                    let last_msg: Option<&ChatMessage> =
                        self.messages.get(&peer_str).and_then(|v| v.last());
                    let preview = match last_msg {
                        Some(m) if m.sender_id == me_str => format!("Вы: {}", m.text),
                        Some(m) => m.text.clone(),
                        None => "Нажмите, чтобы написать…".to_string(),
                    };
                    let time_str = last_msg
                        .map(|m| short_time(&m.timestamp))
                        .unwrap_or_default();

                    let bg = if is_selected {
                        palette::BG_SELECTED
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    let inner = egui::Frame::none()
                        .fill(bg)
                        .rounding(10.0)
                        .inner_margin(egui::Margin {
                            left: 10.0,
                            right: 14.0,
                            top: 8.0,
                            bottom: 8.0,
                        })
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                draw_avatar(ui, &peer_str, name, 42.0, None);
                                ui.add_space(10.0);
                                ui.vertical(|ui| {
                                    let inner_w = ui.available_width();
                                    ui.set_width(inner_w);
                                    ui.horizontal(|ui| {
                                        ui.set_width(inner_w);
                                        // Резервируем место под время справа,
                                        // чтобы длинное имя не выталкивало его
                                        // за край / под скроллбар.
                                        let time_slot = if time_str.is_empty() {
                                            0.0
                                        } else {
                                            44.0
                                        };
                                        let name_w = (inner_w - time_slot - 6.0).max(40.0);
                                        ui.allocate_ui_with_layout(
                                            egui::vec2(name_w, 18.0),
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                ui.add(
                                                    egui::Label::new(
                                                        egui::RichText::new(name)
                                                            .strong()
                                                            .color(palette::TEXT)
                                                            .size(14.5),
                                                    )
                                                    .truncate(),
                                                );
                                            },
                                        );
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                ui.label(
                                                    egui::RichText::new(&time_str)
                                                        .size(10.5)
                                                        .color(palette::TEXT_MUTED),
                                                );
                                            },
                                        );
                                    });
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(truncate_text(&preview, 40))
                                                .color(palette::TEXT_MUTED)
                                                .size(12.5),
                                        )
                                        .truncate(),
                                    );
                                });
                            });
                        })
                        .response;

                    let click = inner.interact(egui::Sense::click());
                    if click.clicked() {
                        self.selected_chat = peer_str.clone();
                        self.messages.entry(peer_str.clone()).or_insert_with(Vec::new);
                    }
                    click.context_menu(|ui| {
                        ui.label(
                            egui::RichText::new("Контакт")
                                .color(palette::TEXT_MUTED)
                                .size(11.0),
                        );
                        ui.separator();
                        if ui.button("📋 Копировать Peer ID").clicked() {
                            ui.output_mut(|o| o.copied_text = peer_str.clone());
                            ui.close_menu();
                        }
                        if ui.button("🗑 Удалить контакт").clicked() {
                            to_remove.push(*peer_id);
                            ui.close_menu();
                        }
                        ui.separator();
                        ui.label(
                            egui::RichText::new("✎  Переименовать")
                                .color(palette::TEXT_MUTED)
                                .size(11.0),
                        );
                        let buf = self
                            .peer_name_edits
                            .entry(*peer_id)
                            .or_insert_with(|| name.clone());
                        let edit = ui.add(
                            egui::TextEdit::singleline(buf)
                                .desired_width(220.0)
                                .hint_text("Новое имя"),
                        );
                        let enter_pressed = edit.lost_focus()
                            && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let save_clicked = ui
                            .add_sized(
                                [ui.available_width(), 28.0],
                                egui::Button::new(
                                    egui::RichText::new("Сохранить имя")
                                        .color(palette::TEXT)
                                        .strong(),
                                )
                                .fill(palette::ACCENT),
                            )
                            .clicked();
                        if enter_pressed || save_clicked {
                            let trimmed = buf.trim().to_string();
                            if !trimmed.is_empty() && trimmed != *name {
                                self.known_peers.insert(*peer_id, trimmed.clone());
                                *buf = trimmed;
                                self.persist_vault();
                            }
                            ui.close_menu();
                        }
                    });
                }

                if !to_remove.is_empty() {
                    for pid in to_remove {
                        let p = pid.to_string();
                        self.known_peers.remove(&pid);
                        self.peer_name_edits.remove(&pid);
                        self.messages.remove(&p);
                        if self.selected_chat == p {
                            self.selected_chat.clear();
                        }
                    }
                    self.persist_vault();
                    self.mark_chat_journal_dirty();
                }

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(8.0);

                // -------- ➕ Добавить контакт --------
                ui.collapsing(
                    egui::RichText::new("➕  Добавить контакт")
                        .color(palette::ACCENT)
                        .strong(),
                    |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.add_contact_peer)
                                .hint_text("PeerId (12D3Koo…)  или  /ip4/.../p2p/…")
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                        ui.add_space(4.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.add_contact_name)
                                .hint_text("Имя в записной книге")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                "По PeerId — клиент найдёт адрес через DHT (нужен живой \
                                 bootstrap). По multiaddr — подключится напрямую сразу.",
                            )
                            .color(palette::TEXT_MUTED)
                            .size(11.0),
                        );
                        ui.add_space(8.0);
                        let save = ui.add_sized(
                            [ui.available_width(), 34.0],
                            egui::Button::new(
                                egui::RichText::new("Сохранить и подключиться")
                                    .color(palette::TEXT)
                                    .strong(),
                            )
                            .fill(palette::ACCENT),
                        );
                        if save.clicked() {
                            let input = self.add_contact_peer.trim().to_string();
                            let name_t = self.add_contact_name.trim().to_string();
                            if input.is_empty() || name_t.is_empty() {
                                self.add_status(
                                    "⚠ Заполните и адрес/PeerId, и имя контакта.".into(),
                                );
                            } else if let Ok(pid) = input.parse::<PeerId>() {
                                // Голый PeerId — DHT-поиск.
                                if pid == self.local_peer_id {
                                    self.add_status(
                                        "⚠ Это ваш собственный PeerId.".into(),
                                    );
                                } else {
                                    self.known_peers.insert(pid, name_t);
                                    self.persist_vault();
                                    let _ = self
                                        .command_tx
                                        .try_send(UICommand::SearchPeer(pid));
                                    self.add_status(format!(
                                        "🔍 Контакт сохранён, ищу {} через DHT…",
                                        &pid.to_string()[..12]
                                    ));
                                    self.add_contact_peer.clear();
                                    self.add_contact_name.clear();
                                }
                            } else {
                                // Возможно multiaddr / IP[:PORT]/p2p/...
                                match parse_seed_input(&input) {
                                    Some((ma, Some(pid))) if pid != self.local_peer_id => {
                                        self.known_peers.insert(pid, name_t);
                                        let addrs =
                                            self.contact_addrs.entry(pid).or_default();
                                        if !addrs.iter().any(|a| a == &ma) {
                                            addrs.push(ma.clone());
                                        }
                                        self.persist_vault();
                                        let _ = self.command_tx.try_send(
                                            UICommand::DialPeer(pid, vec![ma]),
                                        );
                                        self.add_status(format!(
                                            "✅ Контакт сохранён, подключаюсь к {}…",
                                            &pid.to_string()[..12]
                                        ));
                                        self.add_contact_peer.clear();
                                        self.add_contact_name.clear();
                                    }
                                    Some((_, Some(_))) => self.add_status(
                                        "⚠ Это ваш собственный PeerId — контакт не добавлен."
                                            .into(),
                                    ),
                                    Some((_, None)) => self.add_status(
                                        "⚠ В multiaddr нет /p2p/<PeerId> — укажите PeerId \
                                         или полный адрес с /p2p/… в конце."
                                            .into(),
                                    ),
                                    None => self.add_status(
                                        "⚠ Не PeerId и не multiaddr. Примеры: \
                                         12D3Koo… или /ip4/1.2.3.4/tcp/4001/p2p/12D3Koo…"
                                            .into(),
                                    ),
                                }
                            }
                        }
                    },
                );

                ui.add_space(6.0);

                // -------- 🛰  Сеть VOID --------
                ui.collapsing(
                    egui::RichText::new("🛰   Сеть VOID")
                        .color(palette::ACCENT_2)
                        .strong(),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("Подключено:")
                                    .color(palette::TEXT_MUTED)
                                    .size(12.0),
                            );
                            ui.label(
                                egui::RichText::new(format!("{}", self.connected_peers))
                                    .color(palette::ONLINE)
                                    .strong(),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("DHT-таблица:")
                                    .color(palette::TEXT_MUTED)
                                    .size(12.0),
                            );
                            ui.label(
                                egui::RichText::new(format!("{} узл.", self.dht_routing_total))
                                    .color(palette::ACCENT_2),
                            );
                        });
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("Войти в сеть через IP")
                                .color(palette::TEXT_MUTED)
                                .size(11.5),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.void_bootstrap_draft)
                                .hint_text("157.22.192.234")
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                        ui.add_space(6.0);
                        let join = ui.add_sized(
                            [ui.available_width(), 32.0],
                            egui::Button::new(
                                egui::RichText::new("🌐 Войти в VOID")
                                    .color(palette::TEXT)
                                    .strong(),
                            )
                            .fill(palette::ACCENT),
                        );
                        if join.clicked() {
                            let input = self.void_bootstrap_draft.trim().to_string();
                            if input.is_empty() {
                                self.add_status("⚠ Введите IP другой ноды".into());
                            } else {
                                let _ = self
                                    .command_tx
                                    .try_send(UICommand::JoinViaNode(input.clone()));
                                self.add_status(format!("Вход в сеть через {input}…"));
                            }
                        }
                        ui.add_space(4.0);
                        if ui
                            .button(
                                egui::RichText::new("Переподключить seed").color(palette::TEXT),
                            )
                            .clicked()
                        {
                            let _ = self
                                .command_tx
                                .try_send(UICommand::ReloadBootstrapFromSources);
                        }
                        if ui
                            .button(egui::RichText::new("Снимок DHT").color(palette::TEXT))
                            .clicked()
                        {
                            let _ = self
                                .command_tx
                                .try_send(UICommand::SnapshotDhtRoutingPeers);
                        }
                    },
                );

                ui.add_space(6.0);

                // -------- 🔌 Прямое подключение --------
                ui.collapsing(
                    egui::RichText::new("🔌  Прямое подключение")
                        .color(palette::ACCENT_2)
                        .strong(),
                    |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.dial_address)
                                .hint_text("Peer ID или Multiaddr")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("Подключить")
                                            .color(palette::TEXT),
                                    )
                                    .fill(palette::BG_HOVER),
                                )
                                .clicked()
                                && !self.dial_address.is_empty()
                            {
                                let input = self.dial_address.trim().to_string();
                                if let Ok(pid) = input.parse::<PeerId>() {
                                    if pid == self.local_peer_id {
                                        self.add_status(
                                            "Это ваш собственный PeerId.".into(),
                                        );
                                    } else {
                                        let _ =
                                            self.command_tx.try_send(UICommand::SearchPeer(pid));
                                    }
                                } else {
                                    let _ = self.command_tx.try_send(UICommand::Dial(input));
                                }
                                self.dial_address.clear();
                            }
                            if ui
                                .button(
                                    egui::RichText::new("📋 Свой ID").color(palette::TEXT),
                                )
                                .clicked()
                            {
                                ui.output_mut(|o| {
                                    o.copied_text = self.local_peer_id.to_string()
                                });
                            }
                        });
                    },
                );

                ui.add_space(14.0);
            });
    }
}

// ============================================================
//  ВИЗУАЛ: космическая палитра + helpers (Telegram-like layout)
// ============================================================

mod palette {
    use eframe::egui::Color32;
    // База фона: #16232B — взято с пользовательского эталона. Остальные оттенки
    // выведены из неё, чтобы сохранить «лестницу» глубина→панель→карточка→hover→selected.
    pub const BG_DEEP:       Color32 = Color32::from_rgb(0x0f, 0x1b, 0x22); // глубокий тон под панелями
    pub const BG_PANEL:      Color32 = Color32::from_rgb(0x16, 0x23, 0x2b); // sidebar / главный фон
    pub const BG_CHAT:       Color32 = Color32::from_rgb(0x16, 0x23, 0x2b); // чат — единый тон с sidebar
    pub const BG_CARD:       Color32 = Color32::from_rgb(0x1c, 0x2d, 0x38); // карточки/инпуты
    pub const BG_HOVER:      Color32 = Color32::from_rgb(0x23, 0x36, 0x46);
    pub const BG_SELECTED:   Color32 = Color32::from_rgb(0x2a, 0x40, 0x53);
    pub const DIVIDER:       Color32 = Color32::from_rgb(0x34, 0x4c, 0x61);
    pub const TEXT:          Color32 = Color32::from_rgb(0xe8, 0xec, 0xf8);
    pub const TEXT_MUTED:    Color32 = Color32::from_rgb(0x7d, 0x86, 0xa8);
    pub const ACCENT:        Color32 = Color32::from_rgb(0x7c, 0x5c, 0xff); // cosmic violet
    pub const ACCENT_2:      Color32 = Color32::from_rgb(0x5c, 0xc7, 0xff); // starlight cyan
    pub const BUBBLE_ME:     Color32 = Color32::from_rgb(0x32, 0x3f, 0x88);
    pub const BUBBLE_THEM:   Color32 = Color32::from_rgb(0x14, 0x18, 0x33);
    pub const ONLINE:        Color32 = Color32::from_rgb(0x3a, 0xd6, 0x8b);
    pub const NEBULA_VIOLET: Color32 = Color32::from_rgba_premultiplied(0x55, 0x28, 0x88, 170);
    pub const NEBULA_BLUE:   Color32 = Color32::from_rgba_premultiplied(0x18, 0x40, 0x90, 140);
    pub const STAR:          Color32 = Color32::from_rgb(0xd8, 0xe0, 0xf0);
}

fn hsv_to_rgb(h: f32, s: f32, v: f32) -> egui::Color32 {
    let c = v * s;
    let hh = (h / 60.0).rem_euclid(6.0);
    let x = c * (1.0 - (hh.rem_euclid(2.0) - 1.0).abs());
    let (r, g, b) = if hh < 1.0 { (c, x, 0.0) }
        else if hh < 2.0 { (x, c, 0.0) }
        else if hh < 3.0 { (0.0, c, x) }
        else if hh < 4.0 { (0.0, x, c) }
        else if hh < 5.0 { (x, 0.0, c) }
        else             { (c, 0.0, x) };
    let m = v - c;
    egui::Color32::from_rgb(
        (((r + m) * 255.0) as u32).min(255) as u8,
        (((g + m) * 255.0) as u32).min(255) as u8,
        (((b + m) * 255.0) as u32).min(255) as u8,
    )
}

/// Цвет, выводимый детерминированно из строки (peer_id) — для аватаров.
fn deterministic_color(seed: &str) -> egui::Color32 {
    let mut h: u64 = 0x9e37_79b9_7f4a_7c15;
    for b in seed.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    // диапазон оттенков 200..360 + 0..40 = холодный край (синий → фиолетовый → магента)
    let raw = (h % 200) as f32; // 0..200
    let hue = (200.0 + raw) % 360.0;
    hsv_to_rgb(hue, 0.55, 0.78)
}

/// Кружок-аватар с инициалом и (опц.) индикатором онлайна.
fn draw_avatar(
    ui: &mut egui::Ui,
    seed: &str,
    label: &str,
    size: f32,
    online: Option<bool>,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    if !ui.is_rect_visible(rect) {
        return resp;
    }
    let painter = ui.painter();
    let bg = deterministic_color(seed);
    // мягкое свечение
    painter.circle_filled(
        rect.center(),
        size / 2.0 + 2.5,
        egui::Color32::from_rgba_premultiplied(bg.r(), bg.g(), bg.b(), 50),
    );
    painter.circle_filled(rect.center(), size / 2.0, bg);
    let initial: String = label
        .trim()
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".into());
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        initial,
        egui::FontId::new(size * 0.46, egui::FontFamily::Proportional),
        palette::TEXT,
    );
    if let Some(true) = online {
        let dot_r = (size * 0.16).max(4.0);
        let dot_pos = egui::pos2(rect.right() - dot_r, rect.bottom() - dot_r);
        painter.circle_filled(dot_pos, dot_r + 1.6, palette::BG_PANEL);
        painter.circle_filled(dot_pos, dot_r, palette::ONLINE);
    }
    resp
}

/// Один раз генерируемое случайное «звёздное небо» (нормализованные координаты).
fn starfield() -> &'static [(f32, f32, f32, u8)] {
    use std::sync::OnceLock;
    static STARS: OnceLock<Vec<(f32, f32, f32, u8)>> = OnceLock::new();
    STARS.get_or_init(|| {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..240)
            .map(|_| {
                (
                    rng.gen::<f32>(),
                    rng.gen::<f32>(),
                    rng.gen_range(0.6_f32..2.2),
                    rng.gen_range(110_u8..245),
                )
            })
            .collect()
    })
}

/// Рисует `static/icon.png` как фон области диалогов в режиме «cover»:
/// картинка центрируется и масштабируется так, чтобы заполнить всю область
/// без пустых полей; clip самой панели обрежет лишнее. Поверх кладётся
/// лёгкое затемнение для читаемости пузырей сообщений.
fn draw_chat_bg_image(
    painter: &egui::Painter,
    rect: egui::Rect,
    tex_id: egui::TextureId,
    tex_size: egui::Vec2,
) {
    if tex_size.x <= 0.0 || tex_size.y <= 0.0 || rect.width() <= 0.0 || rect.height() <= 0.0 {
        return;
    }
    let scale = (rect.width() / tex_size.x).max(rect.height() / tex_size.y);
    let scaled = egui::vec2(tex_size.x * scale, tex_size.y * scale);
    let img_rect = egui::Rect::from_center_size(rect.center(), scaled);
    let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
    painter.image(tex_id, img_rect, uv, egui::Color32::WHITE);
    // Затемняющая вуаль — без неё bubbles теряются на ярких участках обоев.
    painter.rect_filled(
        rect,
        0.0,
        egui::Color32::from_rgba_unmultiplied(0, 0, 0, 110),
    );
}

/// Звёзды + две туманности, рисуем как фон чата.
fn draw_starfield(painter: &egui::Painter, rect: egui::Rect) {
    // туманности (несколько концентрических кругов с убывающей альфой = soft glow)
    let blob = |c: egui::Pos2, r: f32, color: egui::Color32| {
        for i in 0..9 {
            let alpha = ((color.a() as f32) / (i as f32 + 1.4)) as u8;
            painter.circle_filled(
                c,
                r * (i as f32 / 9.0 + 0.3),
                egui::Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), alpha),
            );
        }
    };
    let nebula1 = egui::pos2(
        rect.left() + rect.width() * 0.22,
        rect.top() + rect.height() * 0.24,
    );
    let nebula2 = egui::pos2(
        rect.left() + rect.width() * 0.78,
        rect.top() + rect.height() * 0.72,
    );
    let scale = rect.width().min(rect.height());
    blob(nebula1, scale * 0.55, palette::NEBULA_VIOLET);
    blob(nebula2, scale * 0.45, palette::NEBULA_BLUE);

    // звёзды
    for (xf, yf, r, a) in starfield() {
        let pos = egui::pos2(rect.left() + xf * rect.width(), rect.top() + yf * rect.height());
        painter.circle_filled(
            pos,
            *r,
            egui::Color32::from_rgba_premultiplied(
                palette::STAR.r(),
                palette::STAR.g(),
                palette::STAR.b(),
                *a,
            ),
        );
    }
}

pub(crate) fn truncate_text(s: &str, max_chars: usize) -> String {
    let mut count = 0usize;
    let mut out = String::new();
    for ch in s.chars() {
        if count >= max_chars {
            out.push('…');
            return out;
        }
        out.push(ch);
        count += 1;
    }
    out
}

/// Из "2026-04-18 14:30:45" берём "14:30".
fn short_time(ts: &str) -> String {
    let last = ts.split_whitespace().last().unwrap_or(ts);
    last.split(':').take(2).collect::<Vec<_>>().join(":")
}

pub(crate) fn setup_custom_style(ctx: &egui::Context) {
    use egui::{FontFamily, FontId, TextStyle};

    // ----- Шрифты: добавляем системный emoji-шрифт как fallback,
    // чтобы такие глифы как ☰, ⋯, 🛰, 🔌, 🔍, ➤ не превращались в □ -----
    let mut fonts = egui::FontDefinitions::default();
    let candidates: &[&str] = &[
        #[cfg(target_os = "windows")]
        "C:/Windows/Fonts/seguiemj.ttf",
        #[cfg(target_os = "windows")]
        "C:/Windows/Fonts/seguisym.ttf",
        #[cfg(target_os = "windows")]
        "C:/Windows/Fonts/segoeui.ttf",
        #[cfg(target_os = "macos")]
        "/System/Library/Fonts/Apple Color Emoji.ttc",
        #[cfg(target_os = "linux")]
        "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
    ];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            let name = format!("sysfont_{}", path);
            fonts
                .font_data
                .insert(name.clone(), egui::FontData::from_owned(bytes));
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .push(name.clone());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .push(name);
        }
    }
    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::dark();

    visuals.override_text_color = Some(palette::TEXT);
    visuals.panel_fill          = palette::BG_PANEL;
    visuals.window_fill         = palette::BG_PANEL;
    visuals.extreme_bg_color    = palette::BG_DEEP;
    visuals.faint_bg_color      = palette::BG_CARD;

    visuals.widgets.noninteractive.bg_fill      = palette::BG_PANEL;
    visuals.widgets.noninteractive.weak_bg_fill = palette::BG_PANEL;
    visuals.widgets.noninteractive.bg_stroke    = egui::Stroke::new(1.0, palette::DIVIDER);
    visuals.widgets.noninteractive.fg_stroke    = egui::Stroke::new(1.0, palette::TEXT);
    visuals.widgets.noninteractive.rounding     = 12.0.into();

    visuals.widgets.inactive.bg_fill      = palette::BG_CARD;
    visuals.widgets.inactive.weak_bg_fill = palette::BG_CARD;
    visuals.widgets.inactive.bg_stroke    = egui::Stroke::new(1.0, palette::DIVIDER);
    visuals.widgets.inactive.fg_stroke    = egui::Stroke::new(1.0, palette::TEXT);
    visuals.widgets.inactive.rounding     = 12.0.into();

    visuals.widgets.hovered.bg_fill      = palette::BG_HOVER;
    visuals.widgets.hovered.weak_bg_fill = palette::BG_HOVER;
    visuals.widgets.hovered.bg_stroke    = egui::Stroke::new(1.0, palette::ACCENT);
    visuals.widgets.hovered.fg_stroke    = egui::Stroke::new(1.4, palette::ACCENT_2);
    visuals.widgets.hovered.rounding     = 12.0.into();

    visuals.widgets.active.bg_fill      = palette::BG_SELECTED;
    visuals.widgets.active.weak_bg_fill = palette::BG_SELECTED;
    visuals.widgets.active.bg_stroke    = egui::Stroke::new(1.4, palette::ACCENT);
    visuals.widgets.active.fg_stroke    = egui::Stroke::new(1.4, palette::ACCENT);
    visuals.widgets.active.rounding     = 12.0.into();

    visuals.widgets.open.bg_fill      = palette::BG_HOVER;
    visuals.widgets.open.weak_bg_fill = palette::BG_HOVER;
    visuals.widgets.open.rounding     = 12.0.into();

    visuals.selection.bg_fill = palette::ACCENT;
    visuals.selection.stroke  = egui::Stroke::new(1.0, palette::TEXT);
    visuals.hyperlink_color   = palette::ACCENT_2;

    visuals.window_rounding = 14.0.into();
    visuals.window_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 6.0),
        blur:   28.0,
        spread: 0.0,
        color:  egui::Color32::from_rgba_premultiplied(0, 0, 0, 140),
    };
    visuals.popup_shadow = visuals.window_shadow;

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Small,     FontId::new(11.5, FontFamily::Proportional)),
        (TextStyle::Body,      FontId::new(14.5, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        (TextStyle::Button,    FontId::new(14.5, FontFamily::Proportional)),
        (TextStyle::Heading,   FontId::new(20.0, FontFamily::Proportional)),
    ]
    .into();
    style.spacing.item_spacing    = egui::vec2(8.0, 6.0);
    style.spacing.window_margin   = egui::Margin::same(0.0);
    style.spacing.button_padding  = egui::vec2(12.0, 8.0);
    style.spacing.menu_margin     = egui::Margin::same(8.0);
    ctx.set_style(style);
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.vault_unlock_gate(ctx) {
            return;
        }

        self.known_peers.remove(&self.local_peer_id);

        // ── Поллинг результата выбора папки сохранения ────────────────────
        // Проверяем, не вернул ли пользователь результат из диалога папки.
        let accept_result: Option<(Option<String>, [u8; 16], PeerId)> =
            if let Some((ref rx, tid, from)) = self.pending_accept {
                match rx.try_recv() {
                    Ok(dir_opt) => Some((dir_opt, tid, from)),
                    Err(std::sync::mpsc::TryRecvError::Empty) => None,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        // Поток завершился без отправки (паника и т.п.) — закрываем.
                        Some((None, tid, from))
                    }
                }
            } else {
                None
            };
        if let Some((dir_opt, tid, from)) = accept_result {
            self.pending_accept = None;
            if let Some(dir) = dir_opt {
                // Пользователь выбрал папку → принять файл.
                let _ = self.command_tx.try_send(UICommand::AcceptFile {
                    transfer_id: tid,
                    from,
                    save_dir: Some(dir),
                });
                self.incoming_file_offers.retain(|o| o.transfer_id != tid);
            }
            // Если dir_opt == None — пользователь отменил выбор папки,
            // оффер остаётся в списке: он может попробовать снова.
        }
        // Запрашиваем перерисовку пока ждём ответа диалога (иначе egui
        // «засыпает» и канал не опрашивается вовремя).
        if self.pending_accept.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }

        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::PublicIpConfirmed(ip) => {
                    self.public_ip = Some(ip);
                }
                NetworkEvent::NewListenAddr(addr) => {
                    let full = format!("{}/p2p/{}", addr, self.local_peer_id);
                    if !self.listen_addrs.contains(&full) {
                        self.add_status(format!("🚀 Listen: {}", addr));
                        self.listen_addrs.push(full);
                    }
                }
                NetworkEvent::MdnsDiscovered(peer, addr) => {
                    self.add_status(format!(
                        "🔍 Найдён пир: {} на {}",
                        &peer.to_string()[..8],
                        addr
                    ));
                    if peer != self.local_peer_id {
                        if let Entry::Vacant(e) = self.known_peers.entry(peer) {
                            e.insert(format!("Peer_{}", &peer.to_string()[..8]));
                            self.persist_vault();
                        }
                        self.select_peer_if_no_chat(peer);
                    }
                }
                NetworkEvent::MdnsExpired(peer) => {
                    self.add_status(format!("⏳ Оффлайн (MDNS): {}", &peer.to_string()[..8]));
                }
                NetworkEvent::Connected(peer) => {
                    self.connected_peers += 1;
                    self.add_status(format!("✅ Подключено: {}...", &peer.to_string()[..8]));
                    if peer != self.local_peer_id {
                        self.select_peer_if_no_chat(peer);
                    }
                    // Коннект появился — немедленно переотправляем зависшие
                    // сообщения этому пиру, не дожидаясь `RESEND_GRACE`/
                    // `RESEND_DELAY`. Без этого пользователь видит, что пир
                    // уже в сети, но сообщение уходит только через 8+ сек.
                    let mut to_resend: Vec<(usize, PeerId, String, String)> = Vec::new();
                    for (idx, p) in self.pending_sends.iter().enumerate() {
                        if p.peer == peer {
                            to_resend.push((idx, p.peer, p.text.clone(), p.message_id.clone()));
                        }
                    }
                    if !to_resend.is_empty() {
                        let now = Instant::now();
                        for (idx, _, _, _) in &to_resend {
                            if let Some(p) = self.pending_sends.get_mut(*idx) {
                                p.awaiting_session = false;
                                p.attempts = p.attempts.saturating_add(1);
                                p.last_send_at = now;
                                p.dht_kicked = false;
                                p.dht_kicked_at = None;
                            }
                        }
                        for (_, peer, text, message_id) in to_resend {
                            let _ = self.command_tx.try_send(UICommand::SendMessage {
                                sender_name: self.local_nickname.clone(),
                                text,
                                recipient: Some(peer),
                                message_id: Some(message_id),
                                is_retry: true,
                            });
                        }
                    }
                }
                NetworkEvent::Disconnected(peer) => {
                    self.connected_peers = self.connected_peers.saturating_sub(1);
                    self.add_status(format!("❌ Отключено: {}...", &peer.to_string()[..8]));
                }
                NetworkEvent::ChatMessage(msg) => {
                    // Update known peers for display names
                    if let Ok(peer_id) = msg.sender_id.parse::<PeerId>() {
                        if peer_id != self.local_peer_id {
                            let prev = self
                                .known_peers
                                .insert(peer_id, msg.sender_name.clone());
                            if prev.as_ref() != Some(&msg.sender_name) {
                                self.persist_vault();
                            }
                        }
                    }

                    self.ingest_chat_message(msg);
                }
                NetworkEvent::Status(msg) => {
                    self.add_status(msg);
                }
                NetworkEvent::DhtRoutingPeers { total, lines } => {
                    self.dht_routing_total = total;
                    self.dht_routing_lines = lines;
                    self.add_status(format!("DHT: в таблице маршрутов {} узл.", total));
                }
                NetworkEvent::MessageDelivered(peer) => {
                    // Снимаем самое раннее ожидание этого пира: ретрая не будет,
                    // ошибочный toast «✖ Не удалось доставить…» тоже не появится.
                    if let Some(idx) = self
                        .pending_sends
                        .iter()
                        .position(|p| p.peer == peer)
                    {
                        self.pending_sends.remove(idx);
                    }
                }
                NetworkEvent::MessageAwaitingSession(peer) => {
                    if let Some(p) = self
                        .pending_sends
                        .iter_mut()
                        .find(|p| p.peer == peer)
                    {
                        p.awaiting_session = true;
                        p.last_send_at = Instant::now();
                        p.dht_kicked = false;
                        p.dht_kicked_at = None;
                    }
                }
                NetworkEvent::MessageOnWire(peer) => {
                    if let Some(p) = self
                        .pending_sends
                        .iter_mut()
                        .find(|p| p.peer == peer)
                    {
                        p.awaiting_session = false;
                        p.last_send_at = Instant::now();
                    }
                }
                NetworkEvent::SendFailedDial(peer) => {
                    // Сразу подталкиваем самое раннее ожидающее сообщение
                    // этому пиру к фазе DHT-lookup (сдвигаем `last_send_at`
                    // в прошлое — следующий tick запустит retry-логику).
                    if let Some(p) = self
                        .pending_sends
                        .iter_mut()
                        .find(|p| p.peer == peer && !p.dht_kicked)
                    {
                        p.last_send_at = Instant::now()
                            .checked_sub(RESEND_GRACE + Duration::from_millis(50))
                            .unwrap_or_else(Instant::now);
                    }
                    // Параллельно: если у контакта есть сохранённые multiaddr
                    // (mDNS/Identify/из vault) — сразу пытаемся дозвониться до
                    // них напрямую, не ждём 3 сек DHT-грейс. На Windows dial
                    // через request_response часто падает с WSAEADDRINUSE
                    // (10048) из-за port-reuse; ручной DialPeer по LAN-адресам
                    // обычно проходит.
                    if let Some(addrs) = self.contact_addrs.get(&peer) {
                        if !addrs.is_empty() {
                            let _ = self.command_tx.try_send(UICommand::DialPeer(
                                peer,
                                addrs.clone(),
                            ));
                        }
                    }
                }
                NetworkEvent::SendFailedUnsupported(peer) => {
                    // Пир физически не поддерживает чат. Ретраить бессмысленно —
                    // снимаем все ожидания ему и удаляем из контактов.
                    self.pending_sends.retain(|p| p.peer != peer);
                    let removed_name = self.known_peers.remove(&peer);
                    self.contact_addrs.remove(&peer);
                    self.messages.remove(&peer.to_string());
                    if self.selected_chat == peer.to_string() {
                        self.selected_chat.clear();
                    }
                    self.persist_vault();
                    self.mark_chat_journal_dirty();
                    let label = removed_name
                        .unwrap_or_else(|| format!("{}…", &peer.to_string()[..10]));
                    self.push_toast(
                        format!(
                            "✖ {} — не VOID-чат (bootstrap/другая версия). Удалён из контактов.",
                            label
                        ),
                        ToastKind::Error,
                        TOAST_TTL_LONG,
                    );
                }
                NetworkEvent::PeerIsNotVoidChat(peer) => {
                    // Identify показал, что у пира нет /void/chat/1.0.0.
                    // Подчищаем его из контактов заранее, не дожидаясь попытки
                    // отправки. Чаще всего это bootstrap из void-bootstrap.txt.
                    if self.known_peers.remove(&peer).is_some() {
                        self.contact_addrs.remove(&peer);
                        self.messages.remove(&peer.to_string());
                        if self.selected_chat == peer.to_string() {
                            self.selected_chat.clear();
                        }
                        self.persist_vault();
                        self.mark_chat_journal_dirty();
                        self.push_toast(
                            format!(
                                "ℹ️ {}… — DHT/bootstrap-узел, не собеседник. Убран из контактов.",
                                &peer.to_string()[..10]
                            ),
                            ToastKind::Info,
                            TOAST_TTL_SHORT,
                        );
                    }
                }
                // ─── Файловый sub-протокол ──────────────────────────────────
                NetworkEvent::FileOffer {
                    transfer_id,
                    from,
                    filename,
                    total_size,
                    kind,
                } => {
                    self.incoming_file_offers.push(file_transfer::PendingFileOffer {
                        transfer_id,
                        from,
                        filename: filename.clone(),
                        total_size,
                        kind,
                    });
                    self.push_toast(
                        format!(
                            "📥 {} «{}» ({}) от {}…",
                            kind.label(),
                            filename,
                            file_transfer::fmt_size(total_size),
                            &from.to_string()[..8]
                        ),
                        ToastKind::Info,
                        TOAST_TTL_LONG,
                    );
                }
                NetworkEvent::FileProgress {
                    transfer_id,
                    sent_chunks,
                    total_chunks,
                    filename,
                    total_size,
                    is_outgoing,
                    peer,
                    kind,
                } => {
                    self.active_file_transfers
                        .entry(transfer_id)
                        .and_modify(|p| {
                            p.sent_chunks = sent_chunks;
                            p.total_chunks = total_chunks;
                        })
                        .or_insert_with(|| FileTransferProgress {
                            filename: filename.clone(),
                            total_size,
                            sent_chunks,
                            total_chunks,
                            is_outgoing,
                            completed: false,
                            saved_to: String::new(),
                            peer,
                            kind,
                        });
                    // Запрашиваем перерисовку, пока идёт передача.
                    ctx.request_repaint_after(Duration::from_millis(200));
                }
                NetworkEvent::FileComplete {
                    transfer_id,
                    filename,
                    saved_to,
                    is_outgoing,
                    peer: _,
                } => {
                    if let Some(p) = self.active_file_transfers.get_mut(&transfer_id) {
                        p.completed = true;
                        p.saved_to = saved_to.clone();
                        p.sent_chunks = p.total_chunks;
                    }
                    if is_outgoing {
                        self.push_toast(
                            format!("✅ Файл «{}» успешно отправлен.", filename),
                            ToastKind::Info,
                            TOAST_TTL_LONG,
                        );
                    } else {
                        self.push_toast(
                            format!("✅ Файл «{}» сохранён → {}", filename, saved_to),
                            ToastKind::Info,
                            TOAST_TTL_LONG,
                        );
                    }
                }
                NetworkEvent::FileError { transfer_id, reason } => {
                    self.active_file_transfers.remove(&transfer_id);
                    self.push_toast(
                        format!("❌ Файл: {}", reason),
                        ToastKind::Error,
                        TOAST_TTL_LONG,
                    );
                }
                NetworkEvent::PeerAddress(peer, ma) => {
                    // Пир засветился с рабочим адресом: если он уже контакт —
                    // обновляем запись; если нет, но это явно реальный VOID-
                    // клиент (Identify/Connected), добавляем как Peer_XXXX.
                    if peer == self.local_peer_id {
                        continue;
                    }
                    let entry = self.contact_addrs.entry(peer).or_default();
                    let is_new = !entry.iter().any(|a| a == &ma);
                    if is_new {
                        entry.push(ma);
                        // Ограничиваем 4 последними адресами на контакта.
                        if entry.len() > 4 {
                            let excess = entry.len() - 4;
                            entry.drain(0..excess);
                        }
                        let mut changed = true;
                        if let Entry::Vacant(e) = self.known_peers.entry(peer) {
                            e.insert(format!("Peer_{}", &peer.to_string()[..8]));
                        } else {
                            // Обновили только адреса — всё равно persist.
                            changed = true;
                        }
                        if changed {
                            self.persist_vault();
                        }
                    }
                }
            }
        }

        // ===== Tick: повторные отправки + истечение toast'ов =====
        self.tick_pending_sends();
        let now = Instant::now();
        self.toasts.retain(|t| t.expires_at > now);

        // Чтобы фоновые таймеры (retry/toast) тикали без активности пользователя.
        if !self.pending_sends.is_empty() || !self.toasts.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(250));
        }

        // ===== Системная консоль (overlay-окно) =====
        if self.show_logs {
            egui::Window::new("Системная консоль")
                .open(&mut self.show_logs)
                .resizable(true)
                .default_size([460.0, 360.0])
                .frame(
                    egui::Frame::none()
                        .fill(palette::BG_PANEL)
                        .stroke(egui::Stroke::new(1.0, palette::DIVIDER))
                        .rounding(12.0)
                        .inner_margin(16.0)
                        .shadow(egui::epaint::Shadow {
                            offset: egui::vec2(0.0, 6.0),
                            blur: 24.0,
                            spread: 0.0,
                            color: egui::Color32::from_rgba_premultiplied(0, 0, 0, 160),
                        }),
                )
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new("ЛОКАЛЬНЫЕ АДРЕСА")
                            .strong()
                            .size(12.0)
                            .color(palette::ACCENT_2),
                    );
                    for addr in &self.listen_addrs {
                        ui.label(
                            egui::RichText::new(addr)
                                .small()
                                .monospace()
                                .color(palette::TEXT_MUTED),
                        );
                    }
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new("ЛОГ СОБЫТИЙ")
                            .strong()
                            .size(12.0)
                            .color(palette::ACCENT),
                    );
                    egui::ScrollArea::vertical()
                        .id_salt("log_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for log in &self.status_log {
                                ui.label(
                                    egui::RichText::new(log)
                                        .size(12.5)
                                        .color(palette::TEXT_MUTED),
                                );
                            }
                        });
                });
        }

        // ===== Левая панель: контакты (Telegram-стиль) =====
        if self.show_sidebar {
            let screen_w = ctx.screen_rect().width();
            let min_w = 80.0_f32;
            let max_w = (screen_w - 320.0).max(min_w + 40.0);
            self.sidebar_width = self.sidebar_width.clamp(min_w, max_w);

            egui::SidePanel::left("sb_v6_fixed")
                .frame(egui::Frame::none().fill(palette::BG_PANEL))
                .resizable(false)
                .exact_width(self.sidebar_width)
                .show(ctx, |ui| {
                    let panel_rect = ui.max_rect();

                    // 1) Контент сидебара (с правым отступом под ручку).
                    let content_rect = egui::Rect::from_min_max(
                        panel_rect.min,
                        egui::pos2(panel_rect.right() - 8.0, panel_rect.bottom()),
                    );
                    let mut content_ui = ui.new_child(
                        egui::UiBuilder::new()
                            .max_rect(content_rect)
                            .layout(egui::Layout::top_down(egui::Align::Min)),
                    );
                    self.ui_sidebar(&mut content_ui);

                    // 2) Drag-ручка строго на правом краю панели (внутри её rect).
                    let handle_rect = egui::Rect::from_min_max(
                        egui::pos2(panel_rect.right() - 8.0, panel_rect.top()),
                        egui::pos2(panel_rect.right(), panel_rect.bottom()),
                    );
                    let handle_resp = ui.interact(
                        handle_rect,
                        egui::Id::new("sb_v6_drag"),
                        egui::Sense::click_and_drag(),
                    );

                    if handle_resp.dragged() {
                        self.sidebar_width += handle_resp.drag_delta().x;
                        self.sidebar_width = self.sidebar_width.clamp(min_w, max_w);
                    }
                    if handle_resp.hovered() || handle_resp.dragged() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
                    }

                    let active = handle_resp.hovered() || handle_resp.dragged();
                    let stroke_color = if handle_resp.dragged() {
                        palette::ACCENT
                    } else if active {
                        palette::ACCENT_2
                    } else {
                        palette::DIVIDER
                    };
                    let stroke_w = if active { 3.0 } else { 2.0 };
                    ui.painter().vline(
                        panel_rect.right() - 1.5,
                        panel_rect.y_range(),
                        egui::Stroke::new(stroke_w, stroke_color),
                    );
                });
        }

        // ===== Шапка активного чата =====
        let mut chat_clear_requested = false;
        egui::TopBottomPanel::top("chat_header")
            .frame(
                egui::Frame::none()
                    .fill(palette::BG_CHAT)
                    .stroke(egui::Stroke::new(1.0, palette::DIVIDER))
                    .inner_margin(egui::Margin {
                        left: 22.0,
                        right: 18.0,
                        top: 12.0,
                        bottom: 12.0,
                    }),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let toggle_label = if self.show_sidebar { "≡" } else { "≡" };
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new(toggle_label)
                                    .size(18.0)
                                    .color(palette::TEXT),
                            )
                            .fill(egui::Color32::TRANSPARENT)
                            .stroke(egui::Stroke::NONE),
                        )
                        .on_hover_text(if self.show_sidebar {
                            "Скрыть список контактов"
                        } else {
                            "Показать список контактов"
                        })
                        .clicked()
                    {
                        self.show_sidebar = !self.show_sidebar;
                    }
                    ui.add_space(8.0);

                    if !self.selected_chat.is_empty() {
                        let display_name = self
                            .selected_chat
                            .parse::<PeerId>()
                            .ok()
                            .and_then(|pid| self.known_peers.get(&pid).cloned())
                            .unwrap_or_else(|| {
                                let n = self.selected_chat.len().min(8);
                                format!("Peer {}", &self.selected_chat[..n])
                            });
                        draw_avatar(ui, &self.selected_chat, &display_name, 40.0, None);
                        ui.add_space(12.0);
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(&display_name)
                                    .strong()
                                    .size(16.0)
                                    .color(palette::TEXT),
                            );
                            let id_short = {
                                let n = self.selected_chat.len().min(20);
                                format!("{}…", &self.selected_chat[..n])
                            };
                            ui.label(
                                egui::RichText::new(id_short)
                                    .size(11.0)
                                    .monospace()
                                    .color(palette::TEXT_MUTED),
                            );
                        });
                    } else {
                        ui.label(
                            egui::RichText::new("✦ VOID")
                                .size(20.0)
                                .strong()
                                .color(palette::ACCENT),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("выберите контакт слева")
                                .color(palette::TEXT_MUTED),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if !self.selected_chat.is_empty() {
                            let chat_menu = ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("⋮")
                                            .size(20.0)
                                            .color(palette::TEXT),
                                    )
                                    .fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::NONE),
                                )
                                .on_hover_text("Переписка");
                            chat_menu.context_menu(|ui| {
                                if ui.button("🗑 Очистить переписку").clicked() {
                                    chat_clear_requested = true;
                                    ui.close_menu();
                                }
                            });
                            ui.add_space(6.0);
                        }
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("⋯")
                                        .size(22.0)
                                        .color(palette::TEXT),
                                )
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::NONE),
                            )
                            .on_hover_text("Системная консоль")
                            .clicked()
                        {
                            self.show_logs = !self.show_logs;
                        }
                        ui.label(
                            egui::RichText::new(format!(
                                "● {} в сети",
                                self.connected_peers
                            ))
                            .size(11.5)
                            .color(if self.connected_peers > 0 {
                                palette::ONLINE
                            } else {
                                palette::TEXT_MUTED
                            }),
                        );
                    });
                });
            });

        if chat_clear_requested {
            if let Ok(peer) = self.selected_chat.parse::<PeerId>() {
                self.delete_conversation(peer);
                self.push_toast(
                    "Переписка удалена только у вас".into(),
                    ToastKind::Info,
                    TOAST_TTL_SHORT,
                );
            }
        }

        // ===== Панель файловых предложений и прогресса =====
        // Показываем только если есть что отобразить и выбран чат.
        let selected_peer_opt = self.selected_chat.parse::<PeerId>().ok();
        let has_offers = selected_peer_opt
            .map(|p| self.incoming_file_offers.iter().any(|o| o.from == p))
            .unwrap_or(false);
        let has_active = !self.active_file_transfers.is_empty();

        if (has_offers || has_active) && !self.selected_chat.is_empty() {
            egui::TopBottomPanel::top("file_panel")
                .frame(
                    egui::Frame::none()
                        .fill(palette::BG_PANEL)
                        .stroke(egui::Stroke::new(1.0, palette::DIVIDER))
                        .inner_margin(egui::Margin {
                            left: 18.0,
                            right: 18.0,
                            top: 8.0,
                            bottom: 8.0,
                        }),
                )
                .show(ctx, |ui| {
                    // ── Входящие предложения файлов ──────────────────────────
                    let sel_peer = selected_peer_opt;
                    let mut to_reject: Vec<[u8; 16]> = Vec::new();
                    // tid оффера, для которого нужно открыть диалог папки.
                    let mut launch_picker: Option<([u8; 16], PeerId)> = None;

                    // transfer_id оффера, для которого уже открыт диалог.
                    let waiting_tid: Option<[u8; 16]> =
                        self.pending_accept.as_ref().map(|(_, tid, _)| *tid);

                    for offer in self.incoming_file_offers.iter().filter(|o| {
                        sel_peer.map(|p| o.from == p).unwrap_or(false)
                    }) {
                        let is_waiting = waiting_tid == Some(offer.transfer_id);

                        egui::Frame::none()
                            .fill(palette::BG_CARD)
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new(offer.kind.icon()).size(22.0),
                                    );
                                    ui.add_space(6.0);
                                    ui.vertical(|ui| {
                                        ui.label(
                                            egui::RichText::new(&offer.filename)
                                                .strong()
                                                .color(palette::TEXT),
                                        );
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{} · {}",
                                                offer.kind.label(),
                                                file_transfer::fmt_size(offer.total_size)
                                            ))
                                            .size(11.5)
                                            .color(palette::TEXT_MUTED),
                                        );
                                    });
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if is_waiting {
                                                // Диалог папки открыт — показываем индикатор.
                                                ui.label(
                                                    egui::RichText::new("📂 Выбор папки…")
                                                        .size(12.0)
                                                        .color(palette::ACCENT_2),
                                                );
                                            } else {
                                                // Кнопка «Отклонить».
                                                if ui
                                                    .add(
                                                        egui::Button::new(
                                                            egui::RichText::new("✖ Отклонить")
                                                                .size(12.0)
                                                                .color(palette::TEXT),
                                                        )
                                                        .fill(egui::Color32::from_rgb(
                                                            0xa0, 0x30, 0x30,
                                                        ))
                                                        .rounding(6.0),
                                                    )
                                                    .clicked()
                                                {
                                                    to_reject.push(offer.transfer_id);
                                                }
                                                ui.add_space(6.0);
                                                // Кнопка «Принять» → открывает диалог папки.
                                                let accept_enabled =
                                                    self.pending_accept.is_none();
                                                if ui
                                                    .add_enabled(
                                                        accept_enabled,
                                                        egui::Button::new(
                                                            egui::RichText::new("✔ Принять")
                                                                .size(12.0)
                                                                .color(palette::TEXT),
                                                        )
                                                        .fill(palette::ACCENT)
                                                        .rounding(6.0),
                                                    )
                                                    .on_hover_text(
                                                        "Выбрать папку и сохранить файл",
                                                    )
                                                    .clicked()
                                                {
                                                    launch_picker =
                                                        Some((offer.transfer_id, offer.from));
                                                }
                                            }
                                        },
                                    );
                                });
                            });
                        ui.add_space(4.0);
                    }

                    // Запускаем диалог выбора папки (если пользователь нажал «Принять»).
                    if let Some((tid, from)) = launch_picker {
                        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
                        self.pending_accept = Some((rx, tid, from));
                        std::thread::spawn(move || {
                            let picked = rfd::FileDialog::new()
                                .set_title("Выберите папку для сохранения файла")
                                .pick_folder();
                            let _ = tx.send(picked.map(|p| p.display().to_string()));
                        });
                    }

                    // Применяем Reject.
                    for tid in to_reject {
                        if let Some(offer) = self
                            .incoming_file_offers
                            .iter()
                            .find(|o| o.transfer_id == tid)
                            .cloned()
                        {
                            let _ = self.command_tx.try_send(UICommand::RejectFile {
                                transfer_id: tid,
                                from: offer.from,
                                reason: "Пользователь отклонил.".into(),
                            });
                            self.incoming_file_offers.retain(|o| o.transfer_id != tid);
                        }
                    }

                    // ── Прогресс активных передач ────────────────────────────
                    let transfers: Vec<([u8; 16], &FileTransferProgress)> = self
                        .active_file_transfers
                        .iter()
                        .filter(|(_, t)| {
                            sel_peer.map(|p| t.peer == p).unwrap_or(false)
                        })
                        .map(|(k, v)| (*k, v))
                        .collect();

                    for (_, t) in &transfers {
                        let frac = if t.total_chunks > 0 {
                            t.sent_chunks as f32 / t.total_chunks as f32
                        } else {
                            0.0
                        };
                        // Иконка = направление + тип
                        let arrow = if t.is_outgoing { "↑" } else { "↓" };
                        let type_icon = t.kind.icon();
                        let status = if t.completed {
                            if t.is_outgoing {
                                "Отправлен ✓".to_string()
                            } else {
                                format!("Сохранён: {}", t.saved_to)
                            }
                        } else {
                            let pct = (frac * 100.0) as u32;
                            format!(
                                "{}%  ·  {}/{}  ·  {}",
                                pct,
                                t.sent_chunks,
                                t.total_chunks,
                                file_transfer::fmt_size(t.total_size)
                            )
                        };

                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}{} «{}»",
                                    type_icon, arrow, t.filename
                                ))
                                .color(palette::TEXT)
                                .size(13.0),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(&status)
                                            .size(11.5)
                                            .color(palette::TEXT_MUTED),
                                    );
                                },
                            );
                        });
                        // Прогресс-бар.
                        let (bar_resp, _painter) =
                            ui.allocate_painter(egui::vec2(ui.available_width(), 6.0), egui::Sense::hover());
                        let bar_r = bar_resp.rect;
                        ui.painter().rect_filled(bar_r, 3.0, palette::DIVIDER);
                        let filled_w = bar_r.width() * frac.clamp(0.0, 1.0);
                        let filled_rect = egui::Rect::from_min_size(
                            bar_r.min,
                            egui::vec2(filled_w, bar_r.height()),
                        );
                        let bar_color = if t.completed {
                            palette::ONLINE
                        } else {
                            palette::ACCENT
                        };
                        ui.painter().rect_filled(filled_rect, 3.0, bar_color);
                        ui.add_space(4.0);
                    }

                    // Убираем завершённые передачи старше 5 секунд.
                    // (Делаем это вне итерации, через retain.)
                });

            // Чистим завершённые передачи (не во время итерации выше).
            self.active_file_transfers
                .retain(|_, t| !t.completed);
        }

        // ===== Поле ввода (нижняя панель) =====
        egui::TopBottomPanel::bottom("chat_input")
            .frame(
                egui::Frame::none()
                    .fill(palette::BG_CHAT)
                    .inner_margin(egui::Margin {
                        left: 18.0,
                        right: 18.0,
                        top: 10.0,
                        bottom: 14.0,
                    }),
            )
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(palette::BG_CARD)
                    .stroke(egui::Stroke::new(1.0, palette::DIVIDER))
                    .rounding(24.0)
                    .inner_margin(egui::Margin {
                        left: 18.0,
                        right: 6.0,
                        top: 4.0,
                        bottom: 4.0,
                    })
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // ── Кнопка прикрепления (📎) + popup-меню типов ──
                            let attach_id = egui::Id::new("attach_popup");
                            let attach_btn = ui
                                .add_sized(
                                    egui::vec2(36.0, 36.0),
                                    egui::Button::new(
                                        egui::RichText::new("📎")
                                            .size(18.0)
                                            .color(if self.show_attach_menu {
                                                palette::ACCENT
                                            } else {
                                                palette::TEXT_MUTED
                                            }),
                                    )
                                    .fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::NONE),
                                )
                                .on_hover_text("Прикрепить файл");

                            if attach_btn.clicked() {
                                if self.selected_chat.parse::<PeerId>().is_ok() {
                                    self.show_attach_menu = !self.show_attach_menu;
                                } else {
                                    self.add_status(
                                        "⚠ Выберите контакт для отправки файла.".into(),
                                    );
                                }
                            }

                            // Popup-меню с тремя кнопками типов.
                            if self.show_attach_menu {
                                if let Some(peer_id) = self.selected_chat.parse::<PeerId>().ok() {
                                    let popup_pos = attach_btn.rect.left_top()
                                        - egui::vec2(0.0, 128.0);

                                    egui::Area::new(attach_id)
                                        .order(egui::Order::Foreground)
                                        .fixed_pos(popup_pos)
                                        .show(ctx, |ui| {
                                            egui::Frame::none()
                                                .fill(palette::BG_PANEL)
                                                .stroke(egui::Stroke::new(
                                                    1.0,
                                                    palette::DIVIDER,
                                                ))
                                                .rounding(12.0)
                                                .inner_margin(egui::Margin::same(8.0))
                                                .shadow(egui::epaint::Shadow {
                                                    offset: egui::vec2(0.0, 4.0),
                                                    blur: 16.0,
                                                    spread: 0.0,
                                                    color: egui::Color32::from_rgba_premultiplied(
                                                        0, 0, 0, 140,
                                                    ),
                                                })
                                                .show(ui, |ui| {
                                                    ui.set_min_width(140.0);

                                                    // Три кнопки: Image / Audio / File
                                                    let kinds = [
                                                        (file_transfer::FileKind::Image,  "🖼  Изображение"),
                                                        (file_transfer::FileKind::Audio,  "🎵  Аудио"),
                                                        (file_transfer::FileKind::Other,  "📄  Файл"),
                                                    ];
                                                    let mut picked: Option<file_transfer::FileKind> = None;
                                                    for (kind, label) in kinds {
                                                        if ui
                                                            .add(
                                                                egui::Button::new(
                                                                    egui::RichText::new(label)
                                                                        .size(13.5)
                                                                        .color(palette::TEXT),
                                                                )
                                                                .fill(egui::Color32::TRANSPARENT)
                                                                .min_size(egui::vec2(124.0, 32.0)),
                                                            )
                                                            .clicked()
                                                        {
                                                            picked = Some(kind);
                                                        }
                                                    }

                                                    if let Some(kind) = picked {
                                                        self.show_attach_menu = false;
                                                        let cmd_tx = self.command_tx.clone();
                                                        // Открываем нативный диалог с фильтрами типа.
                                                        std::thread::spawn(move || {
                                                            let mut dialog =
                                                                rfd::FileDialog::new();
                                                            let exts = kind.extensions();
                                                            if !exts.is_empty() {
                                                                dialog = dialog.add_filter(
                                                                    kind.label(),
                                                                    exts,
                                                                );
                                                            }
                                                            if let Some(path) =
                                                                dialog.pick_file()
                                                            {
                                                                let _ = cmd_tx.try_send(
                                                                    UICommand::SendFile {
                                                                        recipient: peer_id,
                                                                        path: path
                                                                            .display()
                                                                            .to_string(),
                                                                        kind,
                                                                    },
                                                                );
                                                            }
                                                        });
                                                    }
                                                });
                                        });

                                    // Закрываем popup при клике в другом месте.
                                    if ctx.input(|i| i.pointer.any_click())
                                        && !attach_btn.clicked()
                                    {
                                        self.show_attach_menu = false;
                                    }
                                }
                            }

                            let text_w = (ui.available_width() - 56.0).max(80.0);
                            let edit = ui.add(
                                egui::TextEdit::singleline(&mut self.chat_input)
                                    .hint_text("Сообщение…")
                                    .desired_width(text_w)
                                    .frame(false)
                                    .font(egui::TextStyle::Body),
                            );

                            let send_clicked = ui
                                .add_sized(
                                    egui::vec2(44.0, 44.0),
                                    egui::Button::new(
                                        egui::RichText::new("➤")
                                            .size(18.0)
                                            .color(palette::TEXT),
                                    )
                                    .fill(palette::ACCENT)
                                    .rounding(22.0),
                                )
                                .clicked();

                            let enter_pressed = edit.lost_focus()
                                && ctx.input(|i| i.key_pressed(egui::Key::Enter));

                            if (send_clicked || enter_pressed) && !self.chat_input.is_empty() {
                                let recipient = if self.selected_chat.is_empty() {
                                    None
                                } else {
                                    self.selected_chat.parse::<PeerId>().ok()
                                };
                                if let Some(peer_id) = recipient {
                                    let text_to_send = self.chat_input.clone();
                                    let message_id = new_message_id();
                                    match self.command_tx.try_send(UICommand::SendMessage {
                                        sender_name: self.local_nickname.clone(),
                                        text: text_to_send.clone(),
                                        recipient: Some(peer_id),
                                        message_id: Some(message_id.clone()),
                                        is_retry: false,
                                    }) {
                                        Ok(()) => {
                                            self.chat_input.clear();
                                            self.pending_sends.push(PendingSend {
                                                peer: peer_id,
                                                text: text_to_send,
                                                message_id,
                                                last_send_at: Instant::now(),
                                                dht_kicked: false,
                                                dht_kicked_at: None,
                                                attempts: 1,
                                                awaiting_session: false,
                                            });
                                        }
                                        Err(_) => self.add_status(
                                            "⚠ Очередь к сети переполнена, повторите отправку."
                                                .into(),
                                        ),
                                    }
                                } else if self.selected_chat.is_empty() {
                                    self.add_status(
                                        "⚠ Выберите контакт слева, чтобы отправить сообщение."
                                            .into(),
                                    );
                                } else {
                                    self.add_status(
                                        "⚠ Некорректный Peer ID в выбранном чате.".into(),
                                    );
                                }
                                if enter_pressed {
                                    edit.request_focus();
                                }
                            }
                        });
                    });
            });

        // ===== История чата (фоновое изображение + bubbles) =====
        let bg_tex = self.ensure_chat_bg(ctx);
        let bg_tex_size = self
            .chat_bg_texture
            .as_ref()
            .map(|h| h.size_vec2())
            .unwrap_or(egui::Vec2::ZERO);
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(palette::BG_CHAT))
            .show(ctx, |ui| {
                let bg_rect = ui.max_rect();
                if let Some(tex_id) = bg_tex {
                    draw_chat_bg_image(ui.painter(), bg_rect, tex_id, bg_tex_size);
                } else {
                    draw_starfield(ui.painter(), bg_rect);
                }

                if self.selected_chat.is_empty() {
                    ui.allocate_ui_with_layout(
                        ui.available_size(),
                        egui::Layout::centered_and_justified(egui::Direction::TopDown),
                        |ui| {
                            ui.vertical_centered(|ui| {
                                ui.add_space(80.0);
                                ui.label(
                                    egui::RichText::new("✦")
                                        .size(96.0)
                                        .color(palette::ACCENT_2),
                                );
                                ui.add_space(14.0);
                                ui.label(
                                    egui::RichText::new("Тишина в эфире")
                                        .size(22.0)
                                        .strong()
                                        .color(palette::TEXT),
                                );
                                ui.add_space(6.0);
                                ui.label(
                                    egui::RichText::new(
                                        "Выберите контакт слева — и начнём сеанс связи через VOID.",
                                    )
                                    .color(palette::TEXT_MUTED),
                                );
                            });
                        },
                    );
                    return;
                }

                let messages = self
                    .messages
                    .get(&self.selected_chat)
                    .cloned()
                    .unwrap_or_default();
                let me_str = self.local_peer_id.to_string();
                let mut pending_msg_delete: Option<String> = None;

                egui::ScrollArea::vertical()
                    .id_salt("chat_stream")
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(12.0);

                        if messages.is_empty() {
                            ui.add_space(40.0);
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    egui::RichText::new(
                                        "Сообщений пока нет — отправьте первое ↓",
                                    )
                                    .color(palette::TEXT_MUTED),
                                );
                            });
                        }

                        for msg in &messages {
                            let is_me = msg.sender_id == me_str;
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                let avail = ui.available_width();
                                let max_w = (avail * 0.66).min(560.0).max(180.0);

                                if is_me {
                                    ui.add_space((avail - max_w - 28.0).max(0.0));
                                } else {
                                    ui.add_space(20.0);
                                    draw_avatar(
                                        ui,
                                        &msg.sender_id,
                                        &msg.sender_name,
                                        30.0,
                                        None,
                                    );
                                    ui.add_space(8.0);
                                }

                                let bubble_bg = if is_me {
                                    palette::BUBBLE_ME
                                } else {
                                    palette::BUBBLE_THEM
                                };

                                let msg_id = msg.id.clone();
                                let bubble = egui::Frame::none()
                                    .fill(bubble_bg)
                                    .rounding(egui::Rounding {
                                        nw: 16.0,
                                        ne: 16.0,
                                        sw: if is_me { 16.0 } else { 4.0 },
                                        se: if is_me { 4.0 } else { 16.0 },
                                    })
                                    .inner_margin(egui::Margin {
                                        left: 14.0,
                                        right: 14.0,
                                        top: 8.0,
                                        bottom: 6.0,
                                    })
                                    .show(ui, |ui| {
                                        ui.set_max_width(max_w);
                                        ui.vertical(|ui| {
                                            if !is_me {
                                                ui.label(
                                                    egui::RichText::new(&msg.sender_name)
                                                        .size(12.5)
                                                        .strong()
                                                        .color(palette::ACCENT_2),
                                                );
                                            }
                                            ui.label(
                                                egui::RichText::new(&msg.text)
                                                    .size(14.5)
                                                    .color(palette::TEXT),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(
                                                    egui::Align::Center,
                                                ),
                                                |ui| {
                                                    ui.label(
                                                        egui::RichText::new(short_time(
                                                            &msg.timestamp,
                                                        ))
                                                        .size(10.5)
                                                        .color(palette::TEXT_MUTED),
                                                    );
                                                },
                                            );
                                        });
                                    });
                                bubble.response.context_menu(|ui| {
                                    if ui.button("🗑 Удалить").clicked() {
                                        pending_msg_delete = Some(msg_id.clone());
                                        ui.close_menu();
                                    }
                                });
                            });
                        }
                        ui.add_space(12.0);
                    });

                if let Some(msg_id) = pending_msg_delete {
                    if let Ok(peer) = self.selected_chat.parse::<PeerId>() {
                        self.delete_messages(peer, &[msg_id]);
                    }
                }
            });

        // ===== Toasts (поверх всего, правый верхний угол) =====
        self.draw_toasts(ctx);

        self.flush_chat_journal_if_dirty();

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}
