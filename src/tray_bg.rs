//! Minimize-to-tray: close window -> background (network keeps running).
//! Full quit only via tray menu.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use eframe::egui;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

pub(crate) struct TrayBackground {
    _tray: Option<TrayIcon>,
    show_item_id: Option<tray_icon::menu::MenuId>,
    quit_item_id: Option<tray_icon::menu::MenuId>,
    pub background: bool,
    pub force_quit: bool,
    bg_flag: Arc<AtomicBool>,
}

impl TrayBackground {
    pub(crate) fn new(egui_ctx: &egui::Context) -> Self {
        let bg_flag = Arc::new(AtomicBool::new(false));
        let bg_flag_thread = bg_flag.clone();
        let ctx = egui_ctx.clone();
        let _ = thread::Builder::new()
            .name("void-bg-repaint".into())
            .spawn(move || {
                loop {
                    if bg_flag_thread.load(Ordering::Relaxed) {
                        ctx.request_repaint();
                        thread::sleep(Duration::from_millis(250));
                    } else {
                        thread::sleep(Duration::from_millis(500));
                    }
                }
            });

        let (tray, show_id, quit_id) = match build_tray() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("VOID: system tray unavailable ({e}) - close will quit");
                return Self {
                    _tray: None,
                    show_item_id: None,
                    quit_item_id: None,
                    background: false,
                    force_quit: false,
                    bg_flag,
                };
            }
        };

        Self {
            _tray: Some(tray),
            show_item_id: Some(show_id),
            quit_item_id: Some(quit_id),
            background: false,
            force_quit: false,
            bg_flag,
        }
    }

    pub(crate) fn tray_available(&self) -> bool {
        self._tray.is_some()
    }

    pub(crate) fn enter_background(&mut self, ctx: &egui::Context) {
        if self.force_quit || !self.tray_available() {
            return;
        }
        self.background = true;
        self.bg_flag.store(true, Ordering::Relaxed);
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    pub(crate) fn show_window(&mut self, ctx: &egui::Context) {
        self.background = false;
        self.bg_flag.store(false, Ordering::Relaxed);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        ctx.request_repaint();
    }

    pub(crate) fn request_quit(&mut self, ctx: &egui::Context) {
        self.force_quit = true;
        self.background = false;
        self.bg_flag.store(false, Ordering::Relaxed);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        ctx.request_repaint();
    }

    pub(crate) fn poll(&mut self, ctx: &egui::Context) -> bool {
        if !self.tray_available() {
            return false;
        }

        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            match event {
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
                | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                } => {
                    if self.background {
                        self.show_window(ctx);
                    }
                }
                _ => {}
            }
        }

        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if self.show_item_id.as_ref() == Some(event.id()) {
                self.show_window(ctx);
            } else if self.quit_item_id.as_ref() == Some(event.id()) {
                self.request_quit(ctx);
            }
        }

        self.background
    }
}

fn build_tray() -> Result<(TrayIcon, tray_icon::menu::MenuId, tray_icon::menu::MenuId), String> {
    let icon = load_icon()?;
    let menu = Menu::new();
    let show = MenuItem::new("\u{041e}\u{0442}\u{043a}\u{0442}\u{044b}\u{0442}\u{0444} VOID", true, None);
    let quit = MenuItem::new("\u{0412}\u{0445}\u{0439}\u{0442}\u{0438}", true, None);
    menu.append(&show).map_err(|e| e.to_string())?;
    menu.append(&PredefinedMenuItem::separator())
        .map_err(|e| e.to_string())?;
    menu.append(&quit).map_err(|e| e.to_string())?;

    let show_id = show.id().clone();
    let quit_id = quit.id().clone();

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("VOID \u{2014} \u{0440}\u{0430}\u{0431}\u{043e}\u{0442}\u{0430}\u{0435}\u{0442} \u{0432} \u{0444}\u{043e}\u{0438}\u{0435}")
        .with_icon(icon)
        .build()
        .map_err(|e| e.to_string())?;

    Ok((tray, show_id, quit_id))
}

fn load_icon() -> Result<tray_icon::Icon, String> {
    let bytes = include_bytes!("../static/ico.png");
    let img = image::load_from_memory(bytes)
        .map_err(|e| e.to_string())?
        .into_rgba8();
    let (w, h) = img.dimensions();
    let img = if w > 32 || h > 32 {
        image::imageops::resize(&img, 32, 32, image::imageops::FilterType::Triangle)
    } else {
        img
    };
    let (w, h) = img.dimensions();
    tray_icon::Icon::from_rgba(img.into_raw(), w, h).map_err(|e| e.to_string())
}
