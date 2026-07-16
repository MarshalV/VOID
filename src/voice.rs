//! Запись и воспроизведение голосовых (cpal + WinMM на Windows).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait};
use cpal::SampleFormat;

pub(crate) const VOICE_SAMPLE_RATE: u32 = 48_000;
pub(crate) const MAX_VOICE_DURATION_SECS: f32 = 300.0;

const CAPTURE_DRAIN_MS: u64 = 300;
const MIN_RECORD_SECS: f32 = 0.25;
const PROCESSING_TIMEOUT: Duration = Duration::from_secs(12);

pub(crate) enum VoiceRecorderState {
    Idle,
    Recording { started: Instant },
    Processing,
    Ready { path: PathBuf, duration_secs: f32 },
    Error(String),
}

pub(crate) struct VoiceRecorder {
    pub(crate) state: VoiceRecorderState,
    child: Option<Child>,
    /// Linux: запись в потоке (без повторного spawn exe).
    record_done_rx: Option<Receiver<Result<f32, String>>>,
    wav_path: PathBuf,
    stop_path: PathBuf,
    recording_started: Option<Instant>,
    processing_since: Option<Instant>,
    pub(crate) last_status: String,
}

pub(crate) enum MicClick {
    Started,
    Stopped,
    Busy,
    DiscardedReady,
    Error(String),
}

impl VoiceRecorder {
    pub(crate) fn new() -> Self {
        Self {
            state: VoiceRecorderState::Idle,
            child: None,
            record_done_rx: None,
            wav_path: PathBuf::new(),
            stop_path: PathBuf::new(),
            recording_started: None,
            processing_since: None,
            last_status: String::new(),
        }
    }

    /// `true`, если запись только что перешла в `Ready`.
    pub(crate) fn poll(&mut self) -> bool {
        if matches!(self.state, VoiceRecorderState::Processing) {
            if let Some(since) = self.processing_since {
                if since.elapsed() >= PROCESSING_TIMEOUT {
                    self.force_reset();
                    self.state = VoiceRecorderState::Error(
                        "Запись зависла — попробуйте снова".into(),
                    );
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Some(rx) = self.record_done_rx.as_ref() {
                if let Ok(result) = rx.try_recv() {
                    self.record_done_rx = None;
                    self.recording_started = None;
                    return self.finish_recording_result(result);
                }
            }
        }

        let Some(child) = self.child.as_mut() else {
            return false;
        };

        match child.try_wait() {
            Ok(Some(status)) => {
                self.child = None;
                self.recording_started = None;
                voice_log(&format!("child exit: {status}"));
                if status.success() && self.wav_path.is_file() {
                    self.finish_recording_wav()
                } else {
                    let exe = std::env::current_exe()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    self.state = self.set_error(format!(
                        "Запись не удалась (код {status}). Разрешите микрофон для: {exe}"
                    ));
                    false
                }
            }
            Ok(None) => false,
            Err(e) => {
                self.child = None;
                self.state = self.set_error(format!("Ошибка ожидания записи: {e}"));
                false
            }
        }
    }

    fn finish_recording_wav(&mut self) -> bool {
        match wav_duration(&self.wav_path) {
            Ok(duration_secs) => {
                self.last_status =
                    format!("Голосовое {} готово", fmt_duration(duration_secs));
                self.state = VoiceRecorderState::Ready {
                    path: self.wav_path.clone(),
                    duration_secs,
                };
                voice_log(&format!(
                    "ready {} ({duration_secs:.2}s)",
                    self.wav_path.display()
                ));
                true
            }
            Err(e) => {
                self.state = self.set_error(e);
                false
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn finish_recording_result(&mut self, result: Result<f32, String>) -> bool {
        match result {
            Ok(duration_secs) if self.wav_path.is_file() && duration_secs >= MIN_RECORD_SECS => {
                self.last_status =
                    format!("Голосовое {} готово", fmt_duration(duration_secs));
                self.state = VoiceRecorderState::Ready {
                    path: self.wav_path.clone(),
                    duration_secs,
                };
                voice_log(&format!(
                    "ready {} ({duration_secs:.2}s)",
                    self.wav_path.display()
                ));
                true
            }
            Ok(_) => {
                self.state = self.set_error("Запись слишком короткая".into());
                false
            }
            Err(e) => {
                self.state = self.set_error(e);
                false
            }
        }
    }

    fn set_error(&mut self, e: String) -> VoiceRecorderState {
        self.last_status = e.clone();
        VoiceRecorderState::Error(e)
    }

    pub(crate) fn take_error(&mut self) -> Option<String> {
        if let VoiceRecorderState::Error(e) =
            std::mem::replace(&mut self.state, VoiceRecorderState::Idle)
        {
            Some(e)
        } else {
            None
        }
    }

    pub(crate) fn is_recording(&self) -> bool {
        matches!(self.state, VoiceRecorderState::Recording { .. })
    }

    /// Идёт запись (по состоянию или живой дочерний процесс / поток на Linux).
    pub(crate) fn on_air(&self) -> bool {
        self.is_recording()
            || (self.child.is_some() && !self.is_processing())
            || self.record_done_rx.is_some()
    }

    /// Микрофон занят (запись или обработка), в т.ч. если дочерний процесс ещё жив.
    pub(crate) fn mic_active(&self) -> bool {
        self.on_air() || self.is_processing()
    }

    pub(crate) fn is_processing(&self) -> bool {
        matches!(self.state, VoiceRecorderState::Processing)
    }

    pub(crate) fn has_ready(&self) -> bool {
        matches!(self.state, VoiceRecorderState::Ready { .. })
    }

    pub(crate) fn recording_elapsed(&self) -> Option<f32> {
        if let VoiceRecorderState::Recording { started } = &self.state {
            return Some(started.elapsed().as_secs_f32());
        }
        self.recording_started
            .map(|t| t.elapsed().as_secs_f32())
    }

    pub(crate) fn take_ready(&mut self) -> Option<(PathBuf, f32)> {
        if let VoiceRecorderState::Ready {
            path,
            duration_secs,
        } = std::mem::replace(&mut self.state, VoiceRecorderState::Idle)
        {
            self.last_status.clear();
            Some((path, duration_secs))
        } else {
            None
        }
    }

    pub(crate) fn ready_duration(&self) -> Option<f32> {
        match &self.state {
            VoiceRecorderState::Ready { duration_secs, .. } => Some(*duration_secs),
            _ => None,
        }
    }

    pub(crate) fn discard_ready(&mut self) {
        if self.has_ready() {
            self.state = VoiceRecorderState::Idle;
            self.last_status.clear();
        }
    }

    pub(crate) fn handle_mic_click(&mut self) -> MicClick {
        if self.is_processing() {
            return MicClick::Busy;
        }
        if self.on_air() {
            self.stop_recording();
            self.last_status = "Обработка записи…".into();
            return MicClick::Stopped;
        }
        if self.has_ready() {
            self.discard_ready();
            return MicClick::DiscardedReady;
        }
        match self.start_recording() {
            Ok(()) => {
                self.last_status = "Запись…".into();
                MicClick::Started
            }
            Err(e) => MicClick::Error(e),
        }
    }

    fn cleanup_child(&mut self) {
        if !self.stop_path.as_os_str().is_empty() {
            let _ = std::fs::write(&self.stop_path, b"stop");
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.record_done_rx = None;
    }

    fn start_recording(&mut self) -> Result<(), String> {
        if self.has_ready() {
            return Err("Сначала отправьте или отмените голосовое (▶ или ✖)".into());
        }
        self.cleanup_child();

        let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S_%f");
        let wav_path = std::env::temp_dir().join(format!("void_voice_{stamp}.wav"));
        let stop_path = std::env::temp_dir().join(format!("void_voice_{stamp}.stop"));
        let _ = std::fs::remove_file(&wav_path);
        let _ = std::fs::remove_file(&stop_path);

        #[cfg(target_os = "linux")]
        {
            voice_log(&format!(
                "linux thread record -> {} stop={}",
                wav_path.display(),
                stop_path.display()
            ));
            let (stop_tx, stop_rx) = mpsc::channel::<()>();
            let stop_flag = stop_path.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                while !stop_flag.exists() {
                    if started.elapsed().as_secs_f32() >= MAX_VOICE_DURATION_SECS {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
                let _ = stop_tx.send(());
            });
            let wav_out = wav_path.clone();
            let stop_path_rec = stop_path.clone();
            let (done_tx, done_rx) = mpsc::channel();
            std::thread::spawn(move || {
                let result = record_to_wav(stop_rx, Some(&stop_path_rec), &wav_out);
                let _ = done_tx.send(result);
            });
            self.record_done_rx = Some(done_rx);
            self.wav_path = wav_path;
            self.stop_path = stop_path;
            let started = Instant::now();
            self.recording_started = Some(started);
            self.state = VoiceRecorderState::Recording { started };
            return Ok(());
        }

        #[cfg(not(target_os = "linux"))]
        {
            let exe = std::env::current_exe().map_err(|e| format!("exe: {e}"))?;
            voice_log(&format!(
                "spawn {} --voice-record {} {}",
                exe.display(),
                wav_path.display(),
                stop_path.display()
            ));

            let child = Command::new(&exe)
                .arg("--voice-record")
                .arg(&wav_path)
                .arg(&stop_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("Не удалось запустить запись: {e}"))?;

            self.child = Some(child);
            self.wav_path = wav_path;
            self.stop_path = stop_path;
            let started = Instant::now();
            self.recording_started = Some(started);
            self.state = VoiceRecorderState::Recording { started };
            Ok(())
        }
    }

    fn stop_recording(&mut self) {
        if self.on_air() {
            if !self.stop_path.as_os_str().is_empty() {
                let _ = std::fs::write(&self.stop_path, b"stop");
            }
            self.processing_since = Some(Instant::now());
            self.state = VoiceRecorderState::Processing;
            voice_log("stop file written");
        }
    }

    fn force_reset(&mut self) {
        self.cleanup_child();
        self.processing_since = None;
        self.recording_started = None;
        self.state = VoiceRecorderState::Idle;
        self.last_status.clear();
    }
}

pub(crate) const VOICE_BUILD: &str = "v5h-bubble";

/// CLI: `--voice-probe` | `--voice-record <wav> <stop-file>`
pub(crate) fn run_cli_mode() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("--voice-probe") => {
            let code = match probe_microphone() {
                Ok(name) => {
                    println!("OK: {name}");
                    0
                }
                Err(e) => {
                    eprintln!("ERR: {e}");
                    1
                }
            };
            Some(code)
        }
        Some("--voice-diag") => {
            println!("{}", build_diagnostic_report());
            Some(0)
        }
        Some("--voice-record") => {
            let out = args.get(2).cloned().unwrap_or_default();
            let stop = args.get(3).cloned().unwrap_or_default();
            if out.is_empty() || stop.is_empty() {
                eprintln!("usage: --voice-record <out.wav> <stop-file>");
                return Some(2);
            }
            let code = match cli_record(PathBuf::from(out), PathBuf::from(stop)) {
                Ok(secs) => {
                    println!("OK: {secs:.2}");
                    0
                }
                Err(e) => {
                    voice_log(&format!("cli err: {e}"));
                    eprintln!("ERR: {e}");
                    1
                }
            };
            Some(code)
        }
        Some("--voice-play") => {
            let path = args.get(2).cloned().unwrap_or_default();
            if path.is_empty() {
                eprintln!("usage: --voice-play <file.wav>");
                return Some(2);
            }
            let stop_flag = AtomicBool::new(false);
            let frame_pos = Arc::new(AtomicUsize::new(0));
            let code = match play_wav_file(Path::new(&path), &stop_flag, 0.0, frame_pos) {
                Ok(()) => {
                    println!("OK: played {}", path);
                    0
                }
                Err(e) => {
                    eprintln!("ERR: {e}");
                    1
                }
            };
            Some(code)
        }
        _ => None,
    }
}

fn cli_record(out: PathBuf, stop_file: PathBuf) -> Result<f32, String> {
    voice_log(&format!(
        "cli start -> {} stop={}",
        out.display(),
        stop_file.display()
    ));
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let stop_flag = stop_file.clone();
    std::thread::spawn(move || {
        let started = Instant::now();
        while !stop_flag.exists() {
            if started.elapsed().as_secs_f32() >= MAX_VOICE_DURATION_SECS {
                break;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        let _ = stop_tx.send(());
    });
    record_to_wav(stop_rx, Some(&stop_file), &out)
}

fn audio_host() -> cpal::Host {
    #[cfg(target_os = "linux")]
    {
        use cpal::traits::HostTrait;
        if let Ok(host) = cpal::host_from_id(cpal::HostId::Alsa) {
            if host.default_input_device().is_some() || host.default_output_device().is_some() {
                voice_log("audio host: Alsa");
                return host;
            }
        }
    }
    cpal::default_host()
}

/// Быстрая проверка микрофона при старте.
pub(crate) fn probe_microphone() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        if linux_has_external_recorder() {
            voice_log("probe ok: pw-record/parecord");
            return Ok("pipewire".into());
        }
    }
    let host = audio_host();
    let device = host
        .default_input_device()
        .ok_or_else(|| "Системный микрофон не найден".to_string())?;
    let name = device.name().map_err(|e| format!("Микрофон: {e}"))?;
    device
        .default_input_config()
        .map_err(|e| format!("Профиль микрофона: {e}"))?;
    voice_log(&format!("probe ok: {name}"));
    Ok(name)
}

/// Полный дамп аудио-окружения для диагностики (`--voice-diag`): какие внешние
/// плееры/рекордеры найдены, какие desktop-сессии обнаружены, что видит cpal
/// (устройства входа/выхода). Позволяет понять причину без доступа к машине.
fn build_diagnostic_report() -> String {
    let mut out = String::new();
    out.push_str(&format!("OS: {}\n", std::env::consts::OS));
    out.push_str(&format!("VOID_BUILD: {VOICE_BUILD}\n\n"));

    #[cfg(target_os = "linux")]
    {
        out.push_str("--- Linux: внешние инструменты ---\n");
        for tool in ["pw-record", "parecord", "paplay", "pw-cat", "pw-play", "aplay", "runuser"] {
            let found = Command::new(tool).arg("--version").output().is_ok()
                || Command::new("which").arg(tool).output().is_ok_and(|o| o.status.success());
            out.push_str(&format!("  {tool}: {}\n", if found { "найден" } else { "НЕ найден" }));
        }
        out.push_str(&format!("  запущено как root: {}\n", running_as_root()));
        out.push_str(&format!(
            "  USER={:?} XDG_RUNTIME_DIR={:?} PULSE_SERVER={:?}\n",
            std::env::var("USER").unwrap_or_default(),
            std::env::var("XDG_RUNTIME_DIR").unwrap_or_default(),
            std::env::var("PULSE_SERVER").unwrap_or_default(),
        ));

        out.push_str("\n--- Linux: desktop-сессии (/run/user/<uid>/pulse/native) ---\n");
        let sessions = linux_desktop_sessions();
        if sessions.is_empty() {
            out.push_str("  НЕ найдено ни одной сессии с работающим PulseAudio/PipeWire socket.\n");
            out.push_str("  (нормально для SSH/headless-сессии без залогиненного desktop; для звука\n");
            out.push_str("   там нужен виртуальный sink или запуск pipewire/pulseaudio вручную.)\n");
        } else {
            for s in &sessions {
                out.push_str(&format!(
                    "  user={} runtime_dir={} pulse={}\n",
                    s.username,
                    s.runtime_dir.display(),
                    s.pulse_server
                ));
            }
        }

        out.push_str(&format!(
            "\n  всего наборов env для fallback-запуска плееров/рекордеров: {}\n",
            linux_env_sets().len()
        ));

        out.push_str("\n--- Linux: состояние sink (звук/mute/громкость в сессии) ---\n");
        if sessions.is_empty() {
            out.push_str("  нет сессии — не проверяю.\n");
        } else {
            for s in &sessions {
                let env = [
                    ("PULSE_SERVER".to_string(), s.pulse_server.clone()),
                    (
                        "XDG_RUNTIME_DIR".to_string(),
                        s.runtime_dir.display().to_string(),
                    ),
                ];
                for (label, cmd, args) in [
                    ("default sink", "pactl", vec!["get-default-sink"]),
                    ("sinks", "pactl", vec!["list", "sinks", "short"]),
                    ("mute", "pactl", vec!["get-sink-mute", "@DEFAULT_SINK@"]),
                    ("volume", "pactl", vec!["get-sink-volume", "@DEFAULT_SINK@"]),
                    ("wpctl status", "wpctl", vec!["status"]),
                ] {
                    match linux_run_as_user_capture(&s.username, cmd, &args, &env) {
                        Ok(text) => {
                            out.push_str(&format!("  [{}] {label}:\n", s.username));
                            for line in text.lines() {
                                out.push_str(&format!("    {line}\n"));
                            }
                        }
                        Err(e) => out.push_str(&format!("  [{}] {label}: ошибка — {e}\n", s.username)),
                    }
                }
            }
        }
    }

    out.push_str("\n--- cpal (ALSA/системный аудио-стек) ---\n");
    let host = audio_host();
    out.push_str(&format!("  host: {:?}\n", host.id()));
    match host.default_input_device() {
        Some(d) => {
            out.push_str(&format!(
                "  default input: {} config={:?}\n",
                d.name().unwrap_or_default(),
                d.default_input_config()
            ));
        }
        None => out.push_str("  default input: НЕ найден\n"),
    }
    match host.default_output_device() {
        Some(d) => {
            out.push_str(&format!(
                "  default output: {} config={:?}\n",
                d.name().unwrap_or_default(),
                d.default_output_config()
            ));
        }
        None => out.push_str("  default output: НЕ найден\n"),
    }
    match host.devices() {
        Ok(devs) => {
            out.push_str("  все устройства:\n");
            for d in devs {
                let name = d.name().unwrap_or_else(|_| "?".into());
                let is_in = d.default_input_config().is_ok();
                let is_out = d.default_output_config().is_ok();
                out.push_str(&format!(
                    "    - {name} (in={is_in} out={is_out})\n"
                ));
            }
        }
        Err(e) => out.push_str(&format!("  перечисление устройств: ошибка {e}\n")),
    }
    out
}

pub(crate) fn voice_log(msg: &str) {
    let dir = crate::file_transfer::voice_dir_absolute();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("void_voice.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(
            f,
            "[{}] {msg}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
    }
}

fn pick_input_config(device: &cpal::Device) -> Result<cpal::SupportedStreamConfig, String> {
    device
        .default_input_config()
        .map_err(|e| format!("Микрофон: {e}"))
}

#[cfg(target_os = "linux")]
fn linux_has_external_recorder() -> bool {
    Command::new("pw-record").arg("--version").output().is_ok()
        || Command::new("parecord").arg("--version").output().is_ok()
}

#[cfg(target_os = "linux")]
fn linux_record_should_stop(_stop_rx: &Receiver<()>, stop_file: Option<&Path>) -> bool {
    stop_file.is_some_and(|p| p.exists())
}

#[cfg(target_os = "linux")]
fn linux_term_child(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let pid = child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &pid]).status();
    let deadline = Instant::now() + Duration::from_millis(600);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn linux_spawn_recorder(
    cmd: &str,
    args: &[&str],
    out: &Path,
    env: &[(String, String)],
) -> Result<Child, String> {
    let mut command = Command::new(cmd);
    for arg in args {
        command.arg(arg);
    }
    for (k, v) in env {
        command.env(k, v);
    }
    command
        .arg(out)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd}: {e}"))
}

#[cfg(target_os = "linux")]
fn linux_spawn_recorder_as_user(
    username: &str,
    cmd: &str,
    args: &[&str],
    out: &Path,
    env: &[(String, String)],
) -> Result<Child, String> {
    let mut runuser = Command::new("runuser");
    runuser.arg("-u").arg(username).arg("--").arg(cmd);
    for arg in args {
        runuser.arg(arg);
    }
    for (k, v) in env {
        runuser.env(k, v);
    }
    runuser
        .arg(out)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("runuser -u {username} {cmd}: {e}"))
}

#[cfg(target_os = "linux")]
fn linux_wait_recorder(
    child: &mut Child,
    stop_rx: &Receiver<()>,
    stop_file: Option<&Path>,
    label: &str,
) {
    let started = Instant::now();
    loop {
        if linux_record_should_stop(stop_rx, stop_file) {
            voice_log(&format!("record stop ({label})"));
            linux_term_child(child);
            return;
        }
        if started.elapsed().as_secs_f32() >= MAX_VOICE_DURATION_SECS {
            voice_log(&format!("record max duration ({label})"));
            linux_term_child(child);
            return;
        }
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(35)),
            Err(e) => {
                voice_log(&format!("record wait err ({label}): {e}"));
                return;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_try_recorder(
    label: &str,
    child: Result<Child, String>,
    stop_rx: &Receiver<()>,
    stop_file: Option<&Path>,
    out: &Path,
    last_err: &mut String,
) -> Result<f32, String> {
    let mut child = child.map_err(|e| {
        *last_err = e.clone();
        e
    })?;
    voice_log(&format!("record try {label} -> {}", out.display()));
    linux_wait_recorder(&mut child, stop_rx, stop_file, label);
    if !out.is_file() {
        *last_err = format!("{label}: файл не создан");
        return Err(last_err.clone());
    }
    match wav_duration(out) {
        Ok(d) if d >= MIN_RECORD_SECS => {
            voice_log(&format!("record done {label} ({d:.2}s)"));
            Ok(d)
        }
        Ok(d) => {
            *last_err = format!("{label}: слишком короткая запись ({d:.2}s)");
            Err(last_err.clone())
        }
        Err(e) => {
            *last_err = format!("{label}: {e}");
            Err(last_err.clone())
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_record_to_wav(
    stop_rx: &Receiver<()>,
    stop_file: Option<&Path>,
    out: &Path,
) -> Result<f32, String> {
    let _ = std::fs::remove_file(out);
    let mut last_err = String::from("pw-record/parecord недоступны");
    let recorders: [(&str, &[&str]); 3] = [
        ("pw-record", &["--rate", "48000", "--channels", "1"]),
        (
            "parecord",
            &["--file-format=wav", "--rate", "48000", "--channels", "1"],
        ),
        ("parecord", &["--format=wav", "--rate", "48000", "--channels", "1"]),
    ];

    for session in linux_desktop_sessions() {
        let session_env = [
            ("PULSE_SERVER".into(), session.pulse_server.clone()),
            (
                "XDG_RUNTIME_DIR".into(),
                session.runtime_dir.display().to_string(),
            ),
        ];
        for (cmd, args) in &recorders {
            let tag = format!("runuser:{} {cmd}", session.username);
            if let Ok(d) = linux_try_recorder(
                &tag,
                linux_spawn_recorder_as_user(
                    &session.username,
                    cmd,
                    args,
                    out,
                    &session_env,
                ),
                &stop_rx,
                stop_file,
                out,
                &mut last_err,
            ) {
                return Ok(d);
            }
        }
    }

    for env in linux_env_sets() {
        for (cmd, args) in &recorders {
            let tag = format!(
                "{cmd}{}",
                env.iter()
                    .find(|(k, _)| k == "PULSE_SERVER")
                    .map(|(_, v)| format!("@{v}"))
                    .unwrap_or_default()
            );
            if let Ok(d) = linux_try_recorder(
                &tag,
                linux_spawn_recorder(cmd, args, out, &env),
                &stop_rx,
                stop_file,
                out,
                &mut last_err,
            ) {
                return Ok(d);
            }
        }
    }

    Err(last_err)
}

fn record_to_wav(
    stop_rx: Receiver<()>,
    stop_file: Option<&Path>,
    out: &Path,
) -> Result<f32, String> {
    #[cfg(target_os = "linux")]
    if linux_has_external_recorder() {
        match linux_record_to_wav(&stop_rx, stop_file, out) {
            Ok(d) => return Ok(d),
            Err(e) => voice_log(&format!("linux record miss: {e}")),
        }
    }

    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

    let host = audio_host();
    let device = host
        .default_input_device()
        .ok_or_else(|| "Системный микрофон не найден".to_string())?;
    let device_name = device.name().unwrap_or_else(|_| "?".into());
    voice_log(&format!("device: {device_name}"));
    let config = pick_input_config(&device)
        .map_err(|e| format!("{e} ({device_name})"))?;
    voice_log(&format!("config: {:?}", config));

    let sample_rate = config.sample_rate().0;
    let channels = config.channels() as usize;
    let (sample_tx, sample_rx) = mpsc::sync_channel::<Vec<f32>>(4096);
    let err_flag = Arc::new(AtomicBool::new(false));

    let stream = build_input_stream(&device, &config, sample_tx, err_flag.clone())?;
    stream
        .play()
        .map_err(|e| format!("Не удалось начать запись: {e} ({device_name})"))?;
    voice_log("stream.play ok");

    let started = Instant::now();
    let mut stop_requested = false;
    let mut samples: Vec<f32> = Vec::new();
    let max_samples =
        (sample_rate as f32 * MAX_VOICE_DURATION_SECS) as usize * channels.max(1);

    loop {
        if stop_rx.try_recv().is_ok() || stop_file.is_some_and(|p| p.exists()) {
            stop_requested = true;
        }
        if err_flag.load(Ordering::Relaxed) {
            return Err(format!("Ошибка потока записи ({device_name})"));
        }

        while let Ok(chunk) = sample_rx.try_recv() {
            samples.extend(chunk);
        }

        let elapsed = started.elapsed().as_secs_f32();
        if stop_requested && elapsed >= MIN_RECORD_SECS {
            break;
        }
        if samples.len() >= max_samples {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    std::thread::sleep(Duration::from_millis(CAPTURE_DRAIN_MS));
    while let Ok(chunk) = sample_rx.try_recv() {
        samples.extend(chunk);
    }
    drop(stream);
    voice_log(&format!("captured {} samples", samples.len()));

    if samples.is_empty() {
        return Err(format!(
            "Запись пуста ({device_name}). Разрешите микрофон: Параметры → Конфиденциальность → Микрофон."
        ));
    }

    let mono = downmix_to_mono(&samples, channels);
    let duration_secs = mono.len() as f32 / sample_rate as f32;
    if duration_secs < MIN_RECORD_SECS {
        return Err("Слишком короткая запись — говорите дольше".into());
    }

    let mono = if sample_rate == VOICE_SAMPLE_RATE {
        mono
    } else {
        resample_linear(&mono, sample_rate, VOICE_SAMPLE_RATE)
    };
    let duration_secs = mono.len() as f32 / VOICE_SAMPLE_RATE as f32;

    write_wav_mono(out, &mono, VOICE_SAMPLE_RATE)?;
    voice_log(&format!("saved {} ({duration_secs:.2}s)", out.display()));
    Ok(duration_secs)
}

fn wav_duration(path: &Path) -> Result<f32, String> {
    let reader = hound::WavReader::open(path).map_err(|e| format!("WAV: {e}"))?;
    let spec = reader.spec();
    Ok(reader.len() as f32 / spec.sample_rate as f32)
}

fn playback_pcm_frames(path: &Path) -> Result<usize, String> {
    let (mono, src_rate) = read_wav_mono_f32(path)?;
    Ok(if src_rate == VOICE_SAMPLE_RATE {
        mono.len()
    } else {
        resample_linear(&mono, src_rate, VOICE_SAMPLE_RATE).len()
    })
}

fn build_input_stream(
    device: &cpal::Device,
    config: &cpal::SupportedStreamConfig,
    sample_tx: SyncSender<Vec<f32>>,
    err_flag: Arc<AtomicBool>,
) -> Result<cpal::Stream, String> {
    use cpal::traits::StreamTrait;

    let stream_cfg: cpal::StreamConfig = config.clone().into();
    let push = move |chunk: Vec<f32>| {
        match sample_tx.try_send(chunk) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => {}
        }
    };

    macro_rules! mk_stream {
        ($fmt:ident, $map:expr) => {{
            let err_flag = err_flag.clone();
            device
                .build_input_stream(
                    &stream_cfg,
                    move |data, _| $map(data, &push),
                    move |e| {
                        voice_log(&format!("cpal stream error: {e}"));
                        err_flag.store(true, Ordering::Relaxed);
                    },
                    None,
                )
                .map_err(|e| format!("Поток {:?}: {e}", config.sample_format()))
        }};
    }

    match config.sample_format() {
        SampleFormat::F32 => mk_stream!(F32, |data: &[f32], push: &dyn Fn(Vec<f32>)| {
            push(data.to_vec());
        }),
        SampleFormat::I16 => mk_stream!(I16, |data: &[i16], push: &dyn Fn(Vec<f32>)| {
            push(data.iter().map(|&v| v as f32 / i16::MAX as f32).collect());
        }),
        SampleFormat::U16 => mk_stream!(U16, |data: &[u16], push: &dyn Fn(Vec<f32>)| {
            push(
                data.iter()
                    .map(|&v| (v as f32 - u16::MAX as f32 / 2.0) / (u16::MAX as f32 / 2.0))
                    .collect(),
            );
        }),
        SampleFormat::I32 => mk_stream!(I32, |data: &[i32], push: &dyn Fn(Vec<f32>)| {
            push(data.iter().map(|&v| v as f32 / i32::MAX as f32).collect());
        }),
        other => Err(format!("Формат микрофона {other:?} не поддерживается")),
    }
}

fn downmix_to_mono(samples: &[f32], channels: usize) -> Vec<f32> {
    if channels <= 1 {
        return samples.to_vec();
    }
    let frames = samples.len() / channels;
    let mut mono = Vec::with_capacity(frames);
    for frame in 0..frames {
        let base = frame * channels;
        let sum: f32 = (0..channels).map(|c| samples[base + c]).sum();
        mono.push(sum / channels as f32);
    }
    mono
}

fn resample_linear(input: &[f32], from_rate: u32, to_rate: u32) -> Vec<f32> {
    if from_rate == 0 || to_rate == 0 || input.is_empty() || from_rate == to_rate {
        return input.to_vec();
    }
    let ratio = from_rate as f64 / to_rate as f64;
    let out_len = ((input.len() as f64) / ratio).ceil() as usize;
    let mut out = Vec::with_capacity(out_len.max(1));
    for i in 0..out_len {
        let src_pos = i as f64 * ratio;
        let idx = src_pos.floor() as usize;
        let frac = (src_pos - idx as f64) as f32;
        let s0 = input.get(idx).copied().unwrap_or(0.0);
        let s1 = input.get(idx.saturating_add(1)).copied().unwrap_or(s0);
        out.push(s0 + (s1 - s0) * frac);
    }
    out
}

fn write_wav_mono(path: &Path, samples: &[f32], sample_rate: u32) -> Result<(), String> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer =
        hound::WavWriter::create(path, spec).map_err(|e| format!("Не удалось создать WAV: {e}"))?;
    for &s in samples {
        let sample = (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
        writer
            .write_sample(sample)
            .map_err(|e| format!("Ошибка записи WAV: {e}"))?;
    }
    writer
        .finalize()
        .map_err(|e| format!("Ошибка финализации WAV: {e}"))?;
    Ok(())
}

// ─── Воспроизведение ─────────────────────────────────────────────────────────

pub(crate) struct VoicePlayer {
    done_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) playing_id: Option<String>,
    last_error: Option<String>,
    stop_flag: Option<Arc<AtomicBool>>,
    frame_pos: Option<Arc<AtomicUsize>>,
    total_frames: usize,
    duration_secs: f32,
}

impl VoicePlayer {
    pub(crate) fn new() -> Self {
        Self {
            done_rx: None,
            playing_id: None,
            last_error: None,
            stop_flag: None,
            frame_pos: None,
            total_frames: 0,
            duration_secs: 0.0,
        }
    }

    pub(crate) fn take_error(&mut self) -> Option<String> {
        self.last_error.take()
    }

    pub(crate) fn is_playing(&self, transfer_id: &str) -> bool {
        self.playing_id
            .as_deref()
            .is_some_and(|id| id.eq_ignore_ascii_case(transfer_id))
    }

    /// Доля пройденного времени [0..1] для активного голосового.
    pub(crate) fn progress_ratio(&self, transfer_id: &str) -> Option<f32> {
        if !self.is_playing(transfer_id) || self.total_frames == 0 {
            return None;
        }
        let pos = self.frame_pos.as_ref()?.load(Ordering::Relaxed);
        Some((pos as f32 / self.total_frames as f32).clamp(0.0, 1.0))
    }

    /// `true` = запущено, `false` = остановлено.
    pub(crate) fn toggle(&mut self, transfer_id: &str, path: &Path) -> Result<bool, String> {
        let tid = transfer_id.to_ascii_lowercase();
        if self.is_playing(&tid) {
            self.stop();
            return Ok(false);
        }
        self.play_from(&tid, path, 0.0)?;
        Ok(true)
    }

    /// Воспроизвести (или перемотать) с позиции `start_ratio` ∈ [0, 1].
    pub(crate) fn play_from(
        &mut self,
        transfer_id: &str,
        path: &Path,
        start_ratio: f32,
    ) -> Result<(), String> {
        let tid = transfer_id.to_ascii_lowercase();
        if self.playing_id.is_some() || self.done_rx.is_some() {
            self.stop();
        }

        if !path.is_file() {
            return Err(format!("Аудиофайл не найден: {}", path.display()));
        }

        let duration_secs = wav_duration(path).unwrap_or(0.0);
        self.total_frames = playback_pcm_frames(path).unwrap_or(0);
        let start_frame = (self.total_frames as f32 * start_ratio.clamp(0.0, 1.0)) as usize;
        let stop_flag = Arc::new(AtomicBool::new(false));
        let frame_pos = Arc::new(AtomicUsize::new(start_frame));
        let (done_tx, done_rx) = mpsc::channel();
        self.stop_flag = Some(stop_flag.clone());
        self.frame_pos = Some(frame_pos.clone());
        self.done_rx = Some(done_rx);
        self.playing_id = Some(tid);
        self.duration_secs = duration_secs;

        let path = path.to_path_buf();
        let ratio = start_ratio.clamp(0.0, 1.0);
        std::thread::spawn(move || {
            let result = play_wav_file(&path, &stop_flag, ratio, frame_pos);
            let _ = done_tx.send(result);
        });
        Ok(())
    }

    pub(crate) fn stop(&mut self) {
        if let Some(flag) = &self.stop_flag {
            flag.store(true, Ordering::Relaxed);
        }
        #[cfg(target_os = "windows")]
        stop_winmm_playback();
        self.done_rx = None;
        self.stop_flag = None;
        self.playing_id = None;
        self.frame_pos = None;
        self.total_frames = 0;
    }

    pub(crate) fn poll(&mut self) {
        let Some(rx) = self.done_rx.as_ref() else {
            return;
        };
        let Ok(result) = rx.try_recv() else {
            return;
        };
        self.done_rx = None;
        self.stop_flag = None;
        self.frame_pos = None;
        self.playing_id = None;
        self.total_frames = 0;
        if let Err(e) = result {
            self.last_error = Some(e);
        }
    }
}

fn play_wav_file(
    path: &Path,
    stop_flag: &AtomicBool,
    start_ratio: f32,
    frame_pos: Arc<AtomicUsize>,
) -> Result<(), String> {
    let path = normalize_playback_path(path);
    voice_log(&format!("play {} from {:.0}%", path.display(), start_ratio * 100.0));

    #[cfg(target_os = "linux")]
    {
        match play_wav_linux(&path, stop_flag, start_ratio, frame_pos.clone()) {
            Ok(()) => return Ok(()),
            Err(ext_err) => {
                if stop_flag.load(Ordering::Relaxed) {
                    return Ok(());
                }
                voice_log(&format!(
                    "linux external players failed ({ext_err}) — пробую cpal/ALSA как последний резерв"
                ));
                return match play_wav_cpal(&path, stop_flag, start_ratio, frame_pos) {
                    Ok(()) => {
                        voice_log("play done (cpal/ALSA fallback)");
                        Ok(())
                    }
                    Err(cpal_err) => Err(format!("{ext_err}; cpal/ALSA: {cpal_err}")),
                };
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    match play_wav_cpal(&path, stop_flag, start_ratio, frame_pos) {
        Ok(()) => {
            voice_log("play done (cpal)");
            Ok(())
        }
        Err(cpal_err) => {
            if stop_flag.load(Ordering::Relaxed) {
                return Ok(());
            }
            if start_ratio > 0.001 {
                return Err(format!(
                    "Перемотка недоступна (cpal: {cpal_err}). Попробуйте с начала."
                ));
            }
            #[cfg(target_os = "windows")]
            {
                play_wav_winmm(&path, stop_flag)
                    .map_err(|winmm_err| format!("cpal: {cpal_err}; winmm: {winmm_err}"))
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err(cpal_err)
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct LinuxDesktopSession {
    username: String,
    runtime_dir: PathBuf,
    pulse_server: String,
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    std::env::var("USER").is_ok_and(|u| u == "root")
        || std::env::var("UID").is_ok_and(|u| u == "0")
}

#[cfg(target_os = "linux")]
fn linux_run_as_user_capture(
    username: &str,
    cmd: &str,
    args: &[&str],
    env: &[(String, String)],
) -> Result<String, String> {
    let mut runuser = Command::new("runuser");
    runuser.arg("-u").arg(username).arg("--").arg(cmd);
    runuser.args(args);
    for (k, v) in env {
        runuser.env(k, v);
    }
    let output = runuser
        .output()
        .map_err(|e| format!("runuser -u {username} {cmd}: {e}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let err_text = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !err_text.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str("stderr: ");
        text.push_str(&err_text);
    }
    if text.is_empty() {
        text = format!("(пусто, exit={})", output.status);
    }
    Ok(text)
}

#[cfg(target_os = "linux")]
fn linux_desktop_sessions() -> Vec<LinuxDesktopSession> {
    let mut sessions = Vec::new();
    // Обход через `runuser -u <user> -- ...` нужен ТОЛЬКО когда сам процесс
    // запущен от root и должен дотянуться до desktop-сессии обычного
    // пользователя. Если мы уже не root (рекомендуемый режим — запуск от
    // обычного пользователя напрямую), runuser попытки гарантированно
    // проваливаются (нет прав на переключение пользователя) и только тратят
    // время перед реальной прямой попыткой воспроизведения — пропускаем.
    if !running_as_root() {
        return sessions;
    }
    let Ok(entries) = std::fs::read_dir("/run/user") else {
        return sessions;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let uid = entry.file_name().to_string_lossy().into_owned();
        if uid == "0" {
            continue;
        }
        let runtime_dir = entry.path();
        let pulse = runtime_dir.join("pulse/native");
        if !pulse.exists() {
            continue;
        }
        let Ok(out) = Command::new("id").args(["-nu", &uid]).output() else {
            continue;
        };
        if !out.status.success() {
            continue;
        }
        let username = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if username.is_empty() || username == "root" {
            continue;
        }
        sessions.push(LinuxDesktopSession {
            username,
            runtime_dir: runtime_dir.clone(),
            pulse_server: format!("unix:{}", pulse.display()),
        });
    }
    sessions
}

#[cfg(target_os = "linux")]
fn linux_prepare_playback_pcm(
    src: &Path,
    start_ratio: f32,
) -> Result<(Vec<f32>, usize, f32), String> {
    let (mono, src_rate) = read_wav_mono_f32(src)?;
    let mono = if src_rate == VOICE_SAMPLE_RATE {
        mono
    } else {
        resample_linear(&mono, src_rate, VOICE_SAMPLE_RATE)
    };
    let start_frame =
        ((mono.len() as f32 * start_ratio.clamp(0.0, 1.0)) as usize).min(mono.len());
    let trimmed = mono[start_frame..].to_vec();
    let duration = trimmed.len() as f32 / VOICE_SAMPLE_RATE as f32;
    voice_log(&format!(
        "playback pcm {}/{} frames ({duration:.2}s @ {VOICE_SAMPLE_RATE}Hz)",
        trimmed.len(),
        mono.len()
    ));
    Ok((trimmed, start_frame, duration))
}

#[cfg(target_os = "linux")]
fn f32_pcm_as_bytes(samples: &[f32]) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            samples.as_ptr().cast::<u8>(),
            samples.len() * std::mem::size_of::<f32>(),
        )
    }
}

#[cfg(target_os = "linux")]
fn linux_push_pulse_server(servers: &mut Vec<String>, path: &Path) {
    if path.exists() {
        let s = format!("unix:{}", path.display());
        if !servers.iter().any(|x| x == &s) {
            servers.push(s);
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_pulse_servers() -> Vec<String> {
    if let Ok(existing) = std::env::var("PULSE_SERVER") {
        if !existing.trim().is_empty() {
            return vec![existing];
        }
    }
    let mut servers = Vec::new();
    if let Ok(uid) = std::env::var("SUDO_UID") {
        linux_push_pulse_server(
            &mut servers,
            &PathBuf::from(format!("/run/user/{uid}/pulse/native")),
        );
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        linux_push_pulse_server(&mut servers, &PathBuf::from(xdg).join("pulse/native"));
    }
    for session in linux_desktop_sessions() {
        if !servers.iter().any(|s| s == &session.pulse_server) {
            servers.push(session.pulse_server.clone());
        }
    }
    if let Ok(entries) = std::fs::read_dir("/run/user") {
        let mut uids: Vec<_> = entries.flatten().collect();
        uids.sort_by_key(|e| e.file_name());
        for entry in uids {
            linux_push_pulse_server(&mut servers, &entry.path().join("pulse/native"));
        }
    }
    servers
}

#[cfg(target_os = "linux")]
fn linux_env_sets() -> Vec<Vec<(String, String)>> {
    let mut sets = Vec::new();
    for session in linux_desktop_sessions() {
        sets.push(vec![
            ("PULSE_SERVER".into(), session.pulse_server.clone()),
            (
                "XDG_RUNTIME_DIR".into(),
                session.runtime_dir.display().to_string(),
            ),
        ]);
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let mut env = vec![("XDG_RUNTIME_DIR".into(), xdg)];
        if let Ok(ps) = std::env::var("PULSE_SERVER") {
            env.push(("PULSE_SERVER".into(), ps));
        }
        if !sets.iter().any(|s| s == &env) {
            sets.push(env);
        }
    }
    for server in linux_pulse_servers() {
        let mut env = vec![("PULSE_SERVER".into(), server.clone())];
        if let Some(runtime) = server.strip_prefix("unix:/run/user/") {
            if let Some(uid_dir) = runtime.strip_suffix("/pulse/native") {
                env.push(("XDG_RUNTIME_DIR".into(), format!("/run/user/{uid_dir}")));
            }
        }
        if !sets.iter().any(|s| s == &env) {
            sets.push(env);
        }
    }
    if !running_as_root() {
        sets.push(Vec::new());
    }
    sets
}

#[cfg(target_os = "linux")]
fn linux_player_stderr(child: &mut Child) -> String {
    let mut err_text = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        use std::io::Read;
        let _ = stderr.read_to_string(&mut err_text);
    }
    err_text.trim().to_string()
}

#[cfg(target_os = "linux")]
fn linux_write_pcm_and_wait(
    child: &mut Child,
    pcm: &[f32],
    stop_flag: &AtomicBool,
    frame_pos: &Arc<AtomicUsize>,
    start_frame: usize,
    label: &str,
) -> Result<(), String> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| format!("{label}: нет stdin"))?;
    let started = Instant::now();
    let expected_secs = pcm.len() as f32 / VOICE_SAMPLE_RATE as f32;
    const CHUNK_FRAMES: usize = 2048;
    let mut offset = 0usize;
    while offset < pcm.len() {
        if stop_flag.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            voice_log(&format!("play stopped ({label})"));
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            let err = linux_player_stderr(child);
            return Err(format!(
                "{label}: процесс завершился до конца ({status}){err}"
            ));
        }
        let end = (offset + CHUNK_FRAMES).min(pcm.len());
        stdin
            .write_all(f32_pcm_as_bytes(&pcm[offset..end]))
            .map_err(|e| format!("{label}: запись PCM: {e}"))?;
        frame_pos.store(start_frame + end, Ordering::Relaxed);
        offset = end;
    }
    drop(stdin);
    loop {
        if stop_flag.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            voice_log(&format!("play stopped ({label})"));
            return Ok(());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                let elapsed = started.elapsed().as_secs_f32();
                // Порог как в проверенной рабочей версии: считаем успехом, если
                // процесс прожил хотя бы ~35% ожидаемой длительности (более
                // строгий порог 50% на практике отбраковывал реально успешные
                // быстрые завершения плеера и ломал воспроизведение).
                let min_alive = if expected_secs > 0.4 {
                    (expected_secs * 0.35).min(expected_secs - 0.15).max(0.08)
                } else {
                    0.04
                };
                if elapsed + 0.05 < min_alive {
                    let msg = format!(
                        "{label}: подозрительно быстрый выход ({elapsed:.2}s при ожидаемых {expected_secs:.2}s) — считаю неуспехом"
                    );
                    voice_log(&msg);
                    return Err(msg);
                }
                frame_pos.store(start_frame + pcm.len(), Ordering::Relaxed);
                voice_log(&format!("play done ({label}, {elapsed:.2}s)"));
                return Ok(());
            }
            Ok(Some(status)) => {
                let err = linux_player_stderr(child);
                return Err(format!("{label} exit {status}: {err}"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(35)),
            Err(e) => return Err(format!("{label}: {e}")),
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_spawn_player_stdin(
    cmd: &str,
    args: &[&str],
    env: &[(String, String)],
) -> Result<Child, String> {
    let mut command = Command::new(cmd);
    command.args(args);
    for (k, v) in env {
        command.env(k, v);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd}: {e}"))
}

#[cfg(target_os = "linux")]
fn linux_spawn_as_user_stdin(
    username: &str,
    cmd: &str,
    args: &[&str],
    env: &[(String, String)],
) -> Result<Child, String> {
    let mut runuser = Command::new("runuser");
    runuser.arg("-u").arg(username).arg("--").arg(cmd);
    runuser.args(args);
    for (k, v) in env {
        runuser.env(k, v);
    }
    runuser
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("runuser -u {username} {cmd}: {e}"))
}

#[cfg(target_os = "linux")]
const LINUX_PAPLAY_ARGS: &[&str] = &[
    "--raw",
    "--rate",
    "48000",
    "--channels",
    "1",
    "--format",
    "float32le",
];

#[cfg(target_os = "linux")]
const LINUX_PW_CAT_ARGS: &[&str] = &[
    "-p",
    "--raw",
    "--rate",
    "48000",
    "--channels",
    "1",
    "--format",
    "f32",
    "-",
];

#[cfg(target_os = "linux")]
fn linux_try_pcm_stdin(
    label: &str,
    child: Result<Child, String>,
    pcm: &[f32],
    stop_flag: &AtomicBool,
    frame_pos: &Arc<AtomicUsize>,
    start_frame: usize,
    last_err: &mut String,
) -> Result<(), String> {
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            *last_err = e;
            return Err(last_err.clone());
        }
    };
    voice_log(&format!("try {label}"));
    match linux_write_pcm_and_wait(&mut child, pcm, stop_flag, frame_pos, start_frame, label) {
        Ok(()) => Ok(()),
        Err(e) => {
            *last_err = e;
            voice_log(last_err);
            Err(last_err.clone())
        }
    }
}

#[cfg(target_os = "linux")]
fn play_wav_linux_stdin(
    pcm: &[f32],
    stop_flag: &AtomicBool,
    frame_pos: Arc<AtomicUsize>,
    start_frame: usize,
) -> Result<(), String> {
    let players: [(&str, &[&str]); 2] = [("paplay", LINUX_PAPLAY_ARGS), ("pw-cat", LINUX_PW_CAT_ARGS)];
    let mut last_err = String::from("stdin-плееры недоступны");

    for session in linux_desktop_sessions() {
        let session_env = [
            ("PULSE_SERVER".into(), session.pulse_server.clone()),
            (
                "XDG_RUNTIME_DIR".into(),
                session.runtime_dir.display().to_string(),
            ),
        ];
        for (cmd, args) in &players {
            let tag = format!("runuser:{} {cmd} stdin", session.username);
            if linux_try_pcm_stdin(
                &tag,
                linux_spawn_as_user_stdin(&session.username, cmd, args, &session_env),
                pcm,
                stop_flag,
                &frame_pos,
                start_frame,
                &mut last_err,
            )
            .is_ok()
            {
                return Ok(());
            }
        }
    }

    for (cmd, args) in &players {
        for env in linux_env_sets() {
            let tag = format!(
                "{cmd} stdin{}",
                env.iter()
                    .find(|(k, _)| k == "PULSE_SERVER")
                    .map(|(_, v)| format!("@{v}"))
                    .unwrap_or_default()
            );
            if linux_try_pcm_stdin(
                &tag,
                linux_spawn_player_stdin(cmd, args, &env),
                pcm,
                stop_flag,
                &frame_pos,
                start_frame,
                &mut last_err,
            )
            .is_ok()
            {
                return Ok(());
            }
        }
    }

    Err(last_err)
}

#[cfg(target_os = "linux")]
fn linux_spawn_player(
    cmd: &str,
    args: &[&str],
    path: &Path,
    env: &[(String, String)],
) -> Result<Child, String> {
    let mut command = Command::new(cmd);
    for arg in args {
        command.arg(arg);
    }
    for (k, v) in env {
        command.env(k, v);
    }
    command
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd}: {e}"))
}

#[cfg(target_os = "linux")]
fn linux_spawn_as_user(
    username: &str,
    cmd: &str,
    args: &[&str],
    path: &Path,
    env: &[(String, String)],
) -> Result<Child, String> {
    let mut runuser = Command::new("runuser");
    runuser.arg("-u").arg(username).arg("--").arg(cmd);
    for arg in args {
        runuser.arg(arg);
    }
    for (k, v) in env {
        runuser.env(k, v);
    }
    runuser
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("runuser -u {username} {cmd}: {e}"))
}

#[cfg(target_os = "linux")]
fn linux_wait_player(
    child: &mut Child,
    stop_flag: &AtomicBool,
    expect_secs: f32,
    label: &str,
) -> Result<(), String> {
    let started = Instant::now();
    let max_wait = Duration::from_secs_f32(expect_secs + 2.0);
    loop {
        if stop_flag.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            voice_log(&format!("play stopped ({label})"));
            return Ok(());
        }
        if started.elapsed() > max_wait {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{label}: таймаут ({expect_secs:.1}s)"));
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                let elapsed = started.elapsed().as_secs_f32();
                let min_alive = if expect_secs > 0.4 {
                    (expect_secs * 0.35).min(expect_secs - 0.15).max(0.08)
                } else {
                    0.04
                };
                if elapsed + 0.05 < min_alive {
                    let msg = format!(
                        "{label}: подозрительно быстрый выход ({elapsed:.2}s при ожидаемых {expect_secs:.2}s) — считаю неуспехом"
                    );
                    voice_log(&msg);
                    return Err(msg);
                }
                voice_log(&format!("play done ({label}, {elapsed:.2}s)"));
                return Ok(());
            }
            Ok(Some(status)) => {
                let err = linux_player_stderr(child);
                return Err(format!("{label} exit {status}: {err}"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(35)),
            Err(e) => return Err(format!("{label}: {e}")),
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_try_player(
    label: &str,
    child: Result<Child, String>,
    stop_flag: &AtomicBool,
    duration: f32,
    last_err: &mut String,
) -> Result<(), String> {
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            *last_err = e;
            return Err(last_err.clone());
        }
    };
    voice_log(&format!("try {label}"));
    match linux_wait_player(&mut child, stop_flag, duration, label) {
        Ok(()) => Ok(()),
        Err(e) => {
            *last_err = e;
            voice_log(last_err);
            Err(last_err.clone())
        }
    }
}

#[cfg(target_os = "linux")]
fn play_wav_linux_file_fallback(
    pcm: &[f32],
    stop_flag: &AtomicBool,
    duration: f32,
) -> Result<(), String> {
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S_%f");
    let tmp = std::env::temp_dir().join(format!("void_play_{stamp}.wav"));
    write_wav_mono(&tmp, pcm, VOICE_SAMPLE_RATE)?;
    // Файл создаётся текущим (часто root) пользователем, а проигрывать его может
    // другой юзер desktop-сессии через `runuser` — без этого при строгом umask
    // (напр. 077 у root) чтение упадёт с Permission denied.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
    }
    voice_log(&format!("playback wav fallback {}", tmp.display()));
    let result = play_wav_linux_file_inner(&tmp, stop_flag, duration);
    let _ = std::fs::remove_file(&tmp);
    result
}

#[cfg(target_os = "linux")]
fn play_wav_linux_file_inner(
    play_path: &Path,
    stop_flag: &AtomicBool,
    duration: f32,
) -> Result<(), String> {
    let env_sets = linux_env_sets();
    let sessions = linux_desktop_sessions();
    let mut last_err = String::from("нет доступных аудиоплееров");

    let players: [(&str, &[&str]); 2] = [("pw-play", &[]), ("paplay", &[])];

    for session in &sessions {
        let session_env = [
            ("PULSE_SERVER".into(), session.pulse_server.clone()),
            (
                "XDG_RUNTIME_DIR".into(),
                session.runtime_dir.display().to_string(),
            ),
        ];
        for (cmd, args) in &players {
            let tag = format!("runuser:{} {cmd}", session.username);
            if linux_try_player(
                &tag,
                linux_spawn_as_user(
                    &session.username,
                    cmd,
                    args,
                    play_path,
                    &session_env,
                ),
                stop_flag,
                duration,
                &mut last_err,
            )
            .is_ok()
            {
                return Ok(());
            }
        }
    }

    for (cmd, args) in &players {
        for env in &env_sets {
            let tag = format!(
                "{cmd}{}",
                env.iter()
                    .find(|(k, _)| k == "PULSE_SERVER")
                    .map(|(_, v)| format!("@{v}"))
                    .unwrap_or_default()
            );
            if linux_try_player(
                &tag,
                linux_spawn_player(cmd, args, play_path, env),
                stop_flag,
                duration,
                &mut last_err,
            )
            .is_ok()
            {
                return Ok(());
            }
        }
    }

    for device in ["pipewire", "pulse", "default"] {
        let args = ["-q", "-D", device];
        let tag = format!("aplay -D {device}");
        if linux_try_player(
            &tag,
            linux_spawn_player("aplay", &args, play_path, &[]),
            stop_flag,
            duration,
            &mut last_err,
        )
        .is_ok()
        {
            return Ok(());
        }
    }

    Err(last_err)
}

#[cfg(target_os = "linux")]
fn play_wav_linux(
    path: &Path,
    stop_flag: &AtomicBool,
    start_ratio: f32,
    frame_pos: Arc<AtomicUsize>,
) -> Result<(), String> {
    let (pcm, start_frame, duration) = linux_prepare_playback_pcm(path, start_ratio)?;
    if pcm.is_empty() {
        return Err("Пустой фрагмент воспроизведения".into());
    }
    frame_pos.store(start_frame, Ordering::Relaxed);

    if play_wav_linux_stdin(&pcm, stop_flag, frame_pos.clone(), start_frame).is_ok() {
        return Ok(());
    }

    play_wav_linux_file_fallback(&pcm, stop_flag, duration).map_err(|file_err| {
        format!(
            "{file_err} (apt install pipewire-audio-client-libraries pulseaudio-utils alsa-utils)"
        )
    })
}

fn normalize_playback_path(path: &Path) -> PathBuf {
    let s = path.display().to_string();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

#[cfg(target_os = "windows")]
fn stop_winmm_playback() {
    #[link(name = "winmm")]
    extern "system" {
        fn PlaySoundW(psz_sound: *const u16, hmod: *mut std::ffi::c_void, fdw_sound: u32) -> i32;
    }
    let _ = unsafe { PlaySoundW(std::ptr::null(), std::ptr::null_mut(), 0) };
}

#[cfg(target_os = "windows")]
fn play_wav_winmm(path: &Path, stop_flag: &AtomicBool) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "winmm")]
    extern "system" {
        fn PlaySoundW(psz_sound: *const u16, hmod: *mut std::ffi::c_void, fdw_sound: u32) -> i32;
    }
    const SND_FILENAME: u32 = 0x0002_0000;
    const SND_ASYNC: u32 = 0x0001;

    let duration = wav_duration(path).unwrap_or(30.0);
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let ok = unsafe { PlaySoundW(wide.as_ptr(), std::ptr::null_mut(), SND_FILENAME | SND_ASYNC) };
    if ok == 0 {
        return Err(format!("PlaySoundW не смог воспроизвести {}", path.display()));
    }

    let started = Instant::now();
    let max_wait = Duration::from_secs_f32(duration + 1.0);
    while started.elapsed() < max_wait {
        if stop_flag.load(Ordering::Relaxed) {
            stop_winmm_playback();
            voice_log("play stopped (winmm)");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    Ok(())
}

fn play_wav_cpal(
    path: &Path,
    stop_flag: &AtomicBool,
    start_ratio: f32,
    frame_pos: Arc<AtomicUsize>,
) -> Result<(), String> {
    use cpal::traits::{DeviceTrait, HostTrait};

    let (mono, src_rate) = read_wav_mono_f32(path)?;
    let mono = if src_rate == VOICE_SAMPLE_RATE {
        mono
    } else {
        resample_linear(&mono, src_rate, VOICE_SAMPLE_RATE)
    };

    let host = audio_host();
    let mut devices: Vec<cpal::Device> = Vec::new();
    if let Some(default) = host.default_output_device() {
        devices.push(default);
    }
    if let Ok(all) = host.devices() {
        for dev in all {
            if dev.default_output_config().is_ok()
                && !devices
                    .iter()
                    .any(|d| d.name().ok().as_deref() == dev.name().ok().as_deref())
            {
                devices.push(dev);
            }
        }
    }
    if devices.is_empty() {
        return Err("Устройство воспроизведения не найдено".into());
    }

    let mut last_err = String::from("cpal: нет рабочего выхода");
    for device in devices {
        let name = device.name().unwrap_or_else(|_| "?".into());
        match play_wav_cpal_device(
            &device,
            &mono,
            stop_flag,
            start_ratio,
            frame_pos.clone(),
        ) {
            Ok(()) => {
                voice_log(&format!("play done (cpal/{name})"));
                return Ok(());
            }
            Err(e) => {
                last_err = format!("cpal/{name}: {e}");
                voice_log(&last_err);
            }
        }
    }
    Err(last_err)
}

fn play_wav_cpal_device(
    device: &cpal::Device,
    mono: &[f32],
    stop_flag: &AtomicBool,
    start_ratio: f32,
    frame_pos: Arc<AtomicUsize>,
) -> Result<(), String> {
    use cpal::traits::StreamTrait;

    let config = device
        .default_output_config()
        .map_err(|e| format!("Выход аудио: {e}"))?;

    let out_ch = config.channels() as usize;
    let out_rate = config.sample_rate().0;
    let pcm = Arc::new(if out_rate == VOICE_SAMPLE_RATE {
        mono.to_vec()
    } else {
        resample_linear(mono, VOICE_SAMPLE_RATE, out_rate)
    });
    let total_frames = pcm.len();
    let start_frame =
        ((start_ratio.clamp(0.0, 1.0) * total_frames as f32) as usize).min(total_frames);
    frame_pos.store(start_frame, Ordering::Relaxed);
    let stream = build_output_stream(device, &config, pcm, frame_pos.clone(), out_ch)?;
    stream
        .play()
        .map_err(|e| format!("Не удалось начать воспроизведение: {e}"))?;

    let warmup = Instant::now();
    while frame_pos.load(Ordering::Relaxed) <= start_frame
        && warmup.elapsed() < Duration::from_millis(350)
    {
        if stop_flag.load(Ordering::Relaxed) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if frame_pos.load(Ordering::Relaxed) <= start_frame && total_frames > start_frame.saturating_add(1) {
        return Err("поток не воспроизводит (тишина)".into());
    }

    // Некоторые ALSA/PipeWire-плагины отдают весь буфер аудио-callback'у почти
    // мгновенно (не в реальном темпе) — если ориентироваться только на frame_pos,
    // поток обрывается (drop) раньше, чем железо реально успевает его доиграть,
    // и звук не слышен вовсе. Поэтому держим поток живым не меньше реальной
    // длительности клипа по wall-clock, независимо от того, что говорит frame_pos.
    let played_frames = total_frames.saturating_sub(start_frame);
    let expected_secs = played_frames as f32 / out_rate.max(1) as f32;
    let min_hold = Instant::now();
    loop {
        let frames_done = frame_pos.load(Ordering::Relaxed) >= total_frames;
        let time_done = min_hold.elapsed().as_secs_f32() >= expected_secs;
        if frames_done && time_done {
            break;
        }
        if stop_flag.load(Ordering::Relaxed) {
            voice_log("play stopped (cpal)");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    voice_log(&format!(
        "play done (cpal hold, {:.2}s expected)",
        expected_secs
    ));
    Ok(())
}

fn build_output_stream(
    device: &cpal::Device,
    config: &cpal::SupportedStreamConfig,
    pcm: Arc<Vec<f32>>,
    frame_pos: Arc<AtomicUsize>,
    output_channels: usize,
) -> Result<cpal::Stream, String> {
    let stream_cfg: cpal::StreamConfig = config.clone().into();
    let ch = output_channels.max(1);

    macro_rules! write_frames {
        ($out:expr, $to_sample:expr) => {{
            let mut pos = frame_pos.load(Ordering::Relaxed);
            for frame in $out.chunks_mut(ch) {
                let s = pcm.get(pos).copied().unwrap_or(0.0);
                let v = $to_sample(s);
                for slot in frame.iter_mut() {
                    *slot = v;
                }
                pos += 1;
            }
            frame_pos.store(pos, Ordering::Relaxed);
        }};
    }

    match config.sample_format() {
        SampleFormat::F32 => device
            .build_output_stream(
                &stream_cfg,
                move |out: &mut [f32], _| write_frames!(out, |s: f32| s),
                |_| {},
                None,
            )
            .map_err(|e| format!("Выход F32: {e}")),
        SampleFormat::I16 => device
            .build_output_stream(
                &stream_cfg,
                move |out: &mut [i16], _| {
                    write_frames!(out, |s: f32| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16)
                },
                |_| {},
                None,
            )
            .map_err(|e| format!("Выход I16: {e}")),
        other => Err(format!("Формат выхода {other:?} не поддерживается")),
    }
}

fn read_wav_mono_f32(path: &Path) -> Result<(Vec<f32>, u32), String> {
    let mut reader = hound::WavReader::open(path).map_err(|e| format!("WAV: {e}"))?;
    let spec = reader.spec();
    let channels = spec.channels as usize;

    let raw: Vec<f32> = match (spec.sample_format, spec.bits_per_sample) {
        (hound::SampleFormat::Int, 16) => reader
            .samples::<i16>()
            .map(|s| s.unwrap_or(0) as f32 / i16::MAX as f32)
            .collect(),
        (hound::SampleFormat::Int, 24) => reader
            .samples::<i32>()
            .map(|s| s.unwrap_or(0) as f32 / 8_388_608.0)
            .collect(),
        (hound::SampleFormat::Int, 32) => reader
            .samples::<i32>()
            .map(|s| s.unwrap_or(0) as f32 / i32::MAX as f32)
            .collect(),
        (hound::SampleFormat::Float, 32) => reader
            .samples::<f32>()
            .map(|s| s.unwrap_or(0.0))
            .collect(),
        (hound::SampleFormat::Int, 8) => reader
            .samples::<i8>()
            .map(|s| s.unwrap_or(0) as f32 / i8::MAX as f32)
            .collect(),
        _ => {
            return Err(format!(
                "WAV {} бит {:?}",
                spec.bits_per_sample, spec.sample_format
            ));
        }
    };

    Ok((downmix_to_mono(&raw, channels.max(1)), spec.sample_rate))
}

pub(crate) fn fmt_duration(secs: f32) -> String {
    let total = secs.max(0.0).round() as u32;
    format!("{}:{:02}", total / 60, total % 60)
}
