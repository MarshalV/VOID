//! Запись и воспроизведение голосовых (cpal + WinMM на Windows).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_os = "windows"))]
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
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
    stop_tx: Option<mpsc::Sender<()>>,
    done_rx: Option<mpsc::Receiver<Result<(PathBuf, f32), String>>>,
    processing_since: Option<Instant>,
    pub(crate) last_status: String,
}

pub(crate) enum MicClick {
    Started,
    Stopped,
    Busy,
    Error(String),
}

impl VoiceRecorder {
    pub(crate) fn new() -> Self {
        Self {
            state: VoiceRecorderState::Idle,
            stop_tx: None,
            done_rx: None,
            processing_since: None,
            last_status: String::new(),
        }
    }

    pub(crate) fn poll(&mut self) {
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

        if !matches!(
            self.state,
            VoiceRecorderState::Recording { .. } | VoiceRecorderState::Processing
        ) {
            return;
        }

        let Some(rx) = self.done_rx.as_ref() else {
            return;
        };
        let Ok(result) = rx.try_recv() else {
            return;
        };
        self.done_rx = None;
        self.processing_since = None;
        self.state = match result {
            Ok((path, duration_secs)) => {
                self.last_status =
                    format!("Голосовое {} готово", fmt_duration(duration_secs));
                VoiceRecorderState::Ready {
                    path,
                    duration_secs,
                }
            }
            Err(e) => {
                voice_log(&format!("record done err: {e}"));
                self.set_error(e)
            }
        };
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

    pub(crate) fn is_processing(&self) -> bool {
        matches!(self.state, VoiceRecorderState::Processing)
    }

    pub(crate) fn has_ready(&self) -> bool {
        matches!(self.state, VoiceRecorderState::Ready { .. })
    }

    pub(crate) fn is_busy(&self) -> bool {
        self.is_recording() || self.is_processing()
    }

    pub(crate) fn recording_elapsed(&self) -> Option<f32> {
        match &self.state {
            VoiceRecorderState::Recording { started } => {
                Some(started.elapsed().as_secs_f32())
            }
            _ => None,
        }
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

    pub(crate) fn handle_mic_click(&mut self) -> MicClick {
        if self.is_processing() {
            if self
                .processing_since
                .is_some_and(|t| t.elapsed() >= Duration::from_secs(2))
            {
                self.force_reset();
            } else {
                return MicClick::Busy;
            }
        }
        if self.is_recording() {
            self.stop_recording();
            self.last_status = "Обработка записи…".into();
            return MicClick::Stopped;
        }
        match self.start_recording() {
            Ok(()) => {
                self.last_status = "Запись…".into();
                MicClick::Started
            }
            Err(e) => MicClick::Error(e),
        }
    }

    fn start_recording(&mut self) -> Result<(), String> {
        if self.has_ready() {
            self.state = VoiceRecorderState::Idle;
        }
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel();

        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                record_from_default_input(stop_rx)
            }))
            .unwrap_or_else(|_| Err("Внутренняя ошибка записи".into()));
            if let Err(ref e) = result {
                voice_log(&format!("thread result err: {e}"));
            }
            let _ = done_tx.send(result);
        });

        self.stop_tx = Some(stop_tx);
        self.done_rx = Some(done_rx);
        self.state = VoiceRecorderState::Recording {
            started: Instant::now(),
        };
        voice_log("recording started (UI state)");
        Ok(())
    }

    fn stop_recording(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if self.is_recording() {
            self.processing_since = Some(Instant::now());
            self.state = VoiceRecorderState::Processing;
            voice_log("recording stop requested");
        }
    }

    fn force_reset(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        self.done_rx = None;
        self.processing_since = None;
        self.state = VoiceRecorderState::Idle;
        self.last_status.clear();
    }
}

pub(crate) const VOICE_BUILD: &str = "v4-winmanifest";

/// Быстрая проверка микрофона при старте.
pub(crate) fn probe_microphone() -> Result<String, String> {
    let host = cpal::default_host();
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

fn voice_log(msg: &str) {
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

fn record_from_default_input(stop_rx: Receiver<()>) -> Result<(PathBuf, f32), String> {
    let host = cpal::default_host();
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
        if stop_rx.try_recv().is_ok() {
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

    let path = std::env::temp_dir().join(format!(
        "void_voice_{}.wav",
        chrono::Local::now().format("%Y%m%d_%H%M%S_%f")
    ));
    write_wav_mono(&path, &mono, VOICE_SAMPLE_RATE)?;
    voice_log(&format!("saved {} ({duration_secs:.2}s)", path.display()));
    Ok((path, duration_secs))
}

fn build_input_stream(
    device: &cpal::Device,
    config: &cpal::SupportedStreamConfig,
    sample_tx: SyncSender<Vec<f32>>,
    err_flag: Arc<AtomicBool>,
) -> Result<cpal::Stream, String> {
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
}

impl VoicePlayer {
    pub(crate) fn new() -> Self {
        Self {
            done_rx: None,
            playing_id: None,
            last_error: None,
        }
    }

    pub(crate) fn take_error(&mut self) -> Option<String> {
        self.last_error.take()
    }

    pub(crate) fn is_playing(&self, transfer_id: &str) -> bool {
        self.playing_id.as_deref() == Some(transfer_id)
    }

    pub(crate) fn toggle(&mut self, transfer_id: &str, path: &Path) -> Option<String> {
        if self.is_playing(transfer_id) {
            self.stop();
            return None;
        }
        self.stop();

        if !path.is_file() {
            return Some(format!("Аудиофайл не найден: {}", path.display()));
        }

        let (done_tx, done_rx) = mpsc::channel();
        self.done_rx = Some(done_rx);
        self.playing_id = Some(transfer_id.to_string());

        let path = path.to_path_buf();
        std::thread::spawn(move || {
            let result = play_wav_file(&path);
            let _ = done_tx.send(result);
        });
        None
    }

    pub(crate) fn stop(&mut self) {
        self.playing_id = None;
    }

    pub(crate) fn poll(&mut self) {
        let Some(rx) = self.done_rx.as_ref() else {
            return;
        };
        let Ok(result) = rx.try_recv() else {
            return;
        };
        self.done_rx = None;
        self.playing_id = None;
        if let Err(e) = result {
            self.last_error = Some(e);
        }
    }
}

fn play_wav_file(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        return play_wav_winmm(path);
    }
    #[cfg(not(target_os = "windows"))]
    {
        play_wav_cpal(path)
    }
}

#[cfg(target_os = "windows")]
fn play_wav_winmm(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "winmm")]
    extern "system" {
        fn PlaySoundW(psz_sound: *const u16, hmod: *mut std::ffi::c_void, fdw_sound: u32) -> i32;
    }
    const SND_FILENAME: u32 = 0x0002_0000;
    const SND_SYNC: u32 = 0x0000_0000;

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let ok = unsafe { PlaySoundW(wide.as_ptr(), std::ptr::null_mut(), SND_FILENAME | SND_SYNC) };
    if ok == 0 {
        Err(format!("PlaySoundW не смог воспроизвести {}", path.display()))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn play_wav_cpal(path: &Path) -> Result<(), String> {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

    let (mono, src_rate) = read_wav_mono_f32(path)?;
    let mono = if src_rate == VOICE_SAMPLE_RATE {
        mono
    } else {
        resample_linear(&mono, src_rate, VOICE_SAMPLE_RATE)
    };

    let host = cpal::default_host();
    let device = host
        .default_output_device()
        .ok_or_else(|| "Устройство воспроизведения не найдено".to_string())?;
    let config = device
        .default_output_config()
        .map_err(|e| format!("Выход аудио: {e}"))?;

    let out_ch = config.channels() as usize;
    let out_rate = config.sample_rate().0;
    let pcm = Arc::new(if out_rate == VOICE_SAMPLE_RATE {
        mono
    } else {
        resample_linear(&mono, VOICE_SAMPLE_RATE, out_rate)
    });
    let frame_pos = Arc::new(AtomicUsize::new(0));
    let total_frames = pcm.len();
    let stream = build_output_stream(&device, &config, pcm, frame_pos.clone(), out_ch)?;
    stream
        .play()
        .map_err(|e| format!("Не удалось начать воспроизведение: {e}"))?;

    while frame_pos.load(Ordering::Relaxed) < total_frames {
        std::thread::sleep(Duration::from_millis(15));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
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

#[cfg(not(target_os = "windows"))]
fn read_wav_mono_f32(path: &Path) -> Result<(Vec<f32>, u32), String> {
    let mut reader = hound::WavReader::open(path).map_err(|e| format!("WAV: {e}"))?;
    let spec = reader.spec();
    let channels = spec.channels as usize;

    let raw: Vec<f32> = match (spec.sample_format, spec.bits_per_sample) {
        (hound::SampleFormat::Int, 16) => reader
            .samples::<i16>()
            .map(|s| s.unwrap_or(0) as f32 / i16::MAX as f32)
            .collect(),
        (hound::SampleFormat::Int, 32) => reader
            .samples::<i32>()
            .map(|s| s.unwrap_or(0) as f32 / i32::MAX as f32)
            .collect(),
        (hound::SampleFormat::Float, 32) => reader
            .samples::<f32>()
            .map(|s| s.unwrap_or(0.0))
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
