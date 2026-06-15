//! Запись голосовых сообщений с системного микрофона (cpal default input) и воспроизведение.

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::SampleFormat;
use rodio::{Decoder, OutputStream, Sink};

/// Максимальная длительность записи (сек).
pub(crate) const MAX_VOICE_DURATION_SECS: f32 = 300.0;

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
}

impl VoiceRecorder {
    pub(crate) fn new() -> Self {
        Self {
            state: VoiceRecorderState::Idle,
            stop_tx: None,
            done_rx: None,
        }
    }

    pub(crate) fn poll(&mut self) {
        let Some(rx) = self.done_rx.as_ref() else {
            return;
        };
        let Ok(result) = rx.try_recv() else {
            return;
        };
        self.done_rx = None;
        self.state = match result {
            Ok((path, duration_secs)) => VoiceRecorderState::Ready {
                path,
                duration_secs,
            },
            Err(e) => VoiceRecorderState::Error(e),
        };
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
            Some((path, duration_secs))
        } else {
            None
        }
    }

    pub(crate) fn clear(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        self.done_rx = None;
        self.state = VoiceRecorderState::Idle;
    }

    /// Начать / остановить запись. Возвращает текст ошибки, если не удалось начать.
    pub(crate) fn toggle_record(&mut self) -> Option<String> {
        if self.is_processing() {
            return None;
        }
        if self.is_recording() {
            self.stop_recording();
            return None;
        }
        self.clear();
        self.start_recording()
    }

    fn start_recording(&mut self) -> Option<String> {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel();
        self.stop_tx = Some(stop_tx);
        self.done_rx = Some(done_rx);

        std::thread::spawn(move || {
            let result = record_from_default_input(stop_rx);
            let _ = done_tx.send(result);
        });

        self.state = VoiceRecorderState::Recording {
            started: Instant::now(),
        };
        None
    }

    fn stop_recording(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if self.is_recording() {
            self.state = VoiceRecorderState::Processing;
        }
    }
}

fn record_from_default_input(stop_rx: mpsc::Receiver<()>) -> Result<(PathBuf, f32), String> {
    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .ok_or_else(|| "Системный микрофон не найден".to_string())?;
    let config = device
        .default_input_config()
        .map_err(|e| format!("Не удалось открыть микрофон: {}", e))?;

    let sample_rate = config.sample_rate().0;
    let channels = config.channels() as usize;
    let samples: Arc<Mutex<Vec<f32>>> = Arc::new(Mutex::new(Vec::new()));
    let samples_cb = samples.clone();

    let stream = match config.sample_format() {
        SampleFormat::F32 => device
            .build_input_stream(
                &config.into(),
                move |data: &[f32], _| {
                    samples_cb.lock().unwrap().extend_from_slice(data);
                },
                |e| tracing::warn!("cpal stream error: {}", e),
                None,
            )
            .map_err(|e| format!("Ошибка потока записи: {}", e))?,
        SampleFormat::I16 => device
            .build_input_stream(
                &config.into(),
                move |data: &[i16], _| {
                    let mut buf = samples_cb.lock().unwrap();
                    buf.extend(data.iter().map(|&v| v as f32 / i16::MAX as f32));
                },
                |e| tracing::warn!("cpal stream error: {}", e),
                None,
            )
            .map_err(|e| format!("Ошибка потока записи: {}", e))?,
        SampleFormat::U16 => device
            .build_input_stream(
                &config.into(),
                move |data: &[u16], _| {
                    let mut buf = samples_cb.lock().unwrap();
                    buf.extend(
                        data.iter()
                            .map(|&v| (v as f32 - u16::MAX as f32 / 2.0) / (u16::MAX as f32 / 2.0)),
                    );
                },
                |e| tracing::warn!("cpal stream error: {}", e),
                None,
            )
            .map_err(|e| format!("Ошибка потока записи: {}", e))?,
        other => return Err(format!("Неподдерживаемый формат микрофона: {:?}", other)),
    };

    stream
        .play()
        .map_err(|e| format!("Не удалось начать запись: {}", e))?;

    let max_samples = (sample_rate as f32 * MAX_VOICE_DURATION_SECS) as usize * channels;
    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }
        if samples.lock().unwrap().len() >= max_samples {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    drop(stream);

    let raw = samples.lock().unwrap().clone();
    if raw.is_empty() {
        return Err("Запись пуста — проверьте микрофон".into());
    }

    let mono = downmix_to_mono(&raw, channels);
    let duration_secs = mono.len() as f32 / sample_rate as f32;
    if duration_secs < 0.3 {
        return Err("Слишком короткая запись".into());
    }

    let path = std::env::temp_dir().join(format!(
        "void_voice_{}.wav",
        chrono::Local::now().format("%Y%m%d_%H%M%S_%f")
    ));
    write_wav_mono(&path, &mono, sample_rate)?;
    Ok((path, duration_secs))
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

fn write_wav_mono(path: &Path, samples: &[f32], sample_rate: u32) -> Result<(), String> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer =
        hound::WavWriter::create(path, spec).map_err(|e| format!("Не удалось создать WAV: {}", e))?;
    for &s in samples {
        let clamped = s.clamp(-1.0, 1.0);
        let sample = (clamped * i16::MAX as f32) as i16;
        writer
            .write_sample(sample)
            .map_err(|e| format!("Ошибка записи WAV: {}", e))?;
    }
    writer
        .finalize()
        .map_err(|e| format!("Ошибка финализации WAV: {}", e))?;
    Ok(())
}

// ─── Воспроизведение ─────────────────────────────────────────────────────────

pub(crate) struct VoicePlayer {
    sink: Option<Sink>,
    _output: Option<OutputStream>,
    pub(crate) playing_id: Option<String>,
}

impl VoicePlayer {
    pub(crate) fn new() -> Self {
        Self {
            sink: None,
            _output: None,
            playing_id: None,
        }
    }

    pub(crate) fn is_playing(&self, transfer_id: &str) -> bool {
        self.playing_id.as_deref() == Some(transfer_id)
            && self
                .sink
                .as_ref()
                .is_some_and(|s| !s.empty() && !s.is_paused())
    }

    pub(crate) fn toggle(&mut self, transfer_id: &str, path: &Path) {
        if self.is_playing(transfer_id) {
            self.stop();
            return;
        }
        self.stop();
        let Ok((output, stream_handle)) = OutputStream::try_default() else {
            return;
        };
        let Ok(file) = std::fs::File::open(path) else {
            return;
        };
        let Ok(source) = Decoder::new(BufReader::new(file)) else {
            return;
        };
        let Ok(sink) = Sink::try_new(&stream_handle) else {
            return;
        };
        sink.append(source);
        self.sink = Some(sink);
        self._output = Some(output);
        self.playing_id = Some(transfer_id.to_string());
    }

    pub(crate) fn stop(&mut self) {
        if let Some(sink) = self.sink.take() {
            sink.stop();
        }
        self._output = None;
        self.playing_id = None;
    }

    pub(crate) fn poll(&mut self) {
        if let Some(sink) = &self.sink {
            if sink.empty() {
                self.stop();
            }
        }
    }
}

/// Форматирует длительность «0:05».
pub(crate) fn fmt_duration(secs: f32) -> String {
    let total = secs.max(0.0).round() as u32;
    format!("{}:{:02}", total / 60, total % 60)
}
