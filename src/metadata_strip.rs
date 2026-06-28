//! Удаление EXIF, ID3 и прочих метаданных из вложений перед отправкой.

use crate::file_transfer::FileKind;
use std::io::Cursor;

/// Подготавливает байты файла к отправке: убирает метаданные, если формат поддерживается.
/// При ошибке или неизвестном формате возвращает исходные данные без изменений.
pub fn strip_metadata_for_send(filename: &str, kind: FileKind, data: Vec<u8>) -> Vec<u8> {
    let ext = extension_lower(filename);
    let stripped = match kind {
        FileKind::Image => strip_image(&data, &ext),
        FileKind::Audio => strip_audio(&data, &ext),
        FileKind::Other if is_image_ext(&ext) => strip_image(&data, &ext),
        FileKind::Other if is_audio_ext(&ext) => strip_audio(&data, &ext),
        FileKind::Other => None,
    };
    match stripped {
        Some(out) if out != data => {
            tracing::debug!(
                "metadata_strip: «{}» {} → {} байт",
                filename,
                data.len(),
                out.len()
            );
            out
        }
        Some(out) => out,
        None => data,
    }
}

fn extension_lower(filename: &str) -> String {
    std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_image_ext(ext: &str) -> bool {
    matches!(
        ext,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "tiff" | "tif" | "avif" | "ico"
    )
}

fn is_audio_ext(ext: &str) -> bool {
    matches!(
        ext,
        "wav" | "mp3" | "ogg" | "flac" | "aac" | "m4a" | "opus" | "wma" | "aiff" | "aif" | "ape"
            | "mpc" | "wv"
    )
}

fn strip_image(data: &[u8], ext: &str) -> Option<Vec<u8>> {
    let format = match ext {
        "png" => image::ImageFormat::Png,
        "jpg" | "jpeg" => image::ImageFormat::Jpeg,
        "gif" => image::ImageFormat::Gif,
        "webp" => image::ImageFormat::WebP,
        "bmp" => image::ImageFormat::Bmp,
        "tiff" | "tif" => image::ImageFormat::Tiff,
        "avif" => image::ImageFormat::Avif,
        "ico" => image::ImageFormat::Ico,
        _ => return None,
    };

    let img = image::load_from_memory_with_format(data, format).ok()?;
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), format).ok()?;
    Some(out)
}

fn strip_audio(data: &[u8], ext: &str) -> Option<Vec<u8>> {
    if ext == "wav" {
        return strip_wav(data);
    }
    strip_audio_lofty(data)
}

/// Перезаписывает WAV через hound — убирает RIFF INFO/LIST и прочие неаудио-чанки.
fn strip_wav(data: &[u8]) -> Option<Vec<u8>> {
    let mut reader = hound::WavReader::new(Cursor::new(data)).ok()?;
    let spec = reader.spec();
    let samples: Vec<i32> = reader.samples().collect::<Result<_, _>>().ok()?;

    let mut out = Vec::new();
    let mut writer = hound::WavWriter::new(Cursor::new(&mut out), spec).ok()?;
    for sample in samples {
        writer.write_sample(sample).ok()?;
    }
    writer.finalize().ok()?;
    Some(out)
}

/// Удаляет ID3, Vorbis Comments, iTunes ilst и другие теги через lofty.
fn strip_audio_lofty(data: &[u8]) -> Option<Vec<u8>> {
    use lofty::config::WriteOptions;
    use lofty::file::{AudioFile, TaggedFileExt};
    use lofty::probe::Probe;

    let mut reader = Cursor::new(data);
    let mut tagged_file = Probe::new(&mut reader)
        .guess_file_type()
        .ok()?
        .read()
        .ok()?;
    if tagged_file.tags().is_empty() {
        return None;
    }
    tagged_file.clear();
    let mut out = Vec::new();
    let mut writer = Cursor::new(&mut out);
    tagged_file.save_to(&mut writer, WriteOptions::default()).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};

    #[test]
    fn png_roundtrip_produces_valid_image() {
        let img: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_pixel(2, 2, Rgba([1, 2, 3, 255]));
        let mut raw = Vec::new();
        img.write_to(&mut Cursor::new(&mut raw), image::ImageFormat::Png)
            .unwrap();

        let stripped = strip_image(&raw, "png").expect("png strip");
        let decoded = image::load_from_memory(&stripped).expect("decoded png");
        assert_eq!(decoded.width(), 2);
        assert_eq!(decoded.height(), 2);
    }

    #[test]
    fn unknown_ext_returns_none() {
        assert!(strip_image(b"not-an-image", "svg").is_none());
    }

    #[test]
    fn wav_rewrite_keeps_samples() {
        let mut raw = Vec::new();
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: 8000,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        {
            let mut w = hound::WavWriter::new(Cursor::new(&mut raw), spec).unwrap();
            w.write_sample(100i16).unwrap();
            w.write_sample(-50i16).unwrap();
            w.finalize().unwrap();
        }
        raw.extend_from_slice(b"LISTextra");

        let stripped = strip_wav(&raw).expect("wav strip");
        let mut r = hound::WavReader::new(Cursor::new(&stripped)).unwrap();
        let samples: Vec<i32> = r.samples().map(|s| s.unwrap()).collect();
        assert_eq!(samples, vec![100, -50]);
    }
}
