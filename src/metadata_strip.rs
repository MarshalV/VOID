//! Удаление метаданных из любых вложений перед отправкой (фото, аудио, видео, PDF, Office…).

use crate::file_transfer::FileKind;
use std::io::{Cursor, Read, Write};
use std::path::Path;

/// Подготавливает байты файла к отправке: убирает метаданные всеми доступными способами.
pub fn strip_metadata_for_send(filename: &str, _kind: FileKind, data: Vec<u8>) -> Vec<u8> {
    if data.is_empty() {
        return data;
    }
    let ext = extension_lower(filename);
    if let Some(out) = strip_all(&data, &ext) {
        return finish(filename, data, out);
    }
    data
}

fn finish(filename: &str, before: Vec<u8>, after: Vec<u8>) -> Vec<u8> {
    if after != before {
        tracing::debug!(
            "metadata_strip: «{}» {} → {} байт",
            filename,
            before.len(),
            after.len()
        );
    }
    after
}

fn strip_all(data: &[u8], ext: &str) -> Option<Vec<u8>> {
    // 1. Нативные обработчики по сигнатуре файла
    if let Some(out) = strip_image_detected(data, ext) {
        return Some(out);
    }
    if is_riff_wave(data) {
        return strip_wav(data);
    }
    if is_riff_avi(data) {
        return strip_riff_list_info(data, b"AVI ");
    }
    if is_mp4(data) {
        if let Some(out) = strip_mp4(data) {
            return Some(out);
        }
    }
    if data.starts_with(b"%PDF") {
        return strip_pdf(data);
    }
    if data.starts_with(b"PK\x03\x04") {
        return strip_zip_metadata(data);
    }
    if is_svg(data, ext) {
        return strip_svg(data);
    }
    if let Some(out) = strip_audio_lofty(data) {
        return Some(out);
    }

    // 2. По расширению (если сигнатура не сработала)
    if is_image_ext(ext) {
        if let Some(out) = strip_image_detected(data, ext) {
            return Some(out);
        }
    }
    if ext == "wav" {
        return strip_wav(data);
    }
    if is_audio_ext(ext) {
        if let Some(out) = strip_audio_lofty(data) {
            return Some(out);
        }
    }
    if is_video_ext(ext) || is_matroska(data) {
        if let Some(out) = strip_via_ffmpeg(data, ext) {
            return Some(out);
        }
        if is_mp4(data) {
            return strip_mp4(data);
        }
    }

    // 3. Универсальный fallback: ffmpeg понимает сотни контейнеров
    strip_via_ffmpeg(data, ext)
}

fn extension_lower(filename: &str) -> String {
    Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_image_ext(ext: &str) -> bool {
    matches!(
        ext,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "tiff" | "tif" | "avif" | "ico" | "heic"
            | "heif" | "jfif"
    )
}

fn is_audio_ext(ext: &str) -> bool {
    matches!(
        ext,
        "wav" | "mp3" | "ogg" | "flac" | "aac" | "m4a" | "opus" | "wma" | "aiff" | "aif" | "ape"
            | "mpc" | "wv" | "mid" | "midi"
    )
}

fn is_video_ext(ext: &str) -> bool {
    matches!(
        ext,
        "mp4" | "m4v" | "mov" | "mkv" | "webm" | "avi" | "wmv" | "flv" | "mpg" | "mpeg" | "ts"
            | "m2ts" | "mts" | "3gp" | "3g2" | "ogv" | "vob" | "asf" | "rm" | "rmvb"
    )
}

fn is_riff_wave(data: &[u8]) -> bool {
    data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE"
}

fn is_riff_avi(data: &[u8]) -> bool {
    data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"AVI "
}

fn is_mp4(data: &[u8]) -> bool {
    data.len() >= 12 && &data[4..8] == b"ftyp"
}

fn is_matroska(data: &[u8]) -> bool {
    data.starts_with(&[0x1a, 0x45, 0xdf, 0xa3])
}

fn is_svg(data: &[u8], ext: &str) -> bool {
    ext == "svg"
        || (data.starts_with(b"<") && data.len() >= 4 && data[..4].eq_ignore_ascii_case(b"<svg"))
}

fn ext_to_image_format(ext: &str) -> Option<image::ImageFormat> {
    match ext {
        "png" => Some(image::ImageFormat::Png),
        "jpg" | "jpeg" | "jfif" => Some(image::ImageFormat::Jpeg),
        "gif" => Some(image::ImageFormat::Gif),
        "webp" => Some(image::ImageFormat::WebP),
        "bmp" => Some(image::ImageFormat::Bmp),
        "tiff" | "tif" => Some(image::ImageFormat::Tiff),
        "avif" => Some(image::ImageFormat::Avif),
        "ico" => Some(image::ImageFormat::Ico),
        _ => None,
    }
}

fn strip_image_detected(data: &[u8], ext: &str) -> Option<Vec<u8>> {
    let format = image::guess_format(data)
        .ok()
        .or_else(|| ext_to_image_format(ext))?;
    let img = image::load_from_memory_with_format(data, format).ok()?;
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), format).ok()?;
    Some(out)
}

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

/// Удаляет ID3, Vorbis Comments, iTunes ilst и прочие теги; перезаписывает файл.
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
    tagged_file.clear();
    let mut out = Vec::new();
    let mut writer = Cursor::new(&mut out);
    tagged_file.save_to(&mut writer, WriteOptions::default()).ok()?;
    Some(out)
}

/// MP4/MOV/M4V/3GP: убирает udta/meta/ilst и обложки.
fn strip_mp4(data: &[u8]) -> Option<Vec<u8>> {
    use mp4ameta::{ReadConfig, Tag, WriteConfig};

    let mut buf = Cursor::new(data.to_vec());
    let read_cfg = ReadConfig {
        read_meta_items: true,
        read_image_data: true,
        ..ReadConfig::NONE
    };
    let mut tag = Tag::read_with(&mut buf, &read_cfg).ok()?;
    tag.clear_meta_items();
    let write_cfg = WriteConfig {
        write_meta_items: true,
        ..WriteConfig::NONE
    };
    tag.write_with(&mut buf, &write_cfg).ok()?;
    Some(buf.into_inner())
}

fn strip_pdf(data: &[u8]) -> Option<Vec<u8>> {
    use lopdf::{Document, Object};

    let mut doc = Document::load_mem(data).ok()?;
    if let Ok(info) = doc.trailer.get(b"Info") {
        if let Ok(id) = info.as_reference() {
            let _ = doc.delete_object(id);
        }
        doc.trailer.remove(b"Info");
    }
    if let Ok(root_ref) = doc.trailer.get(b"Root") {
        if let Ok(catalog_id) = root_ref.as_reference() {
            let meta_id = doc
                .get_object(catalog_id)
                .ok()
                .and_then(|o| o.as_dict().ok())
                .and_then(|cat| cat.get(b"Metadata").ok())
                .and_then(|m| m.as_reference().ok());
            if let Some(id) = meta_id {
                let _ = doc.delete_object(id);
                if let Ok(Object::Dictionary(cat)) = doc.get_object_mut(catalog_id) {
                    cat.remove(b"Metadata");
                }
            }
        }
    }
    let mut out = Vec::new();
    doc.save_to(&mut out).ok()?;
    Some(out)
}

const MIN_CORE_XML: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>"#;

const MIN_APP_XML: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>"#;

const MIN_ODF_METADATA: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" office:version="1.2"><office:meta/></office:document-meta>"#;

/// Office Open XML / ODF / EPUB (ZIP): чистит docProps, META-INF/metadata и вложенные картинки.
fn strip_zip_metadata(data: &[u8]) -> Option<Vec<u8>> {
    use zip::read::ZipArchive;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    let reader = Cursor::new(data);
    let mut archive = ZipArchive::new(reader).ok()?;
    let mut out_buf = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(&mut out_buf));

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).ok()?;
        let name = file.name().to_string();
        if name == "docProps/custom.xml" || name.ends_with("Thumbs.db") {
            continue;
        }
        let method = file.compression();
        let options = SimpleFileOptions::default().compression_method(method);

        let content = match name.as_str() {
            "docProps/core.xml" => MIN_CORE_XML.to_vec(),
            "docProps/app.xml" => MIN_APP_XML.to_vec(),
            "META-INF/metadata.xml" => MIN_ODF_METADATA.to_vec(),
            _ => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).ok()?;
                if is_image_ext(
                    Path::new(&name)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or(""),
                ) {
                    strip_image_detected(&buf, "").unwrap_or(buf)
                } else {
                    buf
                }
            }
        };

        writer.start_file(name, options).ok()?;
        writer.write_all(&content).ok()?;
    }
    writer.finish().ok()?;
    Some(out_buf)
}

/// RIFF (AVI): пропускает LIST/INFO и прочие мета-чанки.
fn strip_riff_list_info(data: &[u8], form: &[u8; 4]) -> Option<Vec<u8>> {
    if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != form {
        return None;
    }
    let mut body = Vec::new();
    let mut pos = 12usize;
    while pos + 8 <= data.len() {
        let fourcc = &data[pos..pos + 4];
        let size = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().ok()?) as usize;
        let chunk_start = pos + 8;
        let chunk_end = chunk_start.checked_add(size)?;
        if chunk_end > data.len() {
            break;
        }
        let pad = size & 1;
        let skip = match fourcc {
            b"LIST" | b"list" if chunk_start + 4 <= data.len() => {
                &data[chunk_start..chunk_start + 4] == b"INFO"
            }
            b"INFO" | b"JUNK" | b"idit" | b"icmt" | b"iart" | b"icrd" | b"itch" => true,
            _ => false,
        };
        if !skip {
            body.extend_from_slice(&data[pos..chunk_end + pad]);
        }
        pos = chunk_end + pad;
    }
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
    out.extend_from_slice(form);
    out.extend_from_slice(&body);
    Some(out)
}

fn strip_svg(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() {
        if bytes[i..].starts_with(b"<metadata") {
            if let Some(rel) = text[i..].find("</metadata>") {
                i += rel + "</metadata>".len();
                continue;
            }
        }
        if bytes[i..].starts_with(b"<?") {
            if let Some(rel) = text[i..].find("?>") {
                i += rel + 2;
                continue;
            }
        }
        if bytes[i..].starts_with(b"<!--") {
            if let Some(rel) = text[i..].find("-->") {
                i += rel + 3;
                continue;
            }
        }
        out.push(char::from(bytes[i]));
        i += 1;
    }
    Some(out.into_bytes())
}

/// ffmpeg -map_metadata -1: видео, экзотические контейнеры и всё остальное.
fn strip_via_ffmpeg(data: &[u8], ext: &str) -> Option<Vec<u8>> {
    let ext = if ext.is_empty() { "bin" } else { ext };
    let mut seed = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    let id: String = seed.iter().map(|b| format!("{:02x}", b)).collect();
    let dir = std::env::temp_dir();
    let in_path = dir.join(format!("void_meta_in_{id}.{ext}"));
    let out_path = dir.join(format!("void_meta_out_{id}.{ext}"));

    let cleanup = |in_p: &Path, out_p: &Path| {
        let _ = std::fs::remove_file(in_p);
        let _ = std::fs::remove_file(out_p);
    };

    if std::fs::write(&in_path, data).is_err() {
        cleanup(&in_path, &out_path);
        return None;
    }

    let ok = run_ffmpeg(&in_path, &out_path, true).is_some()
        || run_ffmpeg(&in_path, &out_path, false).is_some();
    let result = if ok {
        std::fs::read(&out_path).ok().filter(|b| !b.is_empty())
    } else {
        None
    };
    cleanup(&in_path, &out_path);
    result
}

fn run_ffmpeg(in_path: &Path, out_path: &Path, copy_streams: bool) -> Option<()> {
    let mut cmd = std::process::Command::new("ffmpeg");
    cmd.args([
        "-y",
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-i",
    ])
    .arg(in_path)
    .args(["-map_metadata", "-1"]);
    if copy_streams {
        cmd.args(["-c", "copy"]);
    }
    cmd.arg(out_path);
    let output = cmd.output().ok()?;
    if output.status.success() && out_path.exists() {
        Some(())
    } else {
        None
    }
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

        let stripped = strip_image_detected(&raw, "png").expect("png strip");
        let decoded = image::load_from_memory(&stripped).expect("decoded png");
        assert_eq!(decoded.width(), 2);
        assert_eq!(decoded.height(), 2);
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

    #[test]
    fn svg_strips_metadata_block() {
        let raw = br#"<svg><metadata><author>secret</author></metadata><rect/></svg>"#;
        let out = strip_svg(raw).expect("svg");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(!s.contains("secret"));
        assert!(s.contains("<rect"));
    }
}
