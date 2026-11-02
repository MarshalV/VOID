//! Сжатие вложений на проводе. На диске у получателя снова исходные байты.
//!
//! Голос — IMA ADPCM (`VVAD`): 60 секунд PCM ≈ 5,5 МиБ становятся ≈ 1,4 МиБ
//! и проходят в офлайн-потолок 3 МиБ. Файл — deflate (`VZDF`), только если
//! результат короче. Уже сжатые форматы не трогаем.

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

use crate::file_transfer::MAX_FILE_SIZE;

const VOICE_MAGIC: &[u8] = b"VVAD";
const FILE_MAGIC: &[u8] = b"VZDF";
const VOICE_RATE: u32 = 48_000;
const VOICE_MAX_SAMPLES: u32 = VOICE_RATE * 60;

const STEP_TABLE: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

const INDEX_TABLE: [i32; 16] = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

/// PCM WAV → `VVAD`. Если это не наш WAV, байты возвращаются как есть.
pub(crate) fn pack_voice(wav: &[u8]) -> Vec<u8> {
    let Some(pcm) = read_wav_i16(wav) else {
        return wav.to_vec();
    };
    if pcm.is_empty() || pcm.len() > VOICE_MAX_SAMPLES as usize {
        return wav.to_vec();
    }
    let mut pred = 0i32;
    let mut index = 0i32;
    let mut nibbles = Vec::with_capacity(pcm.len().div_ceil(2));
    let mut i = 0;
    while i < pcm.len() {
        let low = encode_nibble(pcm[i], &mut pred, &mut index);
        let high = if i + 1 < pcm.len() {
            encode_nibble(pcm[i + 1], &mut pred, &mut index)
        } else {
            0
        };
        nibbles.push(low | (high << 4));
        i += 2;
    }
    let mut out = Vec::with_capacity(12 + nibbles.len());
    out.extend_from_slice(VOICE_MAGIC);
    out.extend_from_slice(&VOICE_RATE.to_le_bytes());
    out.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
    out.extend_from_slice(&nibbles);
    out
}

/// Deflate, если файл от этого короче. Картинки, видео и архивы уже сжаты.
pub(crate) fn pack_file(bytes: &[u8], filename: &str) -> Vec<u8> {
    if bytes.len() < 64 || !worth_deflating(filename) || bytes.len() as u64 > MAX_FILE_SIZE {
        return bytes.to_vec();
    }
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::fast());
    if enc.write_all(bytes).is_err() {
        return bytes.to_vec();
    }
    let Ok(compressed) = enc.finish() else {
        return bytes.to_vec();
    };
    let mut out = Vec::with_capacity(12 + compressed.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&compressed);
    if out.len() >= bytes.len() {
        return bytes.to_vec();
    }
    out
}

/// Снимает `VVAD` / `VZDF`. Чужой формат возвращается без изменений.
pub(crate) fn unpack(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.starts_with(VOICE_MAGIC) {
        return unpack_voice(bytes);
    }
    if bytes.starts_with(FILE_MAGIC) {
        return unpack_file(bytes);
    }
    Ok(bytes.to_vec())
}

fn worth_deflating(filename: &str) -> bool {
    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    !matches!(
        ext.as_str(),
        "jpg" | "jpeg"
            | "png"
            | "gif"
            | "webp"
            | "mp3"
            | "m4a"
            | "aac"
            | "ogg"
            | "opus"
            | "mp4"
            | "webm"
            | "mov"
            | "zip"
            | "gz"
            | "xz"
            | "7z"
            | "rar"
            | "flac"
    )
}

fn read_wav_i16(wav: &[u8]) -> Option<Vec<i16>> {
    let mut reader = hound::WavReader::new(std::io::Cursor::new(wav)).ok()?;
    let spec = reader.spec();
    if spec.channels != 1
        || spec.sample_rate != VOICE_RATE
        || spec.bits_per_sample != 16
        || spec.sample_format != hound::SampleFormat::Int
    {
        return None;
    }
    let samples = reader.samples::<i16>().collect::<Result<Vec<_>, _>>().ok()?;
    Some(samples)
}

fn write_wav_i16(samples: &[i16]) -> Result<Vec<u8>, String> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: VOICE_RATE,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = hound::WavWriter::new(&mut cursor, spec)
            .map_err(|e| format!("wav: {e}"))?;
        for sample in samples {
            writer
                .write_sample(*sample)
                .map_err(|e| format!("wav: {e}"))?;
        }
        writer.finalize().map_err(|e| format!("wav: {e}"))?;
    }
    Ok(cursor.into_inner())
}

fn unpack_voice(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 12 {
        return Err("VVAD: короткий заголовок".into());
    }
    let rate = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let n = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if rate != VOICE_RATE || n == 0 || n > VOICE_MAX_SAMPLES {
        return Err("VVAD: недопустимая длина".into());
    }
    let nibbles = &bytes[12..];
    if nibbles.len() < n.div_ceil(2) as usize {
        return Err("VVAD: не хватает данных".into());
    }
    let mut pred = 0i32;
    let mut index = 0i32;
    let mut pcm = Vec::with_capacity(n as usize);
    for (i, &byte) in nibbles.iter().enumerate() {
        if pcm.len() as u32 >= n {
            break;
        }
        pcm.push(decode_nibble(byte & 0x0f, &mut pred, &mut index));
        if pcm.len() as u32 >= n {
            break;
        }
        pcm.push(decode_nibble(byte >> 4, &mut pred, &mut index));
        let _ = i;
    }
    if pcm.len() as u32 != n {
        return Err("VVAD: обрыв".into());
    }
    write_wav_i16(&pcm)
}

fn unpack_file(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 12 {
        return Err("VZDF: короткий заголовок".into());
    }
    let original_len = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
    if original_len == 0 || original_len > MAX_FILE_SIZE {
        return Err("VZDF: недопустимый размер".into());
    }
    let mut decoder = DeflateDecoder::new(&bytes[12..]);
    let mut out = Vec::new();
    decoder
        .by_ref()
        .take(original_len)
        .read_to_end(&mut out)
        .map_err(|e| format!("VZDF: {e}"))?;
    if out.len() as u64 != original_len {
        return Err("VZDF: размер не сошёлся".into());
    }
    Ok(out)
}

fn encode_nibble(sample: i16, pred: &mut i32, index: &mut i32) -> u8 {
    let step = STEP_TABLE[*index as usize];
    let mut diff = sample as i32 - *pred;
    let mut nibble = 0u8;
    if diff < 0 {
        nibble = 8;
        diff = -diff;
    }
    let mut delta = step >> 3;
    if diff >= step {
        nibble |= 4;
        diff -= step;
        delta += step;
    }
    if diff >= step >> 1 {
        nibble |= 2;
        diff -= step >> 1;
        delta += step >> 1;
    }
    if diff >= step >> 2 {
        nibble |= 1;
        delta += step >> 2;
    }
    if nibble & 8 != 0 {
        *pred -= delta;
    } else {
        *pred += delta;
    }
    *pred = (*pred).clamp(-32768, 32767);
    *index = (*index + INDEX_TABLE[nibble as usize]).clamp(0, 88);
    nibble
}

fn decode_nibble(nibble: u8, pred: &mut i32, index: &mut i32) -> i16 {
    let nibble = nibble & 0x0f;
    let step = STEP_TABLE[*index as usize];
    let mut delta = step >> 3;
    if nibble & 4 != 0 {
        delta += step;
    }
    if nibble & 2 != 0 {
        delta += step >> 1;
    }
    if nibble & 1 != 0 {
        delta += step >> 2;
    }
    if nibble & 8 != 0 {
        *pred -= delta;
    } else {
        *pred += delta;
    }
    *pred = (*pred).clamp(-32768, 32767);
    *index = (*index + INDEX_TABLE[nibble as usize]).clamp(0, 88);
    *pred as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wav_of(samples: &[i16]) -> Vec<u8> {
        write_wav_i16(samples).unwrap()
    }

    #[test]
    fn voice_roundtrip_keeps_the_shape_and_shrinks() {
        let mut samples = Vec::new();
        for i in 0..48_000 {
            let t = i as f32 / 48_000.0;
            let s = (t * 440.0 * std::f32::consts::TAU).sin();
            samples.push((s * 12_000.0) as i16);
        }
        let wav = wav_of(&samples);
        let packed = pack_voice(&wav);
        assert!(packed.starts_with(VOICE_MAGIC));
        assert!(packed.len() * 2 < wav.len());
        let back = unpack(&packed).unwrap();
        let pcm = read_wav_i16(&back).unwrap();
        assert_eq!(pcm.len(), samples.len());
        let rest = samples.len() - 1000;
        let mean: u32 = samples
            .iter()
            .zip(pcm.iter())
            .skip(1000)
            .map(|(a, b)| (*a as i32 - *b as i32).unsigned_abs())
            .sum::<u32>()
            / rest as u32;
        assert!(mean < 400, "adpcm mean error {mean}");
    }

    #[test]
    fn file_roundtrip_shrinks_text_and_leaves_noise() {
        let text = b"hello void ".repeat(400);
        let packed = pack_file(&text, "note.txt");
        assert!(packed.starts_with(FILE_MAGIC));
        assert!(packed.len() < text.len());
        assert_eq!(unpack(&packed).unwrap(), text);

        let noise: Vec<u8> = (0..8000u32)
            .map(|i| (i.wrapping_mul(17) & 0xff) as u8)
            .collect();
        let stored = pack_file(&noise, "blob.bin");
        assert!(!stored.starts_with(FILE_MAGIC) || unpack(&stored).unwrap() == noise);
        let jpeg = pack_file(&text, "photo.jpg");
        assert_eq!(jpeg, text);
    }

    #[test]
    fn plain_bytes_pass_through() {
        let raw = b"not compressed at all, just a short note".to_vec();
        assert_eq!(unpack(&raw).unwrap(), raw);
    }
}
