#![no_main]

use libfuzzer_sys::fuzz_target;

/// Length-prefixed seed frame. The node binary owns the real handshake;
/// this target only checks that a frame of any bytes does not panic.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let n = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if n > 1024 * 1024 {
        return;
    }
    let Some(body) = data.get(4..4 + n.min(data.len().saturating_sub(4))) else {
        return;
    };
    let _ = body.len();
});
