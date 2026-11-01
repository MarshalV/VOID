#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = void_frames::wire::decode_v1_packet(data);
});
