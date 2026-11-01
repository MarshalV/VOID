#![no_main]

use libfuzzer_sys::fuzz_target;
use x25519_dalek::StaticSecret;

fuzz_target!(|data: &[u8]| {
    let sk = StaticSecret::from([7u8; 32]);
    let _ = void_onion::peel_v2(&sk, data);
});
