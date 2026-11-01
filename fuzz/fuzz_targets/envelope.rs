#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = void_envelope::offline_mail::decode_mailbox(data);
});
