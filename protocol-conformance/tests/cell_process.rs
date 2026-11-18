//! Ячейка v2 с Query почты в двух процессах ОС.
//!
//! Родитель заворачивает `OfflineMailboxQuery` (подписанный запрос, без внешнего
//! отправителя — путь C.2 / J.2). Ребёнок — тот же бинарник с другим окружением —
//! снимает слой своим секретом hop и пишет внутренние байты в файл. Общей памяти нет.

use std::process::Command;

use libp2p::identity::Keypair;
use void_frames::protocol::V1Packet;
use void_frames::wire::{decode_v1_packet, encode_v1_packet, WireEncoding};
use void_onion::{wrap_v2, PeerId};
use void_session::mailbox_query::sign_mailbox_query;
use x25519_dalek::{PublicKey, StaticSecret};

fn child_peel() {
    if std::env::var("VOID_CELL_CHILD").ok().as_deref() != Some("1") {
        return;
    }
    let input = std::env::var("VOID_CELL_IN").expect("VOID_CELL_IN");
    let output = std::env::var("VOID_CELL_OUT").expect("VOID_CELL_OUT");
    let bytes = std::fs::read(input).expect("cell file");
    if bytes.len() < 32 {
        std::process::exit(2);
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&bytes[..32]);
    let secret = StaticSecret::from(sk);
    match void_onion::peel_v2(&secret, &bytes[32..]) {
        Ok(void_onion::V2Peel::Deliver { body, .. }) => {
            std::fs::write(output, body).expect("peeled body");
            std::process::exit(0);
        }
        _ => std::process::exit(3),
    }
}

#[test]
fn mailbox_query_cell_crosses_two_processes() {
    child_peel();

    let hop_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let hop = (PeerId::random(), PublicKey::from(&hop_sk).to_bytes());
    let owner = Keypair::generate_ed25519();
    let owner_id = void_session::PeerId::from_public_key(&owner.public());
    let ts = 1_700_000_000u64;
    let nonce = [9u8; 32];
    let sig = sign_mailbox_query(&owner, &owner_id, ts, &nonce).expect("query sig");
    let packet = V1Packet::OfflineMailboxQuery {
        recipient: owner_id.to_string(),
        ts,
        nonce,
        sig: sig.clone(),
    };
    let frame = encode_v1_packet(&packet, WireEncoding::Json).expect("frame");
    let cell = wrap_v2(&[hop], PeerId::random(), &frame).expect("cell");

    let dir = std::env::temp_dir().join(format!("void-cell-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let input = dir.join("cell.bin");
    let output = dir.join("body.bin");
    let _ = std::fs::remove_file(&output);
    let mut blob = hop_sk.to_bytes().to_vec();
    blob.extend_from_slice(&cell);
    std::fs::write(&input, blob).expect("write cell");

    let status = Command::new(std::env::current_exe().expect("exe"))
        .arg("mailbox_query_cell_crosses_two_processes")
        .arg("--exact")
        .arg("--quiet")
        .env("VOID_CELL_CHILD", "1")
        .env("VOID_CELL_IN", &input)
        .env("VOID_CELL_OUT", &output)
        .status()
        .expect("child process");
    assert!(status.success(), "child exit {status}");

    let body = std::fs::read(&output).expect("child body");
    assert!(body.len() >= 4 + frame.len());
    let n = u32::from_le_bytes(body[..4].try_into().unwrap()) as usize;
    assert_eq!(n, frame.len());
    assert_eq!(&body[4..4 + n], frame.as_slice());
    let (opened, _) = decode_v1_packet(&body[4..4 + n]).expect("query frame");
    match opened {
        V1Packet::OfflineMailboxQuery {
            recipient,
            ts: got_ts,
            nonce: got_nonce,
            sig: got_sig,
        } => {
            assert_eq!(recipient, owner_id.to_string());
            assert_eq!(got_ts, ts);
            assert_eq!(got_nonce, nonce);
            assert_eq!(got_sig, sig);
        }
        other => panic!("query came back as {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}
