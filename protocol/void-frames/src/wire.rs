//! JSON и CBOR одного `V1Packet` на `/void/chat/1.0.0`.
//!
//! Пока обе стороны не объявили `HELLO_CAP_CBOR`, отправитель пишет JSON.
//! Приёмник (клиент и нода) всегда разбирает оба вида:
//! content-type `VC\x01\x01|02`, магия CBOR `d9 d9 f7`, иначе первый байт.

use anyhow::{anyhow, Result};

use crate::protocol::{V1Packet, HELLO_CAP_CBOR};

/// Потолок поля `ct`: ячейка onion и `ct` конверта. Не размер всего JSON.
pub const MAX_CT_BYTES: usize = void_onion::MAX_CT_BYTES;
/// Потолок `Encrypted.ciphertext`.
pub const MAX_CIPHERTEXT_BYTES: usize = 1024 * 1024;
/// Сколько конвертов в одном `OfflineMailboxStore`.
pub const MAX_STORE_ENVELOPES: usize = 64;
/// Сколько конвертов в одном `OfflineMailboxDeliver` (ответ ящика, до 16 МиБ).
pub const MAX_DELIVER_ENVELOPES: usize = 1024;
/// Тело запроса на `/void/chat/1.0.0`.
pub const REQUEST_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Тело ответа на `/void/chat/1.0.0`.
pub const RESPONSE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// `VC` + версия 1 + тип 2. Дальше тело CBOR.
const CONTENT_TYPE_CBOR: [u8; 4] = [b'V', b'C', 0x01, 0x02];
/// Самоописание CBOR, тег 55799 (RFC 8949). Префикс, не часть значения.
const CBOR_MAGIC: [u8; 3] = [0xd9, 0xd9, 0xf7];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireEncoding {
    Json,
    Cbor,
}

/// Оба Hello несут бит. Иначе на проводе JSON.
pub fn both_announce_cbor(local_caps: u32, remote_caps: u32) -> bool {
    local_caps & HELLO_CAP_CBOR != 0 && remote_caps & HELLO_CAP_CBOR != 0
}

pub fn encode_v1_packet(packet: &V1Packet, encoding: WireEncoding) -> Result<Vec<u8>> {
    check_v1_limits(packet)?;
    match encoding {
        WireEncoding::Json => serde_json::to_vec(packet).map_err(|e| anyhow!("json encode: {e}")),
        WireEncoding::Cbor => {
            let mut out = Vec::with_capacity(CONTENT_TYPE_CBOR.len() + 64);
            out.extend_from_slice(&CONTENT_TYPE_CBOR);
            out.extend(cbor_bytes(packet)?);
            Ok(out)
        }
    }
}

pub fn decode_v1_packet(bytes: &[u8]) -> Result<(V1Packet, WireEncoding)> {
    let (packet, encoding) = sniff_decode(bytes)?;
    check_v1_limits(&packet)?;
    Ok((packet, encoding))
}

fn sniff_decode(bytes: &[u8]) -> Result<(V1Packet, WireEncoding)> {
    if bytes.len() >= 4 && bytes[0] == b'V' && bytes[1] == b'C' && bytes[2] == 0x01 {
        return match bytes[3] {
            0x01 => decode_json(&bytes[4..]).map(|p| (p, WireEncoding::Json)),
            0x02 => decode_cbor(&bytes[4..]).map(|p| (p, WireEncoding::Cbor)),
            other => Err(anyhow!("unknown content-type {other}")),
        };
    }
    if bytes.len() >= 3 && bytes[..3] == CBOR_MAGIC {
        return decode_cbor(&bytes[3..]).map(|p| (p, WireEncoding::Cbor));
    }
    match bytes.first().copied() {
        Some(b'{') | Some(b'[') | Some(b'"') | Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => {
            decode_json(bytes).map(|p| (p, WireEncoding::Json))
        }
        Some(_) => decode_cbor(bytes).map(|p| (p, WireEncoding::Cbor)),
        None => Err(anyhow!("empty chat frame")),
    }
}

fn decode_json(bytes: &[u8]) -> Result<V1Packet> {
    serde_json::from_slice(bytes).map_err(|e| anyhow!("json decode: {e}"))
}

fn decode_cbor(bytes: &[u8]) -> Result<V1Packet> {
    cbor4ii::serde::from_slice(bytes).map_err(|e| anyhow!("cbor decode: {e:?}"))
}

fn cbor_bytes(packet: &V1Packet) -> Result<Vec<u8>> {
    cbor4ii::serde::to_vec(Vec::new(), packet).map_err(|e| anyhow!("cbor encode: {e:?}"))
}

pub fn check_v1_limits(packet: &V1Packet) -> Result<()> {
    match packet {
        V1Packet::Encrypted { ciphertext, .. } => {
            if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
                return Err(anyhow!(
                    "ciphertext {} exceeds {}",
                    ciphertext.len(),
                    MAX_CIPHERTEXT_BYTES
                ));
            }
        }
        V1Packet::Onion { ct, .. } => {
            if ct.len() > MAX_CT_BYTES {
                return Err(anyhow!("ct {} exceeds {}", ct.len(), MAX_CT_BYTES));
            }
        }
        V1Packet::OfflineMailboxStore { envelopes, .. } => {
            check_envelopes(envelopes.len(), envelopes.iter().map(|e| e.ct.len()), MAX_STORE_ENVELOPES)?;
        }
        V1Packet::OfflineMailboxDeliver { envelopes } => {
            check_envelopes(
                envelopes.len(),
                envelopes.iter().map(|e| e.ct.len()),
                MAX_DELIVER_ENVELOPES,
            )?;
        }
        V1Packet::OnionDrop { packet, .. } => check_v1_limits(packet)?,
        _ => {}
    }
    Ok(())
}

fn check_envelopes(
    count: usize,
    ct_lens: impl Iterator<Item = usize>,
    max_count: usize,
) -> Result<()> {
    if count > max_count {
        return Err(anyhow!("envelopes {count} exceeds {max_count}"));
    }
    for n in ct_lens {
        if n > MAX_CT_BYTES {
            return Err(anyhow!("envelope ct {n} exceeds {MAX_CT_BYTES}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{V1Packet, HELLO_CAPS, HELLO_CAP_HEADER_AAD};
    use void_session::crypto::MessageHeader;

    fn enc(n: usize) -> V1Packet {
        V1Packet::Encrypted {
            header: MessageHeader {
                dh_pub: [9u8; 32],
                pn: 1,
                n: 2,
            },
            ciphertext: vec![0xab; n],
        }
    }

    #[test]
    fn two_new_peers_use_cbor_old_peer_stays_json() {
        let new_caps = HELLO_CAPS;
        let old_caps = HELLO_CAP_HEADER_AAD;
        assert!(both_announce_cbor(new_caps, new_caps));
        assert!(!both_announce_cbor(new_caps, old_caps));
        assert!(!both_announce_cbor(old_caps, new_caps));

        let packet = V1Packet::Ack;
        let cbor = encode_v1_packet(&packet, WireEncoding::Cbor).unwrap();
        let json = encode_v1_packet(&packet, WireEncoding::Json).unwrap();
        assert!(cbor.starts_with(&CONTENT_TYPE_CBOR));
        assert_eq!(json, b"\"Ack\"");

        let (a, ea) = decode_v1_packet(&cbor).unwrap();
        let (b, eb) = decode_v1_packet(&json).unwrap();
        assert!(matches!(a, V1Packet::Ack));
        assert!(matches!(b, V1Packet::Ack));
        assert_eq!(ea, WireEncoding::Cbor);
        assert_eq!(eb, WireEncoding::Json);
    }

    #[test]
    fn dual_decode_magic_content_type_and_first_byte() {
        let packet = enc(32);
        let json = encode_v1_packet(&packet, WireEncoding::Json).unwrap();
        assert_eq!(json[0], b'{');
        let (back, encod) = decode_v1_packet(&json).unwrap();
        assert_eq!(encod, WireEncoding::Json);
        match back {
            V1Packet::Encrypted { ciphertext, .. } => assert_eq!(ciphertext, vec![0xab; 32]),
            other => panic!("unexpected {other:?}"),
        }

        let raw = cbor_bytes(&packet).unwrap();
        assert!(raw[0] & 0xe0 == 0xa0, "cbor map, got {:02x}", raw[0]);
        let (by_first, encod) = decode_v1_packet(&raw).unwrap();
        assert_eq!(encod, WireEncoding::Cbor);
        assert!(matches!(by_first, V1Packet::Encrypted { .. }));

        let mut magic = CBOR_MAGIC.to_vec();
        magic.extend_from_slice(&raw);
        let (by_magic, encod) = decode_v1_packet(&magic).unwrap();
        assert_eq!(encod, WireEncoding::Cbor);
        assert!(matches!(by_magic, V1Packet::Encrypted { .. }));

        let framed = encode_v1_packet(&packet, WireEncoding::Cbor).unwrap();
        let (by_ct, encod) = decode_v1_packet(&framed).unwrap();
        assert_eq!(encod, WireEncoding::Cbor);
        match by_ct {
            V1Packet::Encrypted { ciphertext, .. } => assert_eq!(ciphertext.len(), 32),
            other => panic!("unexpected {other:?}"),
        }

        let mut json_ct = vec![b'V', b'C', 0x01, 0x01];
        json_ct.extend_from_slice(&json);
        let (_, encod) = decode_v1_packet(&json_ct).unwrap();
        assert_eq!(encod, WireEncoding::Json);

        assert!(framed.len() < json.len());
    }

    #[test]
    fn field_limits_reject_ct_ciphertext_and_store_count() {
        let big_ct = V1Packet::Onion {
            eph: [1u8; 32],
            nonce: [2u8; 12],
            ct: vec![3u8; MAX_CT_BYTES + 1],
        };
        assert!(encode_v1_packet(&big_ct, WireEncoding::Json).is_err());
        let raw = cbor4ii::serde::to_vec(Vec::new(), &big_ct).unwrap();
        let mut framed = CONTENT_TYPE_CBOR.to_vec();
        framed.extend(raw);
        assert!(decode_v1_packet(&framed).is_err());

        let big_msg = enc(MAX_CIPHERTEXT_BYTES + 1);
        assert!(check_v1_limits(&big_msg).is_err());
        assert!(check_v1_limits(&enc(MAX_CIPHERTEXT_BYTES)).is_ok());

        let env = void_envelope::offline_mail::OfflineEnvelope {
            v: 3,
            sender: String::new(),
            sender_pk: [0u8; 32],
            message_id: "a".into(),
            kind: String::new(),
            eph: [1u8; 32],
            nonce: [2u8; 12],
            ct: vec![4u8; 8],
            local_kind: String::new(),
        };
        let mut many = Vec::new();
        many.resize(MAX_STORE_ENVELOPES + 1, env.clone());
        let store = V1Packet::OfflineMailboxStore {
            recipient: "peer".into(),
            envelopes: many,
        };
        assert!(check_v1_limits(&store).is_err());

        let mut ok = Vec::new();
        ok.resize(MAX_STORE_ENVELOPES, env);
        assert!(check_v1_limits(&V1Packet::OfflineMailboxStore {
            recipient: "peer".into(),
            envelopes: ok,
        })
        .is_ok());
    }
}
