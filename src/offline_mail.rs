//! Offline mail via DHT and peer relay.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use libp2p::kad;
use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{PublicKey, StaticSecret};

const PREKEY_PREFIX: &[u8] = b"/void/prekey/";
const MAILBOX_PREFIX: &[u8] = b"/void/mailbox/";
pub(crate) const MAILBOX_TTL_SECS: u64 = 60 * 60 * 24 * 7;

/// Offline-доставка голосовых: аудио режется на кусочки и уходит через тот же
/// relay/bootstrap store-and-forward канал, что и офлайн-почта для текста
/// (DHT-запись мимо — там жёсткий лимит 64 КБ на весь ящик, см. mailbox_record_key).
#[cfg(any(feature = "egui-ui", test))]
pub(crate) const OFFLINE_VOICE_CHUNK_SIZE: usize = 24 * 1024;
/// Максимальный размер WAV, который мы согласны прогонять через offline-очередь
/// целиком (иначе — только метаданные, аудио дождётся живой передачи).
#[cfg(any(feature = "egui-ui", test))]
pub(crate) const OFFLINE_VOICE_MAX_BYTES: u64 = 3 * 1024 * 1024;
pub(crate) const OFFLINE_VOICE_CHUNK_KIND: &str = "voice_chunk";

/// Плейнтекст одного чанка (до шифрования в `seal_for_recipient`):
/// `[transfer_id:16][index:u32 LE][total:u32 LE][total_size:u32 LE][bytes...]`.
#[cfg(any(feature = "egui-ui", test))]
pub(crate) fn encode_voice_chunk_payload(
    transfer_id: &[u8; 16],
    index: u32,
    total: u32,
    total_size: u32,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(28 + data.len());
    out.extend_from_slice(transfer_id);
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(data);
    out
}

#[cfg(any(feature = "egui-ui", test))]
pub(crate) struct VoiceChunk {
    pub(crate) transfer_id: [u8; 16],
    pub(crate) index: u32,
    pub(crate) total: u32,
    pub(crate) total_size: u32,
    pub(crate) data: Vec<u8>,
}

#[cfg(any(feature = "egui-ui", test))]
pub(crate) fn decode_voice_chunk_payload(bytes: &[u8]) -> Option<VoiceChunk> {
    if bytes.len() < 28 {
        return None;
    }
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&bytes[0..16]);
    let index = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
    let total = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    let total_size = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
    if total == 0 || index >= total {
        return None;
    }
    Some(VoiceChunk {
        transfer_id,
        index,
        total,
        total_size,
        data: bytes[28..].to_vec(),
    })
}

/// Режет байты WAV на чанки для offline-доставки. Возвращает `None`, если файл
/// больше `OFFLINE_VOICE_MAX_BYTES` — в этом случае аудио дождётся живой передачи.
#[cfg(any(feature = "egui-ui", test))]
pub(crate) fn split_voice_for_offline(
    transfer_id: &[u8; 16],
    bytes: &[u8],
) -> Option<Vec<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() as u64 > OFFLINE_VOICE_MAX_BYTES {
        return None;
    }
    let total_size = bytes.len() as u32;
    let total = bytes
        .len()
        .div_ceil(OFFLINE_VOICE_CHUNK_SIZE)
        .max(1) as u32;
    let mut out = Vec::with_capacity(total as usize);
    for (i, chunk) in bytes.chunks(OFFLINE_VOICE_CHUNK_SIZE).enumerate() {
        out.push(encode_voice_chunk_payload(
            transfer_id,
            i as u32,
            total,
            total_size,
            chunk,
        ));
    }
    Some(out)
}

/// Собирает WAV из набора чанков (индекс → данные). `None`, если набор неполный
/// или суммарный размер не совпал с `total_size`.
#[cfg(any(feature = "egui-ui", test))]
pub(crate) fn assemble_voice_chunks(
    total: u32,
    total_size: u32,
    chunks: &std::collections::HashMap<u32, Vec<u8>>,
) -> Option<Vec<u8>> {
    if total == 0 || chunks.len() != total as usize {
        return None;
    }
    let mut out = Vec::with_capacity(total_size as usize);
    for i in 0..total {
        out.extend_from_slice(chunks.get(&i)?);
    }
    if out.len() as u32 != total_size {
        return None;
    }
    Some(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OfflineEnvelope {
    pub(crate) v: u8,
    pub(crate) sender: String,
    pub(crate) sender_pk: [u8; 32],
    pub(crate) message_id: String,
    pub(crate) kind: String,
    pub(crate) eph: [u8; 32],
    pub(crate) nonce: [u8; 12],
    pub(crate) ct: Vec<u8>,
    /// Настоящий `kind` у отправителя (в v3 снаружи пусто); в сеть не уходит.
    #[serde(skip)]
    pub(crate) local_kind: String,
}

impl OfflineEnvelope {
    pub(crate) fn is_voice_chunk(&self) -> bool {
        self.local_kind == OFFLINE_VOICE_CHUNK_KIND || self.kind == OFFLINE_VOICE_CHUNK_KIND
    }
}

pub(crate) fn prekey_record_key(peer: PeerId) -> kad::RecordKey {
    let mut key = PREKEY_PREFIX.to_vec();
    key.extend_from_slice(&peer.to_bytes());
    kad::RecordKey::new(&key)
}

pub(crate) fn mailbox_record_key(peer: PeerId) -> kad::RecordKey {
    let mut key = MAILBOX_PREFIX.to_vec();
    key.extend_from_slice(&peer.to_bytes());
    kad::RecordKey::new(&key)
}

pub(crate) fn encode_mailbox(envelopes: &[OfflineEnvelope]) -> Result<Vec<u8>> {
    // bincode вместо JSON: `ct`/`sender_pk`/`eph`/`nonce` — бинарные поля, JSON
    // раздувает Vec<u8> в массив чисел (~3-4x) — критично, когда в конвертах
    // может лежать аудио голосового (voice_chunk).
    bincode::serialize(envelopes).map_err(|e| anyhow!("mailbox bincode: {e}"))
}

pub(crate) fn decode_mailbox(bytes: &[u8]) -> Result<Vec<OfflineEnvelope>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    // Обратная совместимость: старые mailbox-записи/файлы могли быть в JSON.
    if let Ok(envs) = bincode::deserialize::<Vec<OfflineEnvelope>>(bytes) {
        return Ok(envs);
    }
    serde_json::from_slice(bytes).map_err(|e| anyhow!("mailbox decode: {e}"))
}

/// v3: отправитель, `kind` и `message_id` только внутри `ct`, снаружи — непрозрачный id.
/// v2 (подписан, поля открыты) ещё принимается; v1 (без подписи) — нет.
pub(crate) const ENVELOPE_VERSION: u8 = 3;
const ENVELOPE_V2: u8 = 2;
const OFFLINE_SIG_PREFIX: &[u8] = b"VOID_OFFLINE_SIG_V2\0";
const OFFLINE_AAD_PREFIX: &[u8] = b"VOID_OFFLINE_AAD_V2\0";
const OFFLINE_SIG_PREFIX_V3: &[u8] = b"VOID_OFFLINE_SIG_V3\0";
const OFFLINE_AAD_PREFIX_V3: &[u8] = b"VOID_OFFLINE_AAD_V3\0";
const OFFLINE_ID_PREFIX_V3: &[u8] = b"VOID_OFFLINE_ID_V3\0";
const MAX_OFFLINE_SIG: usize = 256;
const MAX_OFFLINE_PUBKEY_PB: usize = 4096;
/// Тело v3 выравнивается до степени двойки (не меньше `MIN_PADDED_BODY`),
/// крупнее `PAD_STEP` — до кратного `PAD_STEP` (голосовые чанки 24 КБ).
const MIN_PADDED_BODY: usize = 512;
const PAD_STEP: usize = 4096;

/// Вскрытый и проверенный конверт.
#[derive(Debug)]
pub(crate) struct OpenedEnvelope {
    pub(crate) sender: PeerId,
    pub(crate) message_id: String,
    pub(crate) kind: String,
    pub(crate) body: Vec<u8>,
}

/// Внешний id v3: нода дедуплицирует повторы, но не видит настоящий `message_id`
/// (`vchunk:<transfer>:<i>` и т.п.) и не связывает конверты разных получателей.
fn outer_message_id(recipient: &PeerId, message_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(OFFLINE_ID_PREFIX_V3);
    h.update(recipient.to_bytes());
    h.update(message_id.as_bytes());
    h.finalize()[..16].iter().map(|b| format!("{b:02x}")).collect()
}

fn padded_len(n: usize) -> usize {
    if n <= PAD_STEP {
        n.max(MIN_PADDED_BODY).next_power_of_two()
    } else {
        n.div_ceil(PAD_STEP) * PAD_STEP
    }
}

fn read_lp<'a>(b: &mut &'a [u8], max: usize) -> Option<&'a [u8]> {
    let n = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?) as usize;
    if n > max || b.len() < 4 + n {
        return None;
    }
    let out = &b[4..4 + n];
    *b = &b[4 + n..];
    Some(out)
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Заголовок конверта и получатель: AAD шифра и часть подписанного сообщения.
/// Нода не может переписать `sender`/`kind`/`message_id` или перенаправить конверт другому.
#[allow(clippy::too_many_arguments)]
fn envelope_header_bytes(
    prefix: &[u8],
    version: u8,
    sender: &PeerId,
    recipient: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    eph: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(prefix.len() + 192 + message_id.len() + kind.len());
    v.extend_from_slice(prefix);
    v.push(version);
    push_lp(&mut v, &sender.to_bytes());
    push_lp(&mut v, &recipient.to_bytes());
    v.extend_from_slice(sender_pk);
    push_lp(&mut v, message_id.as_bytes());
    push_lp(&mut v, kind.as_bytes());
    v.extend_from_slice(eph);
    v
}

fn signed_message(header: &[u8], body: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut v = header.to_vec();
    v.extend_from_slice(&Sha256::digest(body));
    v
}

/// Плейнтекст v2: `[sig_len:u16][sig][pb_len:u16][pubkey_pb][body]`.
fn encode_signed_inner(sig: &[u8], pubkey_pb: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + sig.len() + pubkey_pb.len() + body.len());
    out.extend_from_slice(&(sig.len() as u16).to_le_bytes());
    out.extend_from_slice(sig);
    out.extend_from_slice(&(pubkey_pb.len() as u16).to_le_bytes());
    out.extend_from_slice(pubkey_pb);
    out.extend_from_slice(body);
    out
}

fn decode_signed_inner(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let take = |b: &[u8], max: usize| -> Option<(usize, usize)> {
        let n = u16::from_le_bytes(b.get(0..2)?.try_into().ok()?) as usize;
        if n > max || b.len() < 2 + n {
            return None;
        }
        Some((2, 2 + n))
    };
    let (s0, s1) = take(bytes, MAX_OFFLINE_SIG)?;
    let sig = &bytes[s0..s1];
    let rest = &bytes[s1..];
    let (p0, p1) = take(rest, MAX_OFFLINE_PUBKEY_PB)?;
    Some((sig, &rest[p0..p1], &rest[p1..]))
}

const PREKEY_SIG_PREFIX: &[u8] = b"VOID_PREKEY_SIG_V1\0";

fn prekey_signed_message(owner: &PeerId, pk: &[u8; 32]) -> Vec<u8> {
    let mut v = PREKEY_SIG_PREFIX.to_vec();
    push_lp(&mut v, &owner.to_bytes());
    v.extend_from_slice(pk);
    v
}

/// Значение DHT-записи `/void/prekey/<owner>`: `pk[32] || [sig_len:u16][sig][pb_len:u16][pubkey_pb]`.
/// Первые 32 байта — сам ключ, как в старом формате.
pub(crate) fn encode_signed_prekey(
    transport: &libp2p::identity::Keypair,
    owner: &PeerId,
    pk: &[u8; 32],
) -> Option<Vec<u8>> {
    if PeerId::from_public_key(&transport.public()) != *owner {
        return None;
    }
    let sig = transport.sign(&prekey_signed_message(owner, pk)).ok()?;
    let pubkey_pb = if crate::protocol::void_peer_transport_public_key(*owner).is_some() {
        Vec::new()
    } else {
        transport.public().encode_protobuf()
    };
    let mut out = pk.to_vec();
    out.extend_from_slice(&encode_signed_inner(&sig, &pubkey_pb, &[]));
    Some(out)
}

/// Prekey из DHT-записи, только если её подписал владелец `owner`.
pub(crate) fn verify_signed_prekey(owner: &PeerId, value: &[u8]) -> Option<[u8; 32]> {
    let pk: [u8; 32] = value.get(..32)?.try_into().ok()?;
    if pk == [0u8; 32] {
        return None;
    }
    let (sig, pubkey_pb, rest) = decode_signed_inner(&value[32..])?;
    if sig.is_empty() || !rest.is_empty() {
        return None;
    }
    let signer = crate::protocol::void_hello_signing_public_key(*owner, pubkey_pb)?;
    signer
        .verify(&prekey_signed_message(owner, &pk), sig)
        .then_some(pk)
}

/// X25519-ключ офлайн-почты, выведенный из Ed25519-ключа внутри PeerId
/// (как `crypto_sign_ed25519_pk_to_curve25519`). Его не раздаёт ни нода, ни DHT —
/// подменить нечего.
pub(crate) fn identity_offline_public(peer: &PeerId) -> Option<PublicKey> {
    let ed = crate::protocol::void_peer_transport_public_key(*peer)?
        .try_into_ed25519()
        .ok()?;
    let point = curve25519_dalek::edwards::CompressedEdwardsY(ed.to_bytes()).decompress()?;
    if point.is_small_order() {
        return None;
    }
    Some(PublicKey::from(point.to_montgomery().to_bytes()))
}

/// Секрет к [`identity_offline_public`]: скаляр Ed25519 (первая половина SHA-512 от seed).
pub(crate) fn identity_offline_secret(key: &libp2p::identity::Keypair) -> Option<StaticSecret> {
    use sha2::{Digest, Sha512};
    let ed = key.clone().try_into_ed25519().ok()?;
    let pair = zeroize::Zeroizing::new(ed.to_bytes());
    let mut h = Sha512::digest(&pair[..32]);
    let mut scalar = zeroize::Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&h[..32]);
    h.as_mut_slice().fill(0);
    Some(StaticSecret::from(*scalar))
}

/// Ключ, к которому запечатывается офлайн-письмо: выведенный из PeerId получателя;
/// `fallback` (prekey из `Hello`/подписанной DHT-записи) — только для не-Ed25519 PeerId.
pub(crate) fn offline_seal_key(recipient: &PeerId, fallback: Option<[u8; 32]>) -> Option<PublicKey> {
    identity_offline_public(recipient).or_else(|| fallback.map(PublicKey::from))
}

fn transport_pubkey_pb(transport: &libp2p::identity::Keypair, sender: &PeerId) -> Vec<u8> {
    if crate::protocol::void_peer_transport_public_key(*sender).is_some() {
        Vec::new()
    } else {
        transport.public().encode_protobuf()
    }
}

fn v3_aad(recipient: &PeerId, outer_id: &str, eph: &[u8; 32]) -> Vec<u8> {
    let mut v = OFFLINE_AAD_PREFIX_V3.to_vec();
    v.push(ENVELOPE_VERSION);
    push_lp(&mut v, &recipient.to_bytes());
    push_lp(&mut v, outer_id.as_bytes());
    v.extend_from_slice(eph);
    v
}

/// Пробует каждый наш секрет: identity-ключ (новые письма) и static prekey (старые).
fn decrypt_envelope(
    recipient_secrets: &[&StaticSecret],
    env: &OfflineEnvelope,
    aad: &[u8],
) -> Result<Vec<u8>> {
    recipient_secrets
        .iter()
        .find_map(|secret| {
            let recipient_pk = PublicKey::from(*secret);
            let shared = secret.diffie_hellman(&PublicKey::from(env.eph));
            let key = hkdf_offline(shared.as_bytes(), &env.eph, recipient_pk.as_bytes());
            ChaCha20Poly1305::new(key.as_slice().into())
                .decrypt(
                    Nonce::from_slice(&env.nonce),
                    Payload {
                        msg: env.ct.as_ref(),
                        aad,
                    },
                )
                .ok()
        })
        .ok_or_else(|| anyhow!("offline open failed"))
}

fn verify_sender(
    sender: PeerId,
    pubkey_pb: &[u8],
    header: &[u8],
    body: &[u8],
    sig: &[u8],
) -> Result<()> {
    let signer = crate::protocol::void_hello_signing_public_key(sender, pubkey_pb)
        .ok_or_else(|| anyhow!("offline envelope: no signer key"))?;
    if sig.is_empty() || !signer.verify(&signed_message(header, body), sig) {
        return Err(anyhow!("offline envelope: bad sender signature"));
    }
    Ok(())
}

/// Запечатывает `plaintext` получателю (конверт v3) и подписывает libp2p-ключом отправителя.
/// Нода видит только получателя (в `OfflineMailboxStore`), непрозрачный id и размер бакета.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_for_recipient(
    transport: &libp2p::identity::Keypair,
    recipient: &PeerId,
    recipient_pk: &PublicKey,
    sender: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    plaintext: &[u8],
) -> Result<OfflineEnvelope> {
    if PeerId::from_public_key(&transport.public()) != *sender {
        return Err(anyhow!("offline seal: transport key ≠ sender"));
    }
    let eph_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let eph = PublicKey::from(&eph_secret).to_bytes();
    let shared = eph_secret.diffie_hellman(recipient_pk);
    let key = hkdf_offline(shared.as_bytes(), &eph, recipient_pk.as_bytes());

    let header = envelope_header_bytes(
        OFFLINE_SIG_PREFIX_V3,
        ENVELOPE_VERSION,
        sender,
        recipient,
        sender_pk,
        message_id,
        kind,
        &eph,
    );
    let sig = transport
        .sign(&signed_message(&header, plaintext))
        .map_err(|e| anyhow!("offline sign: {e}"))?;

    let mut fields = Vec::with_capacity(plaintext.len() + 128);
    push_lp(&mut fields, &sender.to_bytes());
    fields.extend_from_slice(sender_pk);
    push_lp(&mut fields, message_id.as_bytes());
    push_lp(&mut fields, kind.as_bytes());
    push_lp(&mut fields, plaintext);
    fields.resize(padded_len(fields.len()), 0);
    let inner = encode_signed_inner(&sig, &transport_pubkey_pb(transport, sender), &fields);

    let outer_id = outer_message_id(recipient, message_id);
    let aad = v3_aad(recipient, &outer_id, &eph);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(key.as_slice().into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("offline seal failed"))?;
    Ok(OfflineEnvelope {
        v: ENVELOPE_VERSION,
        sender: String::new(),
        sender_pk: [0u8; 32],
        message_id: outer_id,
        kind: String::new(),
        eph,
        nonce,
        ct,
        local_kind: kind.to_string(),
    })
}

/// Вскрывает конверт (v3 или v2) и проверяет подпись отправителя.
/// `recipient_secrets`: identity-секрет ([`identity_offline_secret`]) и static prekey.
pub(crate) fn open_envelope(
    recipient_secrets: &[&StaticSecret],
    recipient: &PeerId,
    env: &OfflineEnvelope,
) -> Result<OpenedEnvelope> {
    match env.v {
        ENVELOPE_VERSION => open_v3(recipient_secrets, recipient, env),
        ENVELOPE_V2 => open_v2(recipient_secrets, recipient, env),
        v => Err(anyhow!("offline envelope v{v} без подписи отправителя")),
    }
}

fn open_v3(
    recipient_secrets: &[&StaticSecret],
    recipient: &PeerId,
    env: &OfflineEnvelope,
) -> Result<OpenedEnvelope> {
    let bad = || anyhow!("offline envelope: bad inner");
    let inner = decrypt_envelope(recipient_secrets, env, &v3_aad(recipient, &env.message_id, &env.eph))?;
    let (sig, pubkey_pb, mut rest) = decode_signed_inner(&inner).ok_or_else(bad)?;
    let sender = PeerId::from_bytes(read_lp(&mut rest, 128).ok_or_else(bad)?).map_err(|_| bad())?;
    let sender_pk: [u8; 32] = rest.get(..32).ok_or_else(bad)?.try_into().map_err(|_| bad())?;
    rest = &rest[32..];
    let message_id = std::str::from_utf8(read_lp(&mut rest, 1024).ok_or_else(bad)?)
        .map_err(|_| bad())?
        .to_string();
    let kind = std::str::from_utf8(read_lp(&mut rest, 64).ok_or_else(bad)?)
        .map_err(|_| bad())?
        .to_string();
    let body = read_lp(&mut rest, usize::MAX).ok_or_else(bad)?;
    if env.message_id != outer_message_id(recipient, &message_id) {
        return Err(anyhow!("offline envelope: outer id mismatch"));
    }
    let header = envelope_header_bytes(
        OFFLINE_SIG_PREFIX_V3,
        ENVELOPE_VERSION,
        &sender,
        recipient,
        &sender_pk,
        &message_id,
        &kind,
        &env.eph,
    );
    verify_sender(sender, pubkey_pb, &header, body, sig)?;
    Ok(OpenedEnvelope {
        sender,
        message_id,
        kind,
        body: body.to_vec(),
    })
}

fn open_v2(
    recipient_secrets: &[&StaticSecret],
    recipient: &PeerId,
    env: &OfflineEnvelope,
) -> Result<OpenedEnvelope> {
    let sender: PeerId = env
        .sender
        .parse()
        .map_err(|_| anyhow!("offline envelope: bad sender"))?;
    let header_for = |prefix| {
        envelope_header_bytes(
            prefix,
            ENVELOPE_V2,
            &sender,
            recipient,
            &env.sender_pk,
            &env.message_id,
            &env.kind,
            &env.eph,
        )
    };
    let inner = decrypt_envelope(recipient_secrets, env, &header_for(OFFLINE_AAD_PREFIX))?;
    let (sig, pubkey_pb, body) =
        decode_signed_inner(&inner).ok_or_else(|| anyhow!("offline envelope: bad inner"))?;
    verify_sender(sender, pubkey_pb, &header_for(OFFLINE_SIG_PREFIX), body, sig)?;
    Ok(OpenedEnvelope {
        sender,
        message_id: env.message_id.clone(),
        kind: env.kind.clone(),
        body: body.to_vec(),
    })
}

fn hkdf_offline(shared: &[u8], eph: &[u8; 32], recipient_pk: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"VOID_OFFLINE_V2"), shared);
    let mut info = Vec::with_capacity(4 + 64);
    info.extend_from_slice(b"mail");
    info.extend_from_slice(eph);
    info.extend_from_slice(recipient_pk);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("hkdf offline key len");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn voice_chunk_roundtrip() {
        let tid = [7u8; 16];
        let bytes: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
        let parts = split_voice_for_offline(&tid, &bytes).expect("split");
        assert!(parts.len() > 1);
        let mut map = HashMap::new();
        let mut total = 0u32;
        let mut total_size = 0u32;
        for p in &parts {
            let c = decode_voice_chunk_payload(p).expect("decode");
            assert_eq!(c.transfer_id, tid);
            total = c.total;
            total_size = c.total_size;
            map.insert(c.index, c.data);
        }
        let assembled = assemble_voice_chunks(total, total_size, &map).expect("assemble");
        assert_eq!(assembled, bytes);
    }

    struct Party {
        key: libp2p::identity::Keypair,
        pid: PeerId,
        static_sk: StaticSecret,
        offline_sk: StaticSecret,
    }

    impl Party {
        fn secrets(&self) -> [&StaticSecret; 2] {
            [&self.offline_sk, &self.static_sk]
        }
    }

    fn party() -> Party {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let pid = PeerId::from(key.public());
        let offline_sk = identity_offline_secret(&key).expect("ed25519");
        Party {
            key,
            pid,
            static_sk: StaticSecret::random_from_rng(rand::rngs::OsRng),
            offline_sk,
        }
    }

    #[test]
    fn identity_offline_key_matches_secret() {
        for _ in 0..16 {
            let p = party();
            let derived = identity_offline_public(&p.pid).expect("derive");
            assert_eq!(derived.as_bytes(), PublicKey::from(&p.offline_sk).as_bytes());
        }
    }

    #[test]
    fn seal_key_ignores_poisoned_fallback() {
        let (bob, mallory) = (party(), party());
        let evil = PublicKey::from(&mallory.static_sk).to_bytes();
        let key = offline_seal_key(&bob.pid, Some(evil)).unwrap();
        assert_ne!(key.as_bytes(), &evil);
        assert_eq!(key.as_bytes(), PublicKey::from(&bob.offline_sk).as_bytes());
    }

    #[test]
    fn envelope_only_opens_for_identity_owner() {
        let (alice, bob, mallory) = (party(), party(), party());
        let env = seal_from(&alice, &bob, b"hi");
        assert!(open_envelope(&[&bob.static_sk], &bob.pid, &env).is_err());
        assert!(open_envelope(&mallory.secrets(), &bob.pid, &env).is_err());
        assert!(open_envelope(&[&bob.offline_sk], &bob.pid, &env).is_ok());
    }

    #[test]
    fn legacy_static_prekey_envelope_still_opens() {
        let (alice, bob) = (party(), party());
        let sender_pk = PublicKey::from(&alice.static_sk).to_bytes();
        let env = seal_for_recipient(
            &alice.key,
            &bob.pid,
            &PublicKey::from(&bob.static_sk),
            &alice.pid,
            &sender_pk,
            "m1",
            "dm",
            b"old",
        )
        .unwrap();
        assert_eq!(open_envelope(&bob.secrets(), &bob.pid, &env).unwrap().body, b"old");
    }

    fn seal_from(from: &Party, to: &Party, body: &[u8]) -> OfflineEnvelope {
        let sender_pk = PublicKey::from(&from.static_sk).to_bytes();
        seal_for_recipient(
            &from.key,
            &to.pid,
            &offline_seal_key(&to.pid, None).expect("ed25519 pid"),
            &from.pid,
            &sender_pk,
            "m1",
            "dm",
            body,
        )
        .expect("seal")
    }

    #[test]
    fn envelope_roundtrip_returns_signed_sender() {
        let (alice, bob) = (party(), party());
        let env = seal_from(&alice, &bob, b"hi");
        let opened = open_envelope(&bob.secrets(), &bob.pid, &env).expect("open");
        assert_eq!(opened.sender, alice.pid);
        assert_eq!(opened.message_id, "m1");
        assert_eq!(opened.kind, "dm");
        assert_eq!(opened.body, b"hi");
    }

    #[test]
    fn envelope_hides_metadata_from_node() {
        let (alice, bob, carol) = (party(), party(), party());
        let env = seal_from(&alice, &bob, b"hi");
        assert!(env.sender.is_empty() && env.kind.is_empty());
        assert_eq!(env.sender_pk, [0u8; 32]);
        assert_ne!(env.message_id, "m1");
        assert_eq!(env.local_kind, "dm");
        // Тот же id для другого получателя не связывается.
        assert_ne!(env.message_id, seal_from(&alice, &carol, b"hi").message_id);
        // Повтор того же сообщения — тот же внешний id (дедуп на ноде).
        assert_eq!(env.message_id, seal_from(&alice, &bob, b"hi").message_id);
        // Размер скрыт бакетом.
        assert_eq!(env.ct.len(), seal_from(&alice, &bob, &[7u8; 300]).ct.len());
        // `local_kind` не сериализуется.
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("local_kind") && !json.contains("\"dm\""));
    }

    #[test]
    fn envelope_rejects_rewritten_outer_id() {
        let (alice, bob) = (party(), party());
        let mut env = seal_from(&alice, &bob, b"hi");
        env.message_id = outer_message_id(&bob.pid, "m2");
        assert!(open_envelope(&bob.secrets(), &bob.pid, &env).is_err());
    }

    #[test]
    fn envelope_rejects_tampered_ct() {
        let (alice, bob) = (party(), party());
        let mut env = seal_from(&alice, &bob, b"hi");
        env.ct[0] ^= 1;
        assert!(open_envelope(&bob.secrets(), &bob.pid, &env).is_err());
    }

    #[test]
    fn envelope_rejects_wrong_recipient_id() {
        let (alice, bob, carol) = (party(), party(), party());
        let env = seal_from(&alice, &bob, b"hi");
        assert!(open_envelope(&bob.secrets(), &carol.pid, &env).is_err());
    }

    #[test]
    fn envelope_rejects_unsigned_v1() {
        let (alice, bob) = (party(), party());
        let mut env = seal_from(&alice, &bob, b"hi");
        env.v = 1;
        assert!(open_envelope(&bob.secrets(), &bob.pid, &env).is_err());
    }

    #[test]
    fn seal_rejects_foreign_sender_id() {
        let (alice, bob, mallory) = (party(), party(), party());
        let sender_pk = PublicKey::from(&mallory.static_sk).to_bytes();
        let res = seal_for_recipient(
            &mallory.key,
            &bob.pid,
            &PublicKey::from(&bob.static_sk),
            &alice.pid,
            &sender_pk,
            "m1",
            "dm",
            b"x",
        );
        assert!(res.is_err());
    }

    #[test]
    fn signed_prekey_roundtrip() {
        let alice = party();
        let pk = PublicKey::from(&alice.static_sk).to_bytes();
        let value = encode_signed_prekey(&alice.key, &alice.pid, &pk).expect("encode");
        assert_eq!(&value[..32], &pk);
        assert_eq!(verify_signed_prekey(&alice.pid, &value), Some(pk));
    }

    #[test]
    fn signed_prekey_rejects_forgery() {
        let (alice, mallory) = (party(), party());
        let evil_pk = PublicKey::from(&mallory.static_sk).to_bytes();
        // Голые 32 байта (старый формат) — без подписи.
        assert_eq!(verify_signed_prekey(&alice.pid, &evil_pk), None);
        // Mallory подписал своим ключом запись «для» Alice.
        let forged = encode_signed_prekey(&mallory.key, &mallory.pid, &evil_pk).unwrap();
        assert_eq!(verify_signed_prekey(&alice.pid, &forged), None);
        // Подменён ключ в подписанной записи Alice.
        let pk = PublicKey::from(&alice.static_sk).to_bytes();
        let mut value = encode_signed_prekey(&alice.key, &alice.pid, &pk).unwrap();
        value[..32].copy_from_slice(&evil_pk);
        assert_eq!(verify_signed_prekey(&alice.pid, &value), None);
    }

    #[test]
    fn voice_chunk_rejects_oversized() {
        let tid = [1u8; 16];
        let big = vec![0u8; (OFFLINE_VOICE_MAX_BYTES as usize) + 1];
        assert!(split_voice_for_offline(&tid, &big).is_none());
    }
}
