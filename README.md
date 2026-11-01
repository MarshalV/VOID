<div align="center">

<img src="static/Image_programm.png" alt="VOID Logo" width="160" />

# VOID — P2P Messenger

**A decentralized, end-to-end encrypted messenger.**
This repository is not only an app: it holds the `/void/…` protocol family and a desktop client on top of it.
No sign-up, no cloud account. Chat content is readable only by the peers in the conversation.
Discovery and NAT traversal go through public bootstrap/relay nodes — not a chat server, and not an anonymizer.

<p>
  <img alt="Rust"         src="https://img.shields.io/badge/Rust-2021-CE422B?logo=rust&logoColor=white">
  <img alt="libp2p"       src="https://img.shields.io/badge/libp2p-0.56-4E8EE9?logo=ipfs&logoColor=white">
  <img alt="Tauri"        src="https://img.shields.io/badge/UI-Tauri%202-FFC131?logo=tauri&logoColor=black">
  <img alt="E2EE"         src="https://img.shields.io/badge/E2EE-Double%20Ratchet-16a34a">
  <img alt="Platform"     src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue">
  <img alt="Status"       src="https://img.shields.io/badge/status-alpha-orange">
</p>

<img src="static/preview_1.png" alt="VOID Preview" width="85%" />

</div>

---

## What this is

**VOID** (Verified Open Independent Dispatcher) is an open delivery protocol and a Rust P2P app on top of it. Both layers live in this repository. The wire rules are the crates under `protocol/` and the catalog in [`spec/`](spec/README.md). `void-protocol` re-exports them for this release. Known-answer vectors are in [`spec/vectors/`](spec/vectors/README.md). The harness in [`protocol-conformance/`](protocol-conformance) runs two sessions and a dispatcher mailbox without a window. The app is the desktop that runs those rules for a person. Live chat goes **peer to peer** over `libp2p`: directly on LAN, or through a **Circuit Relay Hop** on a bootstrap node when both sides are behind NAT. Text, voice, and files are encrypted with **Double Ratchet**. Identity is a `PeerId` from the local vault — no phone number, no email.

A bootstrap node is needed to **find** a peer, **reserve a Hop**, and **store offline envelopes**. It does not decrypt messages, but it **sees metadata**: IP, PeerId, who builds a circuit with whom, and for whom offline mail sits, when, and how large it is. Details: [Privacy and threat model](#privacy-and-threat-model).

The main desktop is **Tauri 2** (`frontend/` + `src-tauri/`). Optionally a native **egui** UI (`cargo run --release --features egui-ui`).

---

## Features

- **P2P chat** — `/void/chat/1.0.0` (request-response). Payload is E2EE (`V1Packet::Encrypted`), optionally wrapped in onion (`VOID_ONION_v2`, or v1 if a hop has no descriptor).
- **E2EE** — **Noise** on the transport, then `Hello` (X25519 + Ed25519 signature bound to `PeerId`, freshness `ts`/`nonce`), then **Double Ratchet** with a DH step on every speaker change; the header and both PeerIds go into AAD.
- **1-to-1 and groups** — invite `void://group/…`. Group text is OpenMLS when every member has announced Hello bit `8`; otherwise the same pairwise fan-out as before. Voice and files stay per member.
- **Voice** — record, preview, WAV over E2EE; in-chat player. Auto-accept, no “accept file” banner.
- **Files** — up to 512 MB, including empty (0-byte) files. Chunks (`VfC1`) and offer/accept (`VfP1`) go in E2EE `/void/chat`. `/void/file/1.0.0` is a fallback channel when the peer already has a live TCP connection.
- **Offline mail** — store-and-forward on bootstrap (`OfflineMailboxStore` / `Query` / `Deliver`). Envelope v3 is signed with the sender’s libp2p key; sender and type sit inside `ct`; unsigned envelopes are rejected. On the node only the recipient is visible. The node in [`VOID_node`](https://github.com/MarshalV/bootstrap_node) hands the box only to the TCP peer whose PeerId is that recipient. TTL 7 days, per-uploader quotas and a store rate limit on the node.
- **Own DHT** — Kademlia `/void/kad/1.0.0`, not IPFS. Chat text is not written to the DHT.
- **NAT** — working path: **Relay v2 Hop** (`listen_on(…/p2p-circuit)` → `ReservationReqAccepted`). DCUtR / AutoNAT / UPnP are **off** (enable with `VOID_ENABLE_NAT=1`: a second dial to the node tears down TCP).
- **Client transport** — listen on **TCP :50001** only. One TCP to bootstrap; `/p2p/` is stripped on dial; the real PeerId is written to the vault after Identify. The client does not open QUIC to the node.
- **LAN** — mDNS (disable with `VOID_DISABLE_MDNS`).
- **Single process** — `void.instance.lock` + TCP port `50001`; in Tauri a second launch (shortcut while the window is in the tray) raises the running window (`tauri-plugin-single-instance`) instead of a second copy.
- **Vault** — nickname, keys, contacts, groups in `vault.bin`; master key in `void.key`. Journal — `chat_journal.bin`, undelivered — `outbox.bin`.
- **Delivery** — ○ / ✓ / ✓✓; read receipt when the chat is open.
- **Beacon** — closing the window hides to tray; the process stays up. UI header uses `Image_programm.png`.
- **Onion** — `VOID_ONION_v2` when every hop has a fresh descriptor, otherwise `VOID_ONION_v1`. 1 live node → 1 hop, 2 → both, 3+ → up to three. The live path is shown in settings. A v2 exit does not see the sender of Hello or Encrypted. A mailbox cell has no sender field; the reply address is inside the seal so the exit can return the handoff Ack. One node or two hops still link the path — see [onion](#onion-void_onion_v2).

---

## Architecture

### Application layers

```
┌─────────────────────────────────────────────────────────────┐
│  frontend/          HTML / CSS / JS (webview)               │
│  events: void://snapshot (~120 ms), void://message, …       │
└────────────────────────────┬────────────────────────────────┘
                             │ Tauri commands
┌────────────────────────────▼────────────────────────────────┐
│  src-tauri/         window, tray, emit to JS                │
└────────────────────────────┬────────────────────────────────┘
                             │ VoidRuntime
┌────────────────────────────▼────────────────────────────────┐
│  src/bridge.rs      vault, journal, outbox, SnapshotDto     │
│                     UICommand ──►  NetworkEvent ◄── swarm   │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│  src/network.rs     libp2p Swarm (ChatBehaviour)            │
└────────────────────────────┬────────────────────────────────┘
                             │ void-protocol (re-export)
┌────────────────────────────▼────────────────────────────────┐
│  protocol/void-frames · void-session · void-envelope        │
│  protocol/void-onion  · void-kad-rules                      │
└─────────────────────────────────────────────────────────────┘
```

`p2p-messenger` depends on all five crates and on the facade. Call sites still use `void_protocol::…`. A node links `void-frames`, `void-envelope`, and `void-onion`, plus its own swarm. `void-onion` has no libp2p dependency and does not enable `kad`. Its `PeerId` is the multihash bytes; the facade turns that into `libp2p::PeerId`. Session, envelope, and frames use `libp2p-identity` for the Ed25519 bind, which is the same `PeerId` type the client already passes. `void-kad-rules` checks a DHT value and does not open a swarm. The Kademlia `RecordStore` stays on the facade because it needs the `kad` feature.

| Module | Role |
|--------|------|
| `src/network.rs` | Swarm, dial bootstrap, Hop, RR chat, mailbox, gossip |
| `src/bridge.rs` | Headless runtime for Tauri: snapshot push, not poll |
| `protocol/void-frames` | `V1Packet` (`Hello`, `Encrypted`, mailbox, onion, …), field limits, JSON and CBOR encode/decode |
| `protocol/void-session` | Hello bind, `SecureSession` (DH step, header and PeerId in AAD), group roster |
| `protocol/void-onion` | Onion v2 when every hop has a descriptor, otherwise v1. Builds without `kad` |
| `protocol/void-envelope` | New envelopes prefer the rotating prekey plus one one-time key. If the node has neither, the client seals to the X25519 key derived from the recipient PeerId. That same key still opens old letters |
| `protocol/void-kad-rules` | `dht_record_allowed`: signed unexpired prekey, or a v3 mailbox. Other values are refused |
| `protocol/` (`void-protocol`) | Thin re-export of the crates above for this release, plus `VoidKadStore` (`protocol/src/kad_store.rs`) |
| `src/relay_mailbox.rs` | Local mailbox for LAN without bootstrap: the client stores neighbours’ mail and serves it to the owner on Query. This copy keeps 256 mailboxes; the node and the harness keep 4096 |
| `src/hello_replay.rs` | Cache of accepted `Hello` ephemeral keys (256 per peer). A `Hello` with `ts == 0` does not reset a live session |
| `src/vault.rs` / `paths.rs` | Vault, data directory, instance lock |
| `src/bootstrap.rs` | Seed merge: vault, env, HTTP, built-in list |
| `src/file_transfer.rs` / `src/voice.rs` | Files and voice |
| [`spec/`](spec/README.md) | Wire catalog for a second implementation (Russian). Not linked into the desktop |
| [`spec/vectors/`](spec/vectors/README.md) | Known-answer JSON. `cargo test -p void-protocol --lib vectors` checks the files in git |
| [`protocol-conformance/`](protocol-conformance) | Two `SecureSession`s and an in-memory dispatcher mailbox. No Tauri, no egui, no vault |

The UI does **not** poll `get_snapshot` on a timer in normal mode. State goes out as `void://snapshot` (flusher ~120 ms, monotonic `revision`). While status is `Hop…`, the UI also polls the snapshot so it does not stick on “waiting for Ack”.

### Status line

Example: `online · Hop OK · 12D3KooW… · live 1 · contacts 0 · bootstrap 1/2`

Until Hop exists, `via node` is appended (mailbox chat). While waiting for Ack — also `Hop…`.

| Fragment | Meaning |
|----------|---------|
| `online` | TCP to at least one bootstrap node |
| `via node` | Node is alive, **Hop not yet** (mailbox chat, no live circuit) |
| `Hop…` | `listen_on(…/p2p-circuit)` sent, waiting for Ack |
| `Hop OK` | Reservation accepted (or the UI confirmed it ~2.5 s later if the Ack event did not surface) |
| `no Hop` | Node is there, no reservation request pending |
| `live N` | Live TCP count: bootstrap + contacts |
| `contacts N` | Live chat peers (**excluding** bootstrap) |
| `bootstrap A/B` | `A` — how many seeds currently on TCP; `B` — how many addresses in the vault. `1/2` = one node live out of two in the list |

`1/2` is not an error: the client first holds **one** primary node (`147.78.64.22:4001`) and picks up the second after Hop. One node with `Hop OK` is enough for NAT and the mailbox.

### How two clients meet

```
Alice                         Bootstrap                         Bob
  │ TCP :4001 (no /p2p/ check)      │
  │ Identify /void/v1               │
  │ vault: live node PeerId         │
  │ listen …/p2p/<node>/p2p-circuit │
  │ ◄── ReservationReqAccepted ──── │
  │          “Hop OK”               │
  │                                 │
  │  dial …/p2p-circuit/p2p/<Bob>   │
  │  (after Hop; LAN/mDNS separate) │
  │                                 │
  │ Hello → Double Ratchet          │
  │ Encrypted  (optional onion wrap)│
```

1. One TCP to `IP:4001`. `/p2p/` is stripped from the dial (`DialOpts::unknown_peer_id()`); otherwise a stale PeerId in the vault breaks Noise in 1 ms.
2. After Identify the client rewrites the bootstrap in the vault to the node’s **live** PeerId.
3. Hop: one `listen_on(/ip4/…/tcp/4001/p2p/<node>/p2p-circuit)` **after Identify** (~1.5 s). Retry only if Hop is still pending (cooldown ~3 s), no Reserve spam. Status is **Hop OK** after `ReservationReqAccepted`; if the event never reached the UI — after ~2.5 s with live TCP.
4. Circuit to a contact — **after** Hop (pause ~8 s after Ack), one address of the live relay; on `NoReservation` pause ~45 s. LAN/mDNS is separate, not mixed into the same dial.
5. `DialBack` asks the peer to dial us over circuit (NAT asymmetry).
6. Offline mail uses the TCP that is already up to the node. It does not wait for Hop and it does not ride a Hop stream.

Two VOID copies on one vault open two TCPs to the same node — both go `yamux Closed` immediately. Hence the instance lock, refuse if `:50001` is taken, and in Tauri a single window.

### Network stack (`libp2p`)

| Layer | Current |
|-------|---------|
| Client listen | TCP `0.0.0.0:50001`. **No** QUIC listen |
| Dial bootstrap | one TCP to `host/tcp/port`; QUIC to the node is filtered out |
| Multiplexer | Yamux (up to 512 streams on the client; Hop on the node is sensitive to RR spam) |
| Channel | Noise |
| Identify | `/void/v1`; bootstrap is recognized by `agent_version` `void-bootstrap-node…`. `;cbor=1` on that string means the node reads and writes CBOR |
| Chat | `/void/chat/1.0.0`, JSON or CBOR `V1Packet` |
| Files (offer, fallback) | `/void/file/1.0.0` |
| File/voice offer and chunks | E2EE frames `VfP1` / `VfC1` inside `/void/chat` |
| DHT | `/void/kad/1.0.0`, `Mode::Server`, k-bucket **Manual** (addresses after live TCP) |
| Discovery | mDNS + Kademlia + bootstrap list |
| Relay | client: `relay::client`; Hop = `ReservationReqAccepted` |
| DCUtR / AutoNAT / UPnP | `Toggle::off` until `VOID_ENABLE_NAT=1` |

There is no dedicated chat server. Relay carries opaque circuit bytes. Offline envelopes **sit on the node** until fetch (`take_batch`) or TTL.

Kademlia `start_providing` — after Identify with a chat peer (not bootstrap). `kad.bootstrap()` — ~30 s **after** Hop Ack, not at first TCP (otherwise a second dial kills the session).

#### Reliability

| Mechanism | Behaviour |
|-----------|-----------|
| Dial bootstrap | one endpoint (`host/tcp/port`), cooldown, no parallel QUIC |
| Contact reconnect | tick ~5 s; circuit only after Hop, backoff ~45 s after `NoReservation` |
| Hop | one `listen_on` after Identify (~1.5 s); retry only if pending (cooldown ~3 s) |
| KAD | `kad.bootstrap()` ~30 s **after** Hop Ack, then every 5 min |
| E2EE Hello | on `ConnectionEstablished` with a contact (not bootstrap) |
| Outbound retry | `RESEND_GRACE` 1 s, exponential up to 300 s |
| Group voice | fan-out + retry `SendGroupMessage` (~8 s) until the WAV is gone |
| Undelivered | `outbox.bin` → `OfflineMailboxStore` on the connected bootstrap, one envelope per request. The node’s `Ack` is handoff. Empty `Deliver` is a refusal and the letter stays in `outbox.bin`. Live `Encrypted` still retries; when that contact’s TCP comes up, the next tick sends, without waiting out the 300 s backoff |
| Offline mailbox | `OfflineMailboxQuery { recipient }` on the node TCP as soon as it is up, then about once a second. A batch’s remainder waits ~500 ms |

### Finding a peer

You need **bootstrap multiaddrs** with `/p2p/<PeerId>` in the vault (after the first successful Identify the node PeerId is filled in). Built-in seed: `/ip4/147.78.64.22/tcp/4001/p2p/12D3KooWCAH8ykDMThNRRVLAM6LnuVrJeoZrQADzHC2x6ddhZxyG`. Reference node: [`MarshalV/bootstrap_node`](https://github.com/MarshalV/bootstrap_node).

Sources (merged, deduped):

1. Built-in (`BUILTIN_VOID_BOOTSTRAP` / `VOID_BUILTIN_BOOTSTRAP`).
2. HTTP(S) list (`VOID_BOOTSTRAP_URL` / `VOID_BOOTSTRAP_PUBLIC_LIST_URL`), ~256 KiB. Optional `VOID_BOOTSTRAP_TRUSTED_HOSTS`, pin `VOID_BOOTSTRAP_TLS_LEAF_SHA256`.
3. `VOID_BOOTSTRAP` — comma-separated multiaddrs.
4. One-shot import of `void-bootstrap.txt` next to the binary → vault. Optional Ed25519 (`VOID_BOOTSTRAP_SIGNING_PUB_HEX`).
5. UI: bootstrap settings.

Clients also **gossip** public seeds to each other (`BootstrapGossip`, up to 32 addresses).

```powershell
$env:VOID_BOOTSTRAP = "/ip4/147.78.64.22/tcp/4001/p2p/12D3KooW..."
```

In the connect field: `multiaddr`, `IP`, or `IP:PORT`. A bootstrap in the seed list must have `/p2p/<PeerId>` (after connect it must match the node’s Identify).

### Protocol `/void/chat/1.0.0`

| Packet | Purpose |
|--------|---------|
| `Hello` | X25519 + identity signature, and ML-KEM-768 when bit `32` is set. Current clients sign bind v3: `ts`, `nonce`, and `caps` (±10 min). A session opens only when that signature is v3 and `caps` bit `1` (`HELLO_CAP_HEADER_AAD`) is set, on a direct path and over onion. Bit `2` is CBOR, bit `4` is the contact queue, bit `8` is MLS, bit `16` seals the ratchet header, bit `32` is the hybrid Hello. Those bits do not open a session by themselves. With bit `32` the first Hello carries `kem_ek` and an empty `kem_ct`; the reply carries `kem_ct`. `pq_sig` covers the v3 fields plus those bytes. A set bit with a bad signature or a missing ciphertext does not open a session. v1 and v2 may verify and do not create a session. A repeated ephemeral is rejected (last 256 per PeerId) and does not reset a live session. A Hello with `ts == 0` does not replace one either |
| `Encrypted` | Double Ratchet. With Hello bit `16` on both sides, `dh_pub`, `pn`, and `n` are zeros and the real header is in `sealed` |
| `Ack` | RR reply / empty mailbox / node accepted the letter |
| `MailboxChallengeRequest` / `MailboxChallenge` | nonce and `ts` for a signed fetch. The desktop does not send these to the current node: that node has no such frames |
| `OfflineMailboxStore` / `Query` / `Deliver` | offline mail on bootstrap. While TCP to the node is up, Store and Query go on that connection, one envelope per Store. `Query` is `{ recipient }` only (`ts`, `nonce`, and `sig` are omitted when they are zero). The node returns the box when the Noise peer is that recipient, then deletes the batch. Empty `Deliver` in reply to `Store` is a refusal. A v2 cell is used only when that TCP is not up and another live hop can be the entry |
| `PrekeyPut` / `Get` / `Offer` | Signed prekey plus a batch of one-time keys. `Offer` returns the signed prekey and one one-time key, then deletes that key. If the offer has no one-time key, the letter is sealed to the signed prekey alone. If nothing sealable comes back, it is sealed to the PeerId key. An unsolicited `Offer` is ignored |
| `CreateQueue` / `QueueStore` / `QueueQuery` / `QueueDeliver` | Contact queue (`HELLO_CAP_QUEUES`). The owner registers `queue_id`, a write token, and a signature; the grant goes inside E2EE. `QueueStore` is the envelope padded to 64 KiB. The running node still files mail by recipient PeerId; the client always stores that copy too |
| `BootstrapGossip` | seed exchange |
| `DialBack` | “dial me over circuit” |
| `Onion` / `OnionDrop` | `VOID_ONION_v1`. `OnionDrop` is accepted only from a bootstrap that advertised `;onion=` in its own Identify; inside — only `Hello` / `Encrypted` / `Ack`. The last layer still carries `src` |
| `Onion2` / `OnionDeliver` | `VOID_ONION_v2`. Fixed-size cell. The exit forwards an opaque body sealed to the recipient’s identity key. No `src`. Used only when every hop on the path has a fresh descriptor |

Chat RR: request up to 4 MiB, response up to 16 MiB. One serde schema for `V1Packet`. The body stays JSON until both sides have announced CBOR: bit `2` in Hello between clients, or `;cbor=1` in the node’s Identify agent (the dispatcher does not send Hello). After that, requests are CBOR. The first Hello, sent before the peer’s announcement, stays JSON. A reply uses the same encoding as the request. Receivers always accept both: content-type `VC\x01\x01` (JSON) or `VC\x01\x02` (CBOR), else CBOR magic `d9 d9 f7`, else the first byte (`{`, `[`, `"`, or whitespace is JSON). In CBOR, `Vec<u8>` is a byte string; `[u8; N]` stays an array of numbers, so JSON and the mailbox bincode layout are unchanged. Field caps, independent of JSON expansion: `ct` 256 KiB, `ciphertext` 1 MiB, at most 64 envelopes in one `Store`, at most 1024 in one `Deliver`. `/void/file/1.0.0` stays JSON.

### End-to-end encryption (`protocol/void-session`)

| Stage | Algorithm |
|-------|-----------|
| Transport | **Noise** |
| Handshake | static + ephemeral **X25519** in `Hello`, **Ed25519** bound to `PeerId`. With Hello bit `32` on both sides the root also takes the ML-KEM-768 secret (`VOID_SALT_PQ`). `transport_sig` stays v3; `pq_sig` is the extra v4 signature |
| Ratchet | **Double Ratchet**: the initiator takes the first DH step right after `Hello`, then a new DH key on every speaker change; header (`dh_pub`, `pn`, `n`) and both PeerIds are AAD. This client turns that requirement on before the first frame. Hello bit `16` seals that header under its own key; the clear fields are then zeros |
| KDF | **HKDF-SHA256** |
| AEAD for chat / onion / offline `ct` | **ChaCha20-Poly1305** |
| Vault / journal / file cache | **AES-256-GCM** |
| File integrity | **BLAKE2b-512** (first 32 bytes) |
| Key memory | `zeroize` |
| Skipped keys | up to **4096** total, at most **1000** per header, TTL 1 h |

A session is not opened for a peer that signs only v1 or v2, or that sends frames without the header in AAD. A Hello with `ts == 0` does not reset a live session. **Update the node together with the client:** an old node on the onion path drops `ts`/`nonce`/`caps`, and a new `Hello` over onion will fail. Seed between an old and a new node will not complete either.

Offline envelope v3 (`protocol/void-envelope`):

- `ct` — ChaCha20-Poly1305. A new letter uses both DH shared secrets (signed prekey and one one-time key). An old letter uses one DH. See [Prekey](#prekey);
- inside `ct` — sender, `sender_pk`, `message_id`, `kind`, body, and a signature of the sender’s libp2p key over those, the recipient, and `eph`; body is padded (power of two from 512 B to 4 KiB, then multiples of 4 KiB);
- outside, `sender` and `kind` are empty, `sender_pk` is zero, `message_id` is a hash of the recipient and the real id (the node can dedupe repeats but cannot link letters of different recipients);
- external id, recipient, and `eph` are cipher AAD: the node cannot rewrite the id or redirect the envelope;
- the recipient accepts `dm` / `group` only if inner `sender_id` matches the signature; `group_sync` is from the signer;
- v3 and v2 (signed, fields in the clear) are accepted; v1 (unsigned) is dropped. **Incompatible with old clients** — update every participant.

The node sees the recipient (mailbox slot), time, and size to bucket accuracy.

### Prekey

A new offline letter is sealed to the recipient’s **rotating X25519 prekey** and one **one-time prekey** when the node returns both: DH(ephemeral, signed prekey) and DH(ephemeral, one-time key). The one-time id sits inside the ciphertext. After open the recipient deletes that key; a second letter with the same id does not open. A signed prekey with an empty one-time batch still seals (single DH). If the node has no sealable prekey at all, the letter is sealed at once to the X25519 key derived from the recipient PeerId, and still uploaded. The signed prekey lives 7 days and is rotated when less than 24 hours remain. The previous secret is kept until its own `not_after`, then dropped. The client publishes both on the bootstrap (`PrekeyPut`) and in DHT `/void/prekey/<peer>` and `/void/opk/<peer>`.

DHT value v2: `pk[32] || 0x02 || not_after[8] ||` owner signature. v3 appends the ML-KEM-768 encapsulation key after the expiry and uses mark `0x03`; the signature is `VOID_PREKEY_SIG_V3` over the X25519 key and that encapsulation key. v1 (no expiry) still verifies and is not used for seal. A letter sealed only to the signed prekey, when that prekey carries the encapsulation key, prefixes `ct` with `VQK1` and the KEM ciphertext. The envelope fields stay the same. A letter that also uses a one-time key stays on the two X25519 shares and does not add that prefix. The node source accepts a v3 put when the Noise peer is the claimed owner, the signature matches the identity key inside the PeerId, and `not_after` is in the future and at most 30 days out. An unsigned put is refused. `PrekeyOffer` is used only if the same signature and expiry check out, and only in answer to our own `PrekeyGet`. The running node binary serves one-time keys and `kem_ek` only after it is rebuilt from this tree.

The PeerId key is Ed25519 inside the PeerId, Edwards → Montgomery, the same conversion as `crypto_sign_ed25519_pk_to_curve25519`. It is not distributed. The recipient opens a letter with the current prekey secret, the previous one, the one-time keys still on disk, and this identity secret.

Leaking the libp2p identity still opens letters that were sealed to it. Letters sealed only to a prekey that has already been dropped do not.

### Offline mail

The live path is **not DHT**. While the client has TCP to the bootstrap, Store and Query are ordinary request-response on that connection. A v2 cell is only the path when that TCP is down and another connected hop can be the entry. The entry hop Ack is not handoff; the node’s own `Ack` is.

1. Recipient offline → seal (prekey and one-time key, signed prekey alone, or the PeerId key) → `OfflineMailboxStore`, one envelope per request. The node replies `Ack` if it stored. Empty `Deliver` is a quota, rate, or mailbox-ceiling refusal — the letter stays in `outbox.bin` and will retry later. `outbox.bin` is cleared on live delivery, not on this `Ack`.
2. Recipient comes online → `OfflineMailboxQuery` with `recipient` set to their own PeerId, on their own TCP to the node. The node returns a batch (`take_batch` ≤ 512 KiB plaintext) and **deletes** it from `relay_mailbox.bin`. The first query runs as soon as that TCP is up, then about once a second. The rest of a batch waits ~500 ms (an immediate re-query would spin the same batch and choke the connection).
3. The frames crate can also carry a signed fetch (`MailboxChallenge` plus `VOID_MAILBOX_QUERY_v1`). The node this desktop uses does not implement those frames, so the client does not send them. A query whose TCP peer is someone else is refused and the mail stays.

If the contact’s Hello has `HELLO_CAP_QUEUES`, the sender also keeps a queue: `CreateQueue`, an E2EE grant, and a `QueueStore` blob padded to 64 KiB so text and voice are the same length on the wire. The node log for that copy is a short `queue_id` and the bucket, not the recipient PeerId. Until that node is the one in production, the PeerId `OfflineMailboxStore` above is the copy the recipient actually reads.

Node limits: at most 4096 mailboxes (a new slot past that is refused), envelope lifetime 7 days, up to 256 envelopes / 8 MiB from one sender in one mailbox, `Store` at most 600 requests, 600 envelopes, and 48 MiB per minute per peer.

With bootstraps configured, letters go only to them, and the client refuses `Store` from anyone else. Without bootstrap (LAN), connected peers get copies — then the client itself answers Query from local `relay_mailbox.bin`, also only to the mailbox owner, with the same per-uploader rate and volume as the node. Kademlia accepts a mailbox record only as a bincode list of v3 envelopes under `/void/mailbox/<PeerId>`.

### Onion (`VOID_ONION_v2`)

A layer **on top of** libp2p and E2EE. This is not a hidden route: one node, or two hops, still links the ends. The settings line still says the route is not anonymous when fewer than three hops are live.

```
Alice → Node A → [Node B → Node C] → Bob
```

| Live nodes with an onion key | Chain |
|------------------------------|-------|
| 0 | no onion — circuit / direct RR |
| 1 | one hop |
| 2 | both hops |
| 3+ | up to three; entry is a guard kept for 14 days |

v2 is wrapped only when every hop has a descriptor `{peer_id, onion_pk, epoch, not_after, operator, sig}` that is still inside its week and not more than 30 days ahead. Otherwise the client wraps v1.

What a hop sees on a **v2** cell:

| Party | Sees |
|-------|------|
| Entry | Alice’s IP and PeerId, the next hop, one of the buckets 2 / 16 / 64 KiB |
| Middle | neighbouring hops, the same bucket |
| Exit | Bob’s PeerId, the same bucket, the length of the sealed body. Not Alice’s PeerId |

The body is sealed to the X25519 key derived from Bob’s PeerId. `Hello` and `Ack` carry Alice’s PeerId inside that seal. `Encrypted` is demultiplexed by trying the live session. The reply is a new onion to that session peer. A v1 cell still puts Alice in `OnionDrop.src`, so an old hop on the path brings the pair back.

Other limits:

- files and large chunks stay on the live channel or in the mailbox, not in an onion cell;
- the guard is sticky for 14 days; middle and exit rotate with the 15-minute path and prefer a different IPv4 `/16`, a different IPv6 `/32`, and a different `VOID_OPERATOR` when that label is set;
- the same node is not used as both entry and exit;
- a hop key rotates every 7 days. The previous secret decrypts for one more day, then it is erased. A higher `epoch` with a valid signature replaces the key the client already stored;
- onion is not used for a packet that is already on a direct channel to Bob.

The live route (hop PeerIds) is shown in settings. Old nodes without `;onion=` are not put in the chain. A hop forwards the inner frame only after Identify, parses `next` as a PeerId, and rate-limits forwarding (600/min from the previous hop, 6000/min overall). Logs do not record `next` or `src`. This is not a mixnet and not protection against a global observer. DCUtR (if enabled) can open a direct channel and link IPs again.

### Files (`src/file_transfer.rs`)

| Parameter | Value |
|-----------|-------|
| Chunk | 32 KB |
| Max size | 512 MB (0 bytes allowed) |
| Offer / Accept | E2EE `VfP1` in `/void/chat`; `/void/file` if the peer is already connected |
| Chunks | E2EE `VfC1` in `/void/chat` |
| Cache | `%APPDATA%\VOID\files` (and equivalents) — AES-256-GCM, `*.vfc` |
| Cache key | HKDF-SHA256 from the master key (`VOID_FILE_CACHE_v1`) |
| “Download” | copy to `Downloads/VOID Messenger/` |
| Delete from chat | cache only |
| Over circuit | ~64 KB/s |

The filename in the offer is seen by whoever terminates the connection (the peer; with `/void/file` — also whoever sees that substream). Over relay without an E2EE offer, metadata should not leak to the node.

### Voice (`src/voice.rs`)

WAV mono 48 kHz 16-bit PCM, up to 5 min. Recording is a child process `--voice-record` (`cpal`). Into chat — `VoiceMeta`; WAV as a file with auto-accept. Offline: `voice_chunk` pieces through the same mailbox. Metadata is stripped when possible (`metadata_strip`).

### Groups (`protocol/void-session`)

Member list in the vault + thread `group:<id>`. A new group is MLS only when every selected member has already announced Hello bit `8` (`HELLO_CAP_MLS`). Any member without that bit keeps the whole group on pairwise fan-out, and an existing pairwise group is not upgraded later. An MLS group refuses a later invitee who has not announced the bit. Text in an MLS group is one OpenMLS ciphertext (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) inside `V1Packet::GroupMls` on `/void/chat`, delivered to each member. Voice and files stay per-peer, each with its own `transfer_id`. The joiner sends `MlsKeyPackage`; the creator answers with Welcome to that member and Commit to the others. After someone leaves, the creator commits the removal. A second copy of that Commit is rejected, and the leaver's old state does not open later epochs. The OpenMLS storage snapshot lives in `vault.bin` under the same master key. Group voice is queued and retried until the WAV is gone. Invite: `void://group/…`, with `&mls=1` when the group is MLS. The creator signs the roster: `version` plus a signature over `group_id ‖ version ‖ name ‖ members`, and one trailing `0x01` when the group is MLS. A snapshot is applied only when `version` is greater than the local one and the signature checks out. An unsigned sync from the creator is refused. Anyone else may only add or remove themselves, and that does not move `version`. `group_leave` — from the member or the creator, `group_delete` — creator only. A live or offline message is stored only when both we and the sender are in the roster. A member who still holds an epoch can read what that epoch carried.

### Local storage

Directory (override with `VOID_DATA_DIR`):

| OS | Path |
|----|------|
| Windows | `%APPDATA%\VOID` |
| Linux | `~/.local/share/VOID` |
| macOS | `~/Library/Application Support/VOID` |

| File / folder | Contents | Protection |
|---------------|----------|------------|
| `void.key` | Wrapped master key (`VOIDKEY3`, old `VOIDKEY2` still opens) | Password + Argon2id (64 MiB) + AES-GCM, AAD = file type |
| `vault.bin` | Nickname, keys, contacts, groups, bootstrap | AES-256-GCM |
| `chat_journal.bin` | Conversations | AES-256-GCM |
| `outbox.bin` | Undelivered | AES-256-GCM |
| `files/` | Attachment cache `*.vfc` | AES-256-GCM |
| `voice/` | WAV | data directory |
| `void.pwd` | “Remember password” | Windows: Credential Manager + file; otherwise file |
| `void.instance.lock` | One process per vault | exclusive open |
| `hello_seen.bin` | Last 256 ephemeral keys of accepted `Hello` per peer. A `Hello` with `ts == 0` does not reset a live session | on disk |
| `offline_prekey.bin` | Current and previous offline-mail prekey secrets | on disk |
| `relay_mailbox.bin` | Local mailbox only on LAN without bootstrap | on disk, unsealed (unlike the node) |

> Never give the vault password together with `void.key` and `vault.bin`.

---

## Privacy and threat model

VOID **hides content** from the network and from bootstrap. VOID **does not hide** that you are online or which IP you used to reach the node.

Typical path behind NAT is one Hop (or LAN):

```
Alice ──E2EE──► Relay/Bootstrap ──► Bob
```

Relay does not see plaintext, but **can** match IP↔PeerId, the circuit pair `src→dst`, volume/time, and the offline-mail recipient.

| Observer | Text / files / voice | Sender IP | Who you are |
|----------|----------------------|-----------|-------------|
| Peer | Yes | Yes if the channel is direct (LAN). Through one relay — usually not | PeerId + nickname |
| Bootstrap operator | No | **Yes** | PeerId, circuit, mailbox metadata |
| Another DHT peer | No | No (except mDNS on LAN) | sometimes a prekey publisher |

The stable identifier is **PeerId** (as long as the vault lives). This is **pseudonymous E2EE**, not Tor. Do not use VOID if the threat model is “the node must not know who wrote to whom”.

One node is the normal mode for current VOID (discovery, Hop, mailbox). It does not hide who met whom — see [onion](#onion-void_onion_v2).

---

## Stack

- **Language:** Rust 2021
- **Network:** libp2p 0.56
- **Desktop:** Tauri 2.6 (`frontend/` + `src-tauri/`); optional egui 0.29 (`egui-ui`)
- **Audio:** cpal + hound; WinMM fallback on Windows
- **Crypto:** x25519-dalek, chacha20poly1305, aes-gcm, argon2, hkdf, blake2, zeroize

The Tauri package (`src-tauri`) depends on `p2p-messenger` with `default-features = false` — no egui.

---

## Install and run

You need **Rust** ≥ 1.77.2 (`stable`) and [Tauri CLI](https://v2.tauri.app/start/prerequisites/).

### Tauri (main client)

```bash
git clone https://github.com/MarshalV/p2p-messenger.git
cd p2p-messenger
cargo tauri dev
# release (MSI/NSIS/deb/dmg):
cargo tauri build
```

Scripts put installers in the root `target/`: `build.bat` (Windows, kills running `app.exe` / `VOID-P2P-Messenger.exe` before linking), `./build.sh` (Linux), `./build_mac.sh` (macOS).

One vault — **one** process. A second copy will not start (`void.instance.lock` / port 50001). If VOID is already in the tray, the shortcut opens the same window.

### egui (optional)

```bash
cargo run --release --features egui-ui
```

On Linux, egui may need `libxcb`, `libxkbcommon`, `libwayland-dev`.

On first launch you set a vault password. A nickname like `User_1A2B` can be changed in settings.

### Connecting

1. Your Peer ID is in settings.
2. A contact is by Peer ID (not a bare IP without `/p2p/<PeerId>`).
3. Bootstrap in the seed list; status `bootstrap 1/N` and **Hop OK** (not a stuck `Hop…`). `1/2` means one of two vault nodes is live — enough for chat.

---

## Client configuration

| Variable | Purpose |
|----------|---------|
| `VOID_DATA_DIR` | Data directory instead of `%APPDATA%\VOID` |
| `VOID_BOOTSTRAP` | comma-separated multiaddrs |
| `VOID_BOOTSTRAP_URL` | URL of a text seed list |
| `VOID_BOOTSTRAP_PUBLIC_LIST_URL` | Public URL baked into the build |
| `VOID_SKIP_PUBLIC_BOOTSTRAP_LIST` | Do not fetch the built-in public list |
| `VOID_BOOTSTRAP_TRUSTED_HOSTS` | Allowed hosts for the URL list |
| `VOID_BOOTSTRAP_TLS_LEAF_SHA256` | Pin SHA-256 of the HTTPS leaf DER |
| `VOID_BOOTSTRAP_SIGNING_PUB_HEX` | Ed25519 for list signature |
| `VOID_BOOTSTRAP_URL_SIG_HEX` | Signature of the URL-list body |
| `VOID_DISABLE_MDNS` | Disable LAN discovery |
| `VOID_ENABLE_NAT` | `1` — enable DCUtR, AutoNAT, UPnP (off by default) |
| `VOID_APPLY_FIREWALL_RULE` | Allow firewall edits (Windows/macOS) |
| `VOID_SKIP_SUBNETS` | Extra CIDRs of “junk” listen addresses |
| `VOID_BUILTIN_BOOTSTRAP` | Bake seeds in at build time |
| `RUST_LOG` | Default **warn**; `void_net=debug` — addresses in logs |

What the node still sees: [Privacy](#privacy-and-threat-model).

---

## Running your own infrastructure

Your own bootstrap/relay nodes speed up discovery and NAT.

### Reference: `void-bootstrap-node`

> 🔗 **[github.com/MarshalV/bootstrap_node](https://github.com/MarshalV/bootstrap_node)**

| Role | What it does |
|------|----------------|
| **Kademlia Server** | Entry into `/void/kad/1.0.0` |
| **Circuit Relay v2** | Hop for clients behind NAT; opaque circuit bytes |
| **Offline mail / prekey** | Store/query on `/void/chat`. `Query` is `{ recipient }`. The node returns the box only when that string is the TCP peer’s PeerId, then deletes the batch (`take_batch`). `relay_mailbox.bin` is encrypted. At most 4096 mailboxes, TTL 7 days, per-uploader quotas, refusal via empty `Deliver`. `PrekeyPut` is stored only with the owner’s signature and an expiry within 30 days. Kademlia `put` keeps a signed unexpired prekey or a v3 mailbox and drops anything else |
| **VOID-SEED** | `/void-seed/v1` on a separate TCP — list exchange **between nodes** |
| **Onion hop** | Identify `void-bootstrap-node/…;onion=<pk>;osig=…;epoch=…;until=…;op=…;osig2=…;cbor=1`. Unwrap v2 (fixed cell) or v1 (JSON inside the cell) and forward. When the peeled `next` is this node and the seal is a mailbox frame, file `Store` by `recipient`. A direct `Query` is answered only if the TCP peer is that recipient. The hop Ack is not handoff; the handoff Ack is a new cell on the reply path. The outer `/void/chat` frame is CBOR only when that next hop announced it. The hop key rotates weekly; the previous secret lasts one more day. `next` is a PeerId. A v2 cell whose slot-0 key (BLAKE2b-128 of `eph` and the slot ciphertext) was peeled in the last 14 days is dropped and not forwarded. Forward is limited to 600/min per previous hop and 6000/min overall. Logs do not record `next` or `src` |

Live `V1Packet::Encrypted` is **not** forwarded as a chat server. Circuit and mailbox are separate paths. Onion is another: the node sees the next hop, not plaintext.

#### Node libp2p

| Component | Setup |
|-----------|-------|
| Transports | TCP + QUIC, `LISTEN_PORT` (4001) |
| Identify | `/void/v1`, `void-bootstrap-node/…;onion=…;cbor=1`. `;cbor=1` is `HELLO_CAP_CBOR` for the dispatcher |
| Kademlia | `/void/kad/1.0.0`, **Mode::Server**. `put` accepts `/void/prekey/*` (owner signature, expiry ≤ 30 days) and `/void/mailbox/*` (v3 envelopes). Any other key is refused |
| Relay | Default + NAT-oriented limits |
| Logs | `RUST_LOG` default **info** (IP in `endpoint`) |

The client vault needs the **current** `/p2p/<PeerId>` of this node (banner at process start). Stale node key + stale `/p2p/` in the client = TCP for 1 ms and silence.

#### Protocol `/void-seed/v1`

Node-to-node list exchange (not client chat): X25519 PFS, HKDF-SHA-512, ChaCha20-Poly1305, Ed25519 of the same pair as the libp2p `PeerId`. The signature covers direction, both ephemeral keys, the signer’s PeerId, timestamp, and (on the client) the server PeerId. `protocol_version` inside AEAD is a version marker, not access control. The server writes the actual TCP IP into `known_nodes.json`. An old node will not complete handshake with this one — update all of them.

#### Node state

| File | What | Share |
|------|------|-------|
| `bootstrap_peer.key` | Node identity | **no** |
| `known_nodes.json` | Other bootstraps | yes (public addresses) |
| `relay_mailbox.bin` | Offline envelopes (encrypted with a key from `bootstrap_peer.key`; slots are hashes) | **no** |

#### Node environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `LISTEN_PORT` | `4001` | libp2p TCP+QUIC |
| `SEED_PORT` | `4010` | `/void-seed/v1` |
| `SEED_BIND` | `0.0.0.0:$SEED_PORT` | seed bind |
| `PUBLIC_HOST` | empty | advertised host |
| `RUST_LOG` | `info` | logs |

```bash
git clone https://github.com/MarshalV/bootstrap_node
cd bootstrap_node
cargo run --release
```

Forward: **TCP 4001**, **UDP 4001**; **TCP 4010** only for other bootstrap nodes.

```
/ip4/<PUBLIC_IP>/tcp/4001/p2p/<PEER_ID>
```

The client does not use the node’s QUIC address in seed for dial (it breaks live TCP). One node can introduce two peers behind NAT (Hop + mailbox). For network resilience — **2–3 nodes in different networks**. One is not enough for routing anonymity.

---

## Specification, vectors, and harness

Wire rules for a second implementation are in [`spec/`](spec/README.md) (Russian): identity, Hello, session, attachments, envelope, discovery, rendezvous, seed, onion, groups. The catalog is bytes on the wire and what a node must do with them. It does not include the vault, the window, this client's listen port, or reconnect timers.

Three checks, none of them opens a window:

| Check | Command | What is green |
|-------|---------|----------------|
| Wire crates | `cargo test -p void-frames -p void-session -p void-envelope -p void-onion -p void-kad-rules` | Frames, Hello and ratchet, envelope, onion (no `kad`), DHT value check |
| Facade and vectors | `cargo test -p void-protocol --lib` | The re-export still type-checks, and the JSON in [`spec/vectors/`](spec/vectors/README.md) matches |
| Harness | `cargo test -p protocol-conformance` | Two `SecureSession`s exchange Hello and ratchet frames. `MailboxNode` applies the node rules for `Store` / `Query` |
| CI | [`.github/workflows/protocol.yml`](.github/workflows/protocol.yml) | Facade vectors and the harness on push and pull request |

The vector files are part of the repository. CI checks them out and compares; it does not regenerate them. `UPDATE_VECTORS=1` rewrites the JSON from `protocol/src/vectors.rs`. Set it only when the wire bytes are supposed to change. The secrets in those files are test seeds.

```powershell
$env:UPDATE_VECTORS='1'
cargo test -p void-protocol --lib vectors
Remove-Item Env:UPDATE_VECTORS
```

What the JSON pins is listed in [`spec/vectors/README.md`](spec/vectors/README.md): Hello v3 accepted and Hello with `ts` outside the 600-second window, ephemeral replay (a per-peer cache of the last 256 keys, not a signature check), four ratchet round-trips where `dh_pub` changes each turn, a tampered ratchet header that fails decrypt without moving state, envelope v3 seal/open, rejection of unsigned `v = 1` and of a v3 ciphertext relabeled as v2, a prekey whose `not_after` is already past, onion v2 on 1, 2, and 3 hops, and a hop secret that does not open the cell.

`protocol-conformance` depends only on `void-protocol`. The mailbox is in memory: `Query` answers the owner only, a batch is deleted before the reply, mail lives 7 days from accept time, one uploader is capped at 256 envelopes and 8 MiB in one box, the store window is 60 seconds / 600 requests / 600 envelopes / 48 MiB of `|ct|`, and a new box past 4096 is refused. An outer envelope that is not v3 is refused. The LAN client in `src/relay_mailbox.rs` uses the same quotas except the box ceiling, which is 256 there.

---

## 31 October 2026

What landed in this tree that day. Stages D and E are in the desktop and in `protocol/void-envelope`. The node this desktop talks to (`VOID_node`) still stores mail by recipient PeerId and does not serve one-time keys or contact queues. [`spec/`](spec/README.md) describes the protocol the crates implement; it is not a dump of that node’s binary.

### D. One-time prekeys

A new letter seals with two Diffie–Hellman shares when both keys exist: DH(ephemeral, signed prekey) and DH(ephemeral, one one-time key). The one-time id (16 bytes) is inside the ciphertext and in the cipher AAD. It is not a field the node can read. `seal_with_opk` refuses an all-zero id.

The recipient keeps a pool of 16 one-time keys (`offline_prekey.bin`) and publishes the signed prekey under `/void/prekey/<peer>` and the pool under `/void/opk/<peer>`. The same bundle goes out as `PrekeyPut`. In this crate, `PrekeyOffer` returns the signed prekey and one one-time key, then deletes that key. Opening the letter deletes the same key on the recipient; a second letter with that id does not open. The signed prekey still lives 7 days and rotates when less than 24 hours remain. The previous secret stays until its own `not_after`.

What actually ships against the running node:

- That node’s `PrekeyOffer` has no one-time key. The letter is then sealed to the signed prekey alone (one DH) and still uploaded.
- If the node has no sealable prekey at all, the letter is sealed at once to the X25519 key derived from the recipient PeerId (Ed25519 inside the PeerId, Edwards → Montgomery) and uploaded. The outbox does not wait for a prekey the node never returns.
- Opening tries, in order, the current signed-prekey secret, the previous one, the one-time keys still on disk, and that identity secret. Old letters sealed only to the identity key still open. A letter sealed only to a prekey that has already been dropped does not.

### E. Contact queues

The recipient creates `queue_id` (32 random bytes), a `write_token`, and a fresh Ed25519 owner. That owner is not the recipient’s PeerId. `CreateQueue` carries `queue_id`, the owner public key, the write token, an expiry, and the owner’s signature over `VOID_QUEUE_CREATE_V1`. The node index in `void-envelope` keys the box by `queue_id`.

The grant (`queue_id`, `write_token`, expiry) goes to the sender inside E2EE, before the chat message, and only after that contact’s Hello has bit `4` (`HELLO_CAP_QUEUES`). The sender’s `QueueStore` is the sealed envelope plus a random tail, exactly 64 KiB, so text and voice are the same length. A blob that does not fit is not queued. The write proof is SHA-256 of the token, the queue id, and the blob. `QueueQuery` is signed by the same owner key (`VOID_QUEUE_QUERY_V1`).

The queue lives 14 days. After 64 stores, or when less than 24 hours remain, the owner makes a new queue. The previous id is kept and still drained until its expiry. Secrets sit in the vault (`ContactQueueRecord`), not on the node. A Store log line from this crate is `queue=<8 hex> bucket=65536` and does not contain the recipient PeerId.

The running node does not decode `CreateQueue` or `QueueStore`. The client therefore always sends the PeerId `OfflineMailboxStore` as well. That copy is the one the recipient reads today. `QueueStore` is an extra, untracked copy, sent only when a grant for that contact is already in hand and TCP to the node is up.

### Also that day

- **Onion mailbox.** `Store` and `Query` can sit in a v2 cell with no outer sender. The hop `Ack` only means the cell was accepted. Handoff is the `Ack` that comes back on the reply path. One envelope per cell. While TCP to the node is already up, the client sends Store and Query on that connection instead.
- **Hop replay.** A v2 cell whose slot-0 key (BLAKE2b-128 of `eph` and the slot ciphertext) was peeled in the last 14 days is dropped and not forwarded.
- **Fetch.** The node answers `OfflineMailboxQuery { recipient }` when the TCP peer is that recipient. It does not implement `MailboxChallengeRequest`. The client asks on the open TCP, starting at connect and then about once a second. Zero `ts` / `nonce` / `sig` are left off the frame.
- **Live retry.** When a contact’s TCP appears, that peer’s pending sends go out on the next tick instead of sitting on the backoff (up to 300 s).

## 1 November 2026

### F. MLS for groups

Group text can use OpenMLS 0.9 (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, RustCrypto) in `protocol/void-mls`. The group id is the existing 32-hex id. The device snapshot (signer, group ids, OpenMLS storage) is a field of `vault.bin` and uses the same master key. Vault JSON plaintext may be up to 2 MiB.

Hello bit `8` is `HELLO_CAP_MLS`. A new group is MLS only when every selected member has already completed Hello with that bit. Otherwise the group stays pairwise. A pairwise group is not turned into an MLS group by a later sync. An MLS roster refuses a peer who has not announced the bit. The roster signature is unchanged for a pairwise group; an MLS roster signs one extra `0x01` byte. Invite links add `&mls=1` only for an MLS group.

The creator opens the group. A joiner sends `MlsKeyPackage`. The creator answers with Welcome to that joiner and Commit to the other members. Text is one `V1Packet::GroupMls` (at most 256 KiB) carrying the same ciphertext to each member on `/void/chat`. Voice and files stay on the pairwise fan-out. A retry seals a new generation; it does not replay the old ciphertext. A second process of the same Commit fails. After removal, the leaver's saved state does not open the next epoch. `group_sync` is still the ACL bootstrap, pairwise, before the member is in the tree.

The running node does not speak MLS. These frames are client-to-client on `/void/chat`.

### G. Header encryption, hybrid Hello, and checks

Hello bit `16` is `HELLO_CAP_HEADER_ENC`. When the peer announced it, the Double Ratchet header is sealed with its own key. The clear `dh_pub`, `pn`, and `n` are zeros. The sealed header is a random 12-byte nonce plus ChaCha20-Poly1305. Header keys come from the shared root before Alice's kickoff. A clear-header peer is unchanged. Offline mail with a sealed header uses tag `5`.

Hello bit `32` is `HELLO_CAP_PQ`. The first Hello carries an ML-KEM-768 encapsulation key. The reply carries the ciphertext. `transport_sig` stays the v3 binding, so an old client still verifies it. `pq_sig` is a second signature over that binding plus the KEM bytes. The session root mixes the KEM secret only when both sides have it. A PQ bit with a bad or missing ciphertext does not open a session. Prekey v3 signs the X25519 key and the encapsulation key (`VOID_PREKEY_SIG_V3`, DHT mark `0x03`). A hybrid offline letter keeps the same envelope fields and prefixes the ciphertext with `VQK1` and the KEM ciphertext. The node forwards that blob and checks the v3 prekey signature. The seed list in msg4 is accepted only after the server signs both PeerIds and a timestamp.

`fuzz/` has cargo-fuzz targets for `V1Packet`, the offline envelope, onion v2, and a seed frame. They are outside the workspace. libFuzzer was not run on this Windows machine. `spec/models/hello_query.pv` is a ProVerif model of the Hello binding, the first ratchet AAD, and the queue-query signature. ProVerif was not run on that file. It is a model of those messages, not a proof of the Rust.

Seed msg2 signs the server PeerId and a timestamp. msg3 signs the client PeerId, the timestamp, and the server PeerId. msg4 is a server confirmation over both PeerIds and a timestamp (`/void-seed/v1|both|…`). The client drops the peer list when that signature fails. The first seed body stays 32 random bytes, so the client PeerId is not in msg2. An old seed peer that still sends a bare `SeedResponse` does not finish the handshake.

This is source. The installed desktop and a node process built earlier do not contain F or G until they are rebuilt.

## Status

**Alpha.** Vault/journal format may still change.

### Done

- [x] P2P + Double Ratchet + Noise + Hello bound to identity
- [x] Kademlia `/void/kad/1.0.0` after Hop (`kad.bootstrap` ~30 s)
- [x] Relay v2 Hop (`ReservationReqAccepted` / UI `Hop OK`)
- [x] Vault, journal, outbox, one process per vault + single-instance in Tauri
- [x] Direct chats and groups (group voice with retry)
- [x] Offline mail via bootstrap (batches + deletion on the node)
- [x] Delivery and read receipt
- [x] Voice and files (E2EE `VfP1`/`VfC1`, empty files, cache, Downloads)
- [x] Tauri UI (push-snapshot) + optional egui
- [x] Tray / beacon; a second launch raises the same window
- [x] `VOID_ONION_v2` when every hop has a fresh descriptor (fixed 2/16/64 KiB cell, no sender in the last layer, weekly hop key, 14-day guard). v1 remains for a path that still has an old hop
- [x] `OnionDrop` only from advertised onion hops, inside only `Hello` / `Encrypted` / `Ack`
- [x] Offline envelope v3: sender signature, metadata inside ciphertext. Seal prefers a rotating prekey and one one-time key; the PeerId-derived key is used when the node has no sealable prekey, and it still opens old letters
- [x] Offline fetch matches the deployed node: `OfflineMailboxQuery { recipient }` on the direct TCP, about once a second from the moment that TCP is up
- [x] Contact queues (`HELLO_CAP_QUEUES`, 64 KiB `QueueStore`) in the client; the PeerId mailbox remains the copy that node serves
- [x] Offline-mail Query only for the mailbox owner; on the node at most 4096 mailboxes, TTL 7 days, quotas and `Store` rate limit; with bootstrap, the client does not accept `Store` from ordinary peers
- [x] Double Ratchet with a DH step on every speaker change. A session opens only after Hello bind v3 with the AAD bit, on a direct path and over onion. Header and both PeerIds are in AAD before the first frame
- [x] `Hello` freshness: `ts` (±10 min) and `nonce` in the signature. A `Hello` with `ts == 0` does not reset a live session
- [x] CBOR `V1Packet` after both sides announce `HELLO_CAP_CBOR` (Hello bit `2`, or `;cbor=1` on the node). Mixed peers stay on JSON. Field caps on `ct`, `ciphertext`, and Store size
- [x] Vault: Argon2id 64 MiB, AES-GCM with AAD (`VOIDKEY3`; old `VOIDKEY2` still opens)
- [x] Group roster has a creator-signed `version`. A replay of an older `group_sync` does not roll membership back. A message is stored only if the sender is in the roster
- [x] Kademlia `put` on the client and the node keeps only a signed unexpired prekey or a v3 mailbox
- [x] A hop forwards an onion cell only after Identify, with a forward rate limit, and does not log `next` or `src`
- [x] Wire catalog in [`spec/`](spec/README.md) and known-answer vectors in [`spec/vectors/`](spec/vectors/README.md) (`cargo test -p void-protocol --lib vectors`)
- [x] Conformance harness `protocol-conformance`: two `SecureSession`s and an in-memory mailbox with the node Query / TTL / quota rules. No Tauri or egui
- [x] `protocol/` split into `void-frames`, `void-session`, `void-envelope`, `void-onion`, `void-kad-rules`, and `void-mls`. `void-onion` builds without libp2p and without `kad`. `void-protocol` re-exports the old paths for this release
- [x] Group text uses OpenMLS when every member has announced Hello bit `8`. A pairwise group stays fan-out. Voice and files stay per member. The epoch snapshot is in the vault
- [x] Hello bit `16` seals the Double Ratchet header. Hello bit `32` mixes ML-KEM-768 into the session root, with v3 kept as `transport_sig` and v4 as `pq_sig`. Prekey v3 signs the encapsulation key. A letter sealed only to that prekey prefixes `ct` with `VQK1`
- [x] Seed msg4 is a server signature over both PeerIds and a timestamp. `fuzz/` holds the four cargo-fuzz targets. `spec/models/hello_query.pv` is the ProVerif model. Neither libFuzzer nor ProVerif was run here

### Optional / not default

- [ ] DCUtR, AutoNAT, UPnP — only `VOID_ENABLE_NAT=1`

### Protocol plan

The wire catalog, the vectors, and the harness are in the tree. See [Specification, vectors, and harness](#specification-vectors-and-harness). Frames, the session (including groups until a later `void-groups`), offline envelopes, onion cells, and the Kademlia value check are separate crates under `protocol/`. `void-protocol` re-exports them so `void_protocol::…` keeps working for this release, then that facade goes away. The desktop stays in `src/`, `frontend/`, and `src-tauri/`, and depends on the facade and on each wire crate. `protocol-conformance` depends only on the facade.

The code stays [MIT](./LICENSE). Specification text — CC BY 4.0.

Out of spec, as this client’s local choices: vault layout, Tauri and egui, listen TCP `:50001`, one TCP to bootstrap, reconnect and Hop timeouts. Changing vault `format_version` does not change bytes on the wire.

| Piece | Where |
|-------|--------|
| Identity through groups | [`spec/00-overview.md`](spec/00-overview.md) … [`spec/10-groups.md`](spec/10-groups.md) |
| Hello, ratchet, envelope, prekey, onion | [`spec/vectors/`](spec/vectors/README.md) |
| Envelope v3, no stable cleartext sender | client and [`spec/05-envelope.md`](spec/05-envelope.md); vectors `envelope_v3_roundtrip`, `envelope_v2_reject` |
| Two sessions and the dispatcher mailbox | [`protocol-conformance`](protocol-conformance) |

Still ahead, in source as well as in the binaries: drop the `void-protocol` facade after this release; replace `libp2p-identity::PeerId` inside `void-session` and `void-envelope`; a two-process dump of an onion Store; the contact-queue index on the node (today the recipient reads the PeerId mailbox); one-time keys actually returned by `PrekeyOffer`; ML-KEM on the letter that already uses a one-time key; a remove Commit sent by the member who is leaving; a vector for the skipped-key cap of 4096. `fuzz/` and `spec/models/hello_query.pv` are in the tree and have not been executed here. A test that is green only against the desktop program is a specification failure.

Reference dispatcher — [`MarshalV/bootstrap_node`](https://github.com/MarshalV/bootstrap_node). One dispatcher still sees the meeting. Onion does not cancel that until several independent nodes are on the path. A v2 cell has three size buckets. A path that still contains a v1 hop also shows the sender.

### Outside this plan

- [ ] Mobile builds
- [ ] Signed releases and reproducible builds
- [ ] External review of Hello + ratchet + envelope seal — against [`spec/`](spec/README.md) and [`spec/vectors/`](spec/vectors/README.md), not instead of them

---

## Security

Do **not** file vulnerabilities as a public issue. Write to the author privately.

The project has **not had an external audit**. Do not use VOID to protect people’s lives or freedom.

Practice in the code: E2EE only in chat; Hello bound to identity, with `ts`/`nonce`/`caps` in the v3 signature and a second v4 signature when the ML-KEM bytes are present; a `Hello` without `ts` does not reset a live session; ratchet header and PeerId in AAD, and that header sealed when Hello bit `16` is set; mailbox Query only for the owner and at most 4096 boxes on the node; offline mail sealed to a rotating prekey; group text in OpenMLS when every member announced bit `8`; group roster signed and monotonic; Kademlia refuses unsigned records; a hop forwards only after Identify. A v2 onion cell hides the sender from the exit; a v1 cell on a mixed path does not. Residual risks (IP at the node, PeerId, offline-mail recipient, Identify, onion-key gossip, a path shorter than three independent hops) — in [Privacy](#privacy-and-threat-model).

---

## License

[MIT](./LICENSE). No warranty.

---

<div align="center">

**Made with Rust 🦀 and a lot of `zeroize()`**

</div>
