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

**VOID** (Verified Open Independent Dispatcher) is an open delivery protocol and a Rust P2P app on top of it. Both layers live in this repository. The protocol is the stream rules and frames in `src/` (`protocol`, `crypto`, `network`, `onion`, offline envelope). The app is the desktop that runs those rules for a person. Live chat goes **peer to peer** over `libp2p`: directly on LAN, or through a **Circuit Relay Hop** on a bootstrap node when both sides are behind NAT. Text, voice, and files are encrypted with **Double Ratchet**. Identity is a `PeerId` from the local vault — no phone number, no email.

A bootstrap node is needed to **find** a peer, **reserve a Hop**, and **store offline envelopes**. It does not decrypt messages, but it **sees metadata**: IP, PeerId, who builds a circuit with whom, and for whom offline mail sits, when, and how large it is. Details: [Privacy and threat model](#privacy-and-threat-model).

The main desktop is **Tauri 2** (`frontend/` + `src-tauri/`). Optionally a native **egui** UI (`cargo run --release --features egui-ui`).

---

## Features

- **P2P chat** — `/void/chat/1.0.0` (request-response). Payload is E2EE (`V1Packet::Encrypted`), optionally wrapped in onion (`VOID_ONION_v2`, or v1 if a hop has no descriptor).
- **E2EE** — **Noise** on the transport, then `Hello` (X25519 + Ed25519 signature bound to `PeerId`, freshness `ts`/`nonce`), then **Double Ratchet** with a DH step on every speaker change; the header and both PeerIds go into AAD.
- **1-to-1 and groups** — groups with invite `void://group/…`, fan-out to each member (not MLS).
- **Voice** — record, preview, WAV over E2EE; in-chat player. Auto-accept, no “accept file” banner.
- **Files** — up to 512 MB, including empty (0-byte) files. Chunks (`VfC1`) and offer/accept (`VfP1`) go in E2EE `/void/chat`. `/void/file/1.0.0` is a fallback channel when the peer already has a live TCP connection.
- **Offline mail** — store-and-forward on bootstrap (`OfflineMailboxStore` / `Query` / `Deliver`). Envelope v3 is signed with the sender’s libp2p key; sender and type sit inside `ct`; unsigned envelopes are rejected. On the node only the recipient is visible. Only the recipient can fetch mail. TTL 7 days, per-uploader quotas and a store rate limit on the node.
- **Own DHT** — Kademlia `/void/kad/1.0.0`, not IPFS. Chat text is not written to the DHT.
- **NAT** — working path: **Relay v2 Hop** (`listen_on(…/p2p-circuit)` → `ReservationReqAccepted`). DCUtR / AutoNAT / UPnP are **off** (enable with `VOID_ENABLE_NAT=1`: a second dial to the node tears down TCP).
- **Client transport** — listen on **TCP :50001** only. One TCP to bootstrap; `/p2p/` is stripped on dial; the real PeerId is written to the vault after Identify. The client does not open QUIC to the node.
- **LAN** — mDNS (disable with `VOID_DISABLE_MDNS`).
- **Single process** — `void.instance.lock` + TCP port `50001`; in Tauri a second launch (shortcut while the window is in the tray) raises the running window (`tauri-plugin-single-instance`) instead of a second copy.
- **Vault** — nickname, keys, contacts, groups in `vault.bin`; master key in `void.key`. Journal — `chat_journal.bin`, undelivered — `outbox.bin`.
- **Delivery** — ○ / ✓ / ✓✓; read receipt when the chat is open.
- **Beacon** — closing the window hides to tray; the process stays up. UI header uses `Image_programm.png`.
- **Onion** — `VOID_ONION_v2` when every hop has a fresh descriptor, otherwise `VOID_ONION_v1`. 1 live node → 1 hop, 2 → both, 3+ → up to three. The live path is shown in settings. A v2 exit does not see the sender; one node or two hops still link the path — see [onion](#onion-void_onion_v2).

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
                             │ crate void-protocol
┌────────────────────────────▼────────────────────────────────┐
│  protocol/          frames, session, onion, offline mail    │
└─────────────────────────────────────────────────────────────┘
```

| Module | Role |
|--------|------|
| `src/network.rs` | Swarm, dial bootstrap, Hop, RR chat, mailbox, gossip |
| `src/bridge.rs` | Headless runtime for Tauri: snapshot push, not poll |
| `protocol/src/protocol.rs` | `V1Packet` (`Hello`, `Encrypted`, mailbox, onion, …) |
| `protocol/src/crypto.rs` | Handshake + Double Ratchet (DH step, header and PeerId in AAD) |
| `protocol/src/onion.rs` | Onion v2 when every hop has a descriptor, otherwise v1 |
| `protocol/src/offline_mail.rs` | Seal envelope to the recipient’s rotating prekey, or to the key derived from their PeerId if none is published |
| `protocol/src/kad_store.rs` | Kademlia `put`: signed unexpired prekey, or a v3 mailbox. Other keys are refused |
| `src/relay_mailbox.rs` | Local mailbox for LAN without bootstrap: the client stores neighbours’ mail and serves it to the owner on Query |
| `src/hello_replay.rs` | Cache of accepted `Hello` ephemeral keys (256 per peer). A `Hello` with `ts == 0` does not reset a live session |
| `src/vault.rs` / `paths.rs` | Vault, data directory, instance lock |
| `src/bootstrap.rs` | Seed merge: vault, env, HTTP, built-in list |
| `src/file_transfer.rs` / `src/voice.rs` | Files and voice |
| `protocol/src/group.rs` | Group roster, invite, creator-signed version |

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
6. Until Hop exists, mail to bootstrap does not hammer HOP streams (deferred until Ack or ~90 s).

Two VOID copies on one vault open two TCPs to the same node — both go `yamux Closed` immediately. Hence the instance lock, refuse if `:50001` is taken, and in Tauri a single window.

### Network stack (`libp2p`)

| Layer | Current |
|-------|---------|
| Client listen | TCP `0.0.0.0:50001`. **No** QUIC listen |
| Dial bootstrap | one TCP to `host/tcp/port`; QUIC to the node is filtered out |
| Multiplexer | Yamux (up to 512 streams on the client; Hop on the node is sensitive to RR spam) |
| Channel | Noise |
| Identify | `/void/v1`; bootstrap is recognized by `agent_version` `void-bootstrap-node…` |
| Chat | `/void/chat/1.0.0` |
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
| Undelivered | `outbox.bin` → `OfflineMailboxStore` on bootstrap (node Ack = handoff; node refusal — the letter stays in `outbox.bin`) |
| Offline mailbox | Query bootstrap after Hop; at most ~750 ms; remainder of a batch ~500 ms later |

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
| `Hello` | X25519 + identity signature. New clients sign bind v3: `ts`, `nonce`, and `caps` (±10 min). `caps` bit `1` puts the ratchet header in AAD. An onion Hello is accepted only as v3 with that bit set. A direct Hello with `ts == 0` can still open a session and does not reset one that is already live |
| `Encrypted` | Double Ratchet |
| `Ack` | RR reply / empty mailbox / node accepted the letter |
| `OfflineMailboxStore` / `Query` / `Deliver` | offline mail on bootstrap; `Query` runs only for own PeerId; empty `Deliver` in reply to `Store` is a refusal |
| `PrekeyPut` / `Get` / `Offer` | Rotating X25519 prekey: `{public_key, not_after, sig}`. The node stores a put only from the Noise peer who owns the PeerId, with a valid signature and `not_after` within 30 days. An offer is used for seal only when that signature and expiry check out. An unsolicited `Offer` is ignored |
| `BootstrapGossip` | seed exchange |
| `DialBack` | “dial me over circuit” |
| `Onion` / `OnionDrop` | `VOID_ONION_v1`. `OnionDrop` is accepted only from a bootstrap that advertised `;onion=` in its own Identify; inside — only `Hello` / `Encrypted` / `Ack`. The last layer still carries `src` |
| `Onion2` / `OnionDeliver` | `VOID_ONION_v2`. Fixed-size cell. The exit forwards an opaque body sealed to the recipient’s identity key. No `src`. Used only when every hop on the path has a fresh descriptor |

JSON RR: request up to 4 MiB, response up to 16 MiB (offline voice chunks).

### End-to-end encryption (`protocol/src/crypto.rs`)

| Stage | Algorithm |
|-------|-----------|
| Transport | **Noise** |
| Handshake | static + ephemeral **X25519** in `Hello`, **Ed25519** bound to `PeerId` |
| Ratchet | **Double Ratchet**: the initiator takes the first DH step right after `Hello`, then a new DH key on every speaker change; header (`dh_pub`, `pn`, `n`) and both PeerIds are AAD if both clients advertised this in `Hello.caps` |
| KDF | **HKDF-SHA256** |
| AEAD for chat / onion / offline `ct` | **ChaCha20-Poly1305** |
| Vault / journal / file cache | **AES-256-GCM** |
| File integrity | **BLAKE2b-512** (first 32 bytes) |
| Key memory | `zeroize` |
| Skipped keys | up to **4096** total, at most **1000** per header, TTL 1 h |

A direct session with an old client still works: no DH step, frames without AAD, `Hello` without `ts` under a v1 signature, and that Hello does not reset a live session. An onion Hello from an old client is refused until it signs v3 with `HELLO_CAP_HEADER_AAD`. **Update the node together with the client:** an old node on the onion path drops `ts`/`nonce`/`caps`, and a new `Hello` over onion will fail. Seed between an old and a new node will not complete either.

Offline envelope v3 (`protocol/src/offline_mail.rs`):

- `ct` — ChaCha20-Poly1305 to a key from X25519(ephemeral, recipient prekey — see [Prekey](#prekey)), HKDF with `eph` and that key;
- inside `ct` — sender, `sender_pk`, `message_id`, `kind`, body, and a signature of the sender’s libp2p key over those, the recipient, and `eph`; body is padded (power of two from 512 B to 4 KiB, then multiples of 4 KiB);
- outside, `sender` and `kind` are empty, `sender_pk` is zero, `message_id` is a hash of the recipient and the real id (the node can dedupe repeats but cannot link letters of different recipients);
- external id, recipient, and `eph` are cipher AAD: the node cannot rewrite the id or redirect the envelope;
- the recipient accepts `dm` / `group` only if inner `sender_id` matches the signature; `group_sync` is from the signer;
- v3 and v2 (signed, fields in the clear) are accepted; v1 (unsigned) is dropped. **Incompatible with old clients** — update every participant.

The node sees the recipient (mailbox slot), time, and size to bucket accuracy.

### Prekey

A new offline letter is sealed to the recipient’s **rotating X25519 prekey**, not to the long-lived chat static key. The prekey lives 7 days and is rotated when less than 24 hours remain. The previous secret is kept until its own `not_after`, then dropped. The client publishes it on the bootstrap (`PrekeyPut`) and in DHT `/void/prekey/<peer>`.

DHT value v2: `pk[32] || 0x02 || not_after[8] ||` owner signature. v1 (no expiry) still verifies and is not used for seal. The node accepts `PrekeyPut` only when the Noise peer is the claimed owner, the signature matches the identity key inside the PeerId, and `not_after` is in the future and at most 30 days out. An unsigned put is refused. `PrekeyOffer` is used only if the same signature and expiry check out, and only in answer to our own `PrekeyGet`.

If no sealable prekey comes back, the letter is sealed to the X25519 key **derived from the recipient PeerId** (Ed25519 inside the PeerId, Edwards → Montgomery, same as `crypto_sign_ed25519_pk_to_curve25519`). That key is never distributed. The recipient opens a letter with the current prekey secret, the previous one, and this identity secret, so mail sealed before the upgrade still opens.

Leaking the libp2p identity still opens letters that were sealed to it. Letters sealed only to a prekey that has already been dropped do not.

### Offline mail

The live path is **not DHT**, it is RR to bootstrap:

1. Recipient offline → their prekey, or the PeerId key if none is published → `OfflineMailboxStore`. The node replies `Ack` if it stored; empty `Deliver` is a quota, rate, or mailbox-ceiling refusal — the letter stays queued and will retry later.
2. Recipient online → `OfflineMailboxQuery`; the node returns a batch (`take_batch` ≤ 512 KiB plaintext) and **deletes** it from `relay_mailbox.bin`. Mail is given only to the recipient: the connection PeerId must match `recipient`.
3. The client fetches the rest with the next Query, with a pause (no immediate re-query: otherwise the same batch spins hundreds of times per second and chokes Hop).

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

### Groups (`protocol/src/group.rs`)

Member list in the vault + thread `group:<id>`. Message/file/voice is fan-out to each member (file and voice get a per-peer `transfer_id`). Group voice is queued and retried until the WAV is gone. Invite: `void://group/…`. The creator signs the roster: `version` plus a signature over `group_id ‖ version ‖ name ‖ members`. A snapshot is applied only when `version` is greater than the local one and the signature checks out. An unsigned sync from the creator is refused. Anyone else may only add or remove themselves, and that does not move `version`. `group_leave` — from the member or the creator, `group_delete` — creator only. A live or offline message is stored only when both we and the sender are in the roster. **Not MLS**: compromising a member reveals what they received.

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
| **Offline mail / prekey** | Store/query on `/void/chat`; delivery **only to the mailbox owner**, in batches with deletion (`take_batch`). `relay_mailbox.bin` is encrypted. At most 4096 mailboxes, TTL 7 days, per-uploader quotas, refusal via empty `Deliver`. `PrekeyPut` is stored only with the owner’s signature and an expiry within 30 days. Kademlia `put` keeps a signed unexpired prekey or a v3 mailbox and drops anything else |
| **VOID-SEED** | `/void-seed/v1` on a separate TCP — list exchange **between nodes** |
| **Onion hop** | Identify `void-bootstrap-node/…;onion=<pk>;osig=…;epoch=…;until=…;op=…;osig2=…`. Unwrap v2 (fixed cell) or v1 (JSON) and forward only after the next hop’s Identify. The hop key rotates weekly; the previous secret lasts one more day. `next` is a PeerId. Forward is limited to 600/min per previous hop and 6000/min overall. Logs do not record `next` or `src` |

Live `V1Packet::Encrypted` is **not** forwarded as a chat server. Circuit and mailbox are separate paths. Onion is another: the node sees the next hop, not plaintext.

#### Node libp2p

| Component | Setup |
|-----------|-------|
| Transports | TCP + QUIC, `LISTEN_PORT` (4001) |
| Identify | `/void/v1`, `void-bootstrap-node/…` (+ `;onion=` if built with onion) |
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
- [x] Offline envelope v3: sender signature, metadata inside ciphertext. Seal goes to a rotating prekey; the PeerId-derived key remains the fallback
- [x] Offline-mail Query only for the mailbox owner; on the node at most 4096 mailboxes, TTL 7 days, quotas and `Store` rate limit; with bootstrap, the client does not accept `Store` from ordinary peers
- [x] Double Ratchet with a DH step on every speaker change; frame header and both PeerIds in AAD if both clients advertised it in `Hello.caps`. New clients sign `caps` in Hello bind v3; an onion Hello without that flag is refused
- [x] `Hello` freshness: `ts` (±10 min) and `nonce` in the signature. A `Hello` with `ts == 0` does not reset a live session
- [x] Vault: Argon2id 64 MiB, AES-GCM with AAD (`VOIDKEY3`; old `VOIDKEY2` still opens)
- [x] Group roster has a creator-signed `version`. A replay of an older `group_sync` does not roll membership back. A message is stored only if the sender is in the roster
- [x] Kademlia `put` on the client and the node keeps only a signed unexpired prekey or a v3 mailbox
- [x] A hop forwards an onion cell only after Identify, with a forward rate limit, and does not log `next` or `src`

### Optional / not default

- [ ] DCUtR, AutoNAT, UPnP — only `VOID_ENABLE_NAT=1`

### Protocol plan

The wire protocol lives in `protocol/` (crate `void-protocol`): frames, the session, offline envelopes, onion cells, groups, and the Kademlia record check. The desktop stays in `src/`, `frontend/`, and `src-tauri/`, and depends on that crate. Tauri is still one consumer. Next work is a specification and test vectors, so another implementation can speak the same streams without this repository as a UI sample.

The code stays [MIT](./LICENSE). Specification text — CC BY 4.0.

Only what a second node needs to interoperate goes into the spec. Out of spec, as this client’s local choices: vault layout, Tauri and egui, listen TCP `:50001`, one TCP to bootstrap, reconnect and Hop timeouts. Streams have their own version: changing vault `format_version` does not change bytes on the wire.

Fixed order: specification, then crates, then vectors, then envelope form. Vectors are written against the crates from task 2.

#### 1. Normative specification

Separate already implemented rules from this client’s behaviour. One dispatcher sees the meeting; onion does not cancel that until several independent nodes are on the path. Kademlia is a discovery index; the spec forbids chat text in the DHT rather than leaving it as a client comment.

| Document | What it pins |
|----------|----------------|
| Identity | PeerId as the participant key, not an account |
| Hello | Signature that binds session keys to both PeerIds |
| Session | Double Ratchet frames inside `/void/chat/1.0.0` |
| Attachments | Files and voice (`VfP1` / `VfC1`) inside that session; `/void/file/1.0.0` is a fallback |
| Envelope | `OfflineMailboxStore` / `Query` / `Deliver`, prekey; what the dispatcher stores and still sees (recipient, time, size bucket — see task 4) |
| Discovery | `/void/kad/1.0.0` without chat text |
| Meeting | Which Hop reservation a peer needs from the dispatcher |
| Seed | `/void-seed/v1` between dispatchers |
| Onion | `VOID_ONION_v2` when every hop has a descriptor, else v1: 1 / 2 / 3 hops, what each hop sees |

Reference dispatcher — [`MarshalV/bootstrap_node`](https://github.com/MarshalV/bootstrap_node). Seed and mailbox are described here even if the node code lives in that repository. The specification text has no internal types of the desktop shell.

#### 2. Libraries without a UI

`protocol/` is the first crate the desktop depends on. Splitting it into frames, session, envelope, and onion, then the harness from task 3, is still ahead.

| Crate | Contents |
|-------|----------|
| Frames | Frame types and length limits |
| Session | Signed Hello and Double Ratchet |
| Envelope | Seal and open of offline mail |
| Onion | Wrap and unwrap `VOID_ONION_v2`, and v1 when a hop has no descriptor |

The Tauri shell is not a deliverable of this work.

#### 3. Conformance tests

Machine-readable vectors so the protocol can be implemented without reading the UI:

- Hello accepted and Hello rejected
- Skipped ratchet keys within the current cap of **4096**
- Seal and open of an envelope
- Onion on 1, 2, and 3 hops

The harness is two processes, no GUI window. A test that is green only against the desktop program is a specification failure.

#### 4. Envelope without a stable cleartext `sender`

Status: done in the client (envelope v3) — `sender` and `kind` inside `ct`, external id opaque, size padded. Still to write this into the specification.

Before v3 the dispatcher stored opaque `ct` and saw stable `sender`, `recipient`, and `kind`. New envelope form: the node still expires the record and hands it to the recipient, but without a stable sender in the clear.

The spec still states what the route still shows: size bucket, time, and the recipient on the last hop. Calling the form anonymity is not allowed: one dispatcher sees the meeting; a v2 cell has three size buckets; an observer of the whole path links entry and exit. A path that still contains a v1 hop also shows the sender.

This form gets its own vectors.

### Outside this plan

- [ ] Group ratchet. Groups today are fan-out of pairwise sessions, with no group forward secrecy. The spec will state that limit. Next step, if any, is OpenMLS or an explicit refusal — not a second homemade ratchet
- [ ] Mobile builds
- [ ] Signed releases and reproducible builds
- [ ] External review of Hello + ratchet + envelope seal — against the finished spec and vectors, not instead of them

---

## Security

Do **not** file vulnerabilities as a public issue. Write to the author privately.

The project has **not had an external audit**. Do not use VOID to protect people’s lives or freedom.

Practice in the code: E2EE only in chat; Hello bound to identity, with `ts`/`nonce`/`caps` in the v3 signature; a `Hello` without `ts` does not reset a live session; ratchet header and PeerId in AAD; mailbox Query only for the owner and at most 4096 boxes on the node; offline mail sealed to a rotating prekey; group roster signed and monotonic; Kademlia refuses unsigned records; a hop forwards only after Identify. A v2 onion cell hides the sender from the exit; a v1 cell on a mixed path does not. Residual risks (IP at the node, PeerId, offline-mail recipient, Identify, onion-key gossip, a path shorter than three independent hops) — in [Privacy](#privacy-and-threat-model).

---

## License

[MIT](./LICENSE). No warranty.

---

<div align="center">

**Made with Rust 🦀 and a lot of `zeroize()`**

</div>
