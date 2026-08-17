<div align="center">

<img src="static/icon.png" alt="VOID Logo" width="160" />

# VOID — P2P Messenger

**Децентрализованный, сквозно-шифрованный мессенджер.**
Без регистрации и облачного аккаунта. Содержимое чата читают только собеседники.
Поиск в сети и прохождение NAT идут через публичные bootstrap/relay-узлы — это не сервер чата, но и не анонимайзер.

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

## Что это

**VOID** (Verified Open Independent Dispatcher) — P2P-мессенджер на Rust. Живой чат идёт **между пирами** по `libp2p`: напрямую в LAN или через **Circuit Relay Hop** на bootstrap-ноде, если оба за NAT. Текст, голос и файлы шифруются **Double Ratchet**. Идентичность — `PeerId` из локального vault, без телефона и почты.

Bootstrap-нода нужна, чтобы **найти** собеседника, **зарезервировать Hop** и **хранить офлайн-конверты**. Она не расшифровывает сообщения, но **видит метаданные**: IP, PeerId, кто с кем строит circuit, поля офлайн-почты. Подробнее — [Приватность](#приватность-и-модель-угроз).

Основной десктоп — **Tauri 2** (`frontend/` + `src-tauri/`). Опционально — нативный UI на **egui** (`cargo run --release --features egui-ui`).

---

## Ключевые возможности

- **P2P-чат** — `/void/chat/1.0.0` (request-response). Полезная нагрузка — E2EE (`V1Packet::Encrypted`), поверх — опциональный onion (`VOID_ONION_v1`).
- **E2EE** — транспорт **Noise**, затем `Hello` (X25519 + подпись Ed25519 к `PeerId`), далее **Double Ratchet**.
- **1-на-1 и группы** — группы с invite `void://group/…`, рассылка каждому участнику (не MLS).
- **Голос** — запись, превью, WAV по E2EE; в чате плеер. Автоприём, без баннера «принять файл».
- **Файлы** — до 512 МБ. Чанки по E2EE-чату; оффер (имя, размер, хэш) по `/void/file/1.0.0`.
- **Офлайн-почта** — store-and-forward на bootstrap (`OfflineMailboxStore` / `Query` / `Deliver`). `ct` непрозрачен; `sender` / `recipient` / `kind` на ноде открыты. TTL 7 суток.
- **Свой DHT** — Kademlia `/void/kad/1.0.0`, не IPFS. Текст чата в DHT не пишется.
- **NAT** — рабочий путь: **Relay v2 Hop** (`listen_on(…/p2p-circuit)` → `ReservationReqAccepted`). DCUtR / AutoNAT / UPnP **выключены** (включаются `VOID_ENABLE_NAT=1`: второй dial к ноде рвёт TCP).
- **Транспорт клиента** — listen только **TCP :50001**. К bootstrap — один TCP; `/p2p/` на dial снимается, реальный PeerId пишется в vault после Identify. QUIC к ноде клиент не поднимает.
- **LAN** — mDNS (отключается `VOID_DISABLE_MDNS`).
- **Один процесс на vault** — `void.instance.lock`; вторая копия с тем же ключом рвёт yamux на ноде.
- **Vault** — ник, ключи, контакты, группы в `vault.bin`; мастер-ключ в `void.key`. Журнал — `chat_journal.bin`, недоставленное — `outbox.bin`.
- **Доставка** — ○ / ✓ / ✓✓; read receipt при открытом чате.
- **Beacon** — закрытие окна прячет в трей, процесс живёт.

---

## Архитектура

### Слои приложения

```
┌─────────────────────────────────────────────────────────────┐
│  frontend/          HTML / CSS / JS (webview)               │
│  события: void://snapshot (~120 мс), void://message, …      │
└────────────────────────────┬────────────────────────────────┘
                             │ Tauri commands
┌────────────────────────────▼────────────────────────────────┐
│  src-tauri/         окно, трей, emit в JS                   │
└────────────────────────────┬────────────────────────────────┘
                             │ VoidRuntime
┌────────────────────────────▼────────────────────────────────┐
│  src/bridge.rs      vault, журнал, outbox, SnapshotDto      │
│                     UICommand ──►  NetworkEvent ◄── swarm   │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│  src/network.rs     libp2p Swarm (ChatBehaviour)            │
│  src/onion.rs       VOID_ONION_v1                           │
│  src/crypto.rs      Double Ratchet                          │
└─────────────────────────────────────────────────────────────┘
```

| Модуль | Роль |
|--------|------|
| `src/network.rs` | Swarm, dial bootstrap, Hop, RR-чат, mailbox, gossip |
| `src/bridge.rs` | Головаless runtime для Tauri: snapshot push, не poll |
| `src/protocol.rs` | `V1Packet` (`Hello`, `Encrypted`, mailbox, onion, …) |
| `src/crypto.rs` | Handshake + Double Ratchet |
| `src/onion.rs` | Слои onion на живых bootstrap с `;onion=` в Identify |
| `src/offline_mail.rs` | Seal конверта на prekey получателя |
| `src/relay_mailbox.rs` | Локальный ящик, если этот клиент сам отвечает на Query |
| `src/vault.rs` / `paths.rs` | Vault, каталог данных, instance lock |
| `src/bootstrap.rs` | Склейка seed: vault, env, HTTP, вшитый список |
| `src/file_transfer.rs` / `voice.rs` / `group.rs` | Файлы, голос, группы |

UI **не** крутит `get_snapshot` по таймеру. Состояние уходит событием `void://snapshot` (флашер ~120 мс, `revision` монотонный).

### Как два клиента встречаются

```
Alice                         Bootstrap                         Bob
  │ TCP :4001 (без проверки /p2p/)  │
  │ Identify /void/v1               │
  │ vault: реальный PeerId ноды     │
  │ listen …/p2p/<node>/p2p-circuit │
  │ ◄── ReservationReqAccepted ──── │
  │          «relay Hop OK»         │
  │                                 │
  │  dial …/p2p-circuit/p2p/<Bob>   │
  │  (после Hop; LAN/mDNS отдельно) │
  │                                 │
  │ Hello → Double Ratchet          │
  │ Encrypted  (опц. Onion-обёртка) │
```

1. Один TCP на `IP:4001`. `/p2p/` с dial снимается (`DialOpts::unknown_peer_id()`), иначе старый PeerId в vault рвёт Noise за 1 мс.
2. После Identify клиент переписывает bootstrap в vault на **живой** PeerId ноды.
3. Hop: `listen_on(/ip4/…/tcp/4001/p2p/<node>/p2p-circuit)`. В статусе **relay Hop OK** только после `ReservationReqAccepted` (не после `listen_on Ok`).
4. Контакты набираются **через circuit**, когда Hop есть. Без Hop UI показывает `нет Hop (NAT закрыт)` — чат в LAN при этом может уже работать.
5. `DialBack` просит собеседника набрать нас по circuit (асимметрия NAT).

Две копии VOID с одним vault дают два TCP на одну ноду — оба сразу `yamux Closed`. Поэтому instance lock и отказ, если `:50001` занят (без fallback-порта).

### Сетевой стек (`libp2p`)

| Слой | Как сейчас |
|------|------------|
| Listen клиента | TCP `0.0.0.0:50001`. QUIC listen **нет** |
| Dial bootstrap | один TCP на `host/tcp/port`; QUIC к ноде отфильтрован |
| Мультиплексор | Yamux (до 512 стримов на клиенте; на ноде Hop чувствителен к спаму RR) |
| Канал | Noise |
| Identify | `/void/v1`; bootstrap узнаётся по `agent_version` `void-bootstrap-node…` |
| Чат | `/void/chat/1.0.0` |
| Файлы (оффер) | `/void/file/1.0.0` |
| Чанки файла/голоса | E2EE-кадры внутри `/void/chat` |
| DHT | `/void/kad/1.0.0`, `Mode::Server`, k-bucket **Manual** (адреса после живого TCP) |
| Discovery | mDNS + Kademlia + список bootstrap |
| Relay | клиент: `relay::client`; Hop = `ReservationReqAccepted` |
| DCUtR / AutoNAT / UPnP | `Toggle::off`, пока нет `VOID_ENABLE_NAT=1` |

Выделенного сервера переписки нет. Relay таскает непрозрачные байты circuit. Офлайн-конверты **лежат на ноде** до выдачи (`take_batch`) или TTL.

Kademlia `bootstrap()` / `start_providing` — **после** Identify, не в момент первого TCP (иначе второй dial убивает сессию).

#### Надёжность

| Механизм | Поведение |
|----------|-----------|
| Dial bootstrap | один endpoint (`host/tcp/port`), cooldown, без параллельного QUIC |
| Автореконнект контакта | тик ~5 с, backoff 2 → 5 → 15 → 60 с |
| Hop retry | пока нет Ack: повтор listen ~3–12 с, не чаще (лишние Reserve забивают стримы ноды) |
| KAD | periodic bootstrap 5 мин, после Identify |
| E2EE Hello | при `ConnectionEstablished` с контактом (не с bootstrap) |
| Ретрай исходящих | `RESEND_GRACE` 1 с, экспоненциально до 300 с |
| Недоставленное | `outbox.bin` → `OfflineMailboxStore` на bootstrap (Ack ноды = handoff) |
| Офлайн-ящик | Query к bootstrap, не чаще ~750 мс; остаток порции — через ~500 мс, не в tight loop |

### Поиск собеседника

Нужны **bootstrap multiaddr** с `/p2p/<PeerId>` в vault (после первого успешного Identify PeerId ноды подставляется сам). Референс ноды: [`MarshalV/bootstrap_node`](https://github.com/MarshalV/bootstrap_node).

Источники (склеиваются, дедуп):

1. Вшитые (`BUILTIN_VOID_BOOTSTRAP` / `VOID_BUILTIN_BOOTSTRAP`).
2. HTTP(S) список (`VOID_BOOTSTRAP_URL` / `VOID_BOOTSTRAP_PUBLIC_LIST_URL`), ~256 KiB. Опционально `VOID_BOOTSTRAP_TRUSTED_HOSTS`, pin `VOID_BOOTSTRAP_TLS_LEAF_SHA256`.
3. `VOID_BOOTSTRAP` — multiaddr через запятую.
4. Разовый импорт `void-bootstrap.txt` рядом с бинарём → vault. Опционально Ed25519 (`VOID_BOOTSTRAP_SIGNING_PUB_HEX`).
5. UI: настройки bootstrap.

Клиенты ещё **гоняют** публичные seed друг другу (`BootstrapGossip`, до 32 адресов).

```powershell
$env:VOID_BOOTSTRAP = "/ip4/147.78.64.22/tcp/4001/p2p/12D3KooW..."
```

В поле подключения: `multiaddr`, `IP` или `IP:PORT`. Для bootstrap в списке seed обязателен суффикс `/p2p/<PeerId>` (после коннекта он должен совпасть с Identify ноды).

### Протокол `/void/chat/1.0.0`

| Пакет | Назначение |
|-------|------------|
| `Hello` | X25519 + подпись identity |
| `Encrypted` | Double Ratchet |
| `Ack` | RR-ответ / пустой ящик |
| `OfflineMailboxStore` / `Query` / `Deliver` | офлайн-почта на bootstrap |
| `PrekeyPut` / `Get` / `Offer` | X25519 prekey для seal без живого Hello |
| `BootstrapGossip` | обмен seed |
| `DialBack` | «набери меня по circuit» |
| `Onion` / `OnionDrop` | слои `VOID_ONION_v1` |

JSON RR: запрос до 4 МиБ, ответ до 16 МиБ (голосовые офлайн-чанки).

### Сквозное шифрование (`src/crypto.rs`)

| Этап | Алгоритм |
|------|----------|
| Транспорт | **Noise** |
| Handshake | статический + эфемерный **X25519** в `Hello`, **Ed25519** к `PeerId` |
| Ratchet | **Double Ratchet** |
| KDF | **HKDF-SHA256** |
| AEAD чата / onion / офлайн `ct` | **ChaCha20-Poly1305** |
| Vault / журнал / кэш файлов | **AES-256-GCM** |
| Целостность файла | **BLAKE2b-512** (первые 32 байта) |
| Память ключей | `zeroize` |
| Skipped keys | до **4096** |

Офлайн-конверт: `ct` на prekey получателя. На ноде открыты `sender`, `kind`, `message_id`.

### Офлайн-почта

Живой путь — **не DHT**, а RR к bootstrap:

1. Получатель офлайн → `PrekeyGet` → `OfflineMailboxStore`.
2. Получатель online → `OfflineMailboxQuery`; нода отдаёт порцию (`take_batch` ≤ 512 КиБ plaintext) и **удаляет** её из `relay_mailbox.bin`.
3. Клиент забирает остаток следующим Query, с паузой (без немедленного ре-query: иначе тот же batch крутится сотни раз в секунду и душит Hop).

Клиент сам может отвечать на Query (локальный `relay_mailbox.bin`) — для пиров, которые ошибочно стучатся не в bootstrap.

### Anonymous routing (`VOID_ONION_v1`)

Слой **поверх** libp2p и E2EE. Ключ hop'а — `onion=<64 hex>` в Identify `agent_version` ноды.

```
Alice → Node A → [Node B → Node C] → Bob
```

| Живые ноды с onion-ключом | Цепочка |
|---------------------------|---------|
| 1 | один hop: нода после unwrap видит пару Alice↔Bob |
| 2 | оба hop'а |
| 3+ | до трёх случайных; entry не видит Bob, exit не видит IP Alice |

Старые ноды без `;onion=` в цепочку не входят — чат идёт circuit / прямой RR. Это не mixnet и не защита от глобального наблюдателя. DCUtR (если включён) может открыть прямой канал и снова связать IP.

### Файлы (`src/file_transfer.rs`)

| Параметр | Значение |
|----------|----------|
| Чанк | 32 КБ |
| Макс. размер | 512 МБ |
| Кэш | `%APPDATA%\VOID\files` (и аналоги) — AES-256-GCM, `*.vfc` |
| Ключ кэша | HKDF-SHA256 от мастер-ключа (`VOID_FILE_CACHE_v1`) |
| «Скачать» | копия в `Загрузки/VOID Messenger/` |
| Удаление из чата | только кэш |
| Через circuit | ~64 КБ/с |

После `Accept` чанки идут по E2EE `/void/chat`. По `/void/file` — `Offer` / `Accept` / `Reject` / `Cancel` / `Ack` (имя файла на этом слое видит тот, кто терминирует соединение).

### Голосовые (`src/voice.rs`)

WAV mono 48 kHz 16-bit PCM, до 5 мин. Запись — дочерний процесс `--voice-record` (`cpal`). В чат — `VoiceMeta`; WAV как файл с автоприёмом. Офлайн: чанки `voice_chunk` через тот же mailbox. Метаданные по возможности снимаются (`metadata_strip`).

### Группы (`src/group.rs`)

Список участников в vault + тред `group:<id>`. Сообщение/файл/голос — fan-out каждому (у файла свой `transfer_id` на пира). Invite: `void://group/…`. **Не MLS**: компрометация участника раскрывает то, что он получил.

### Локальное хранилище

Каталог (переопределяется `VOID_DATA_DIR`):

| ОС | Путь |
|----|------|
| Windows | `%APPDATA%\VOID` |
| Linux | `~/.local/share/VOID` |
| macOS | `~/Library/Application Support/VOID` |

| Файл / папка | Содержимое | Защита |
|--------------|------------|--------|
| `void.key` | Обёрнутый мастер-ключ (`VOIDKEY2`) | Пароль + Argon2id + AES-GCM |
| `vault.bin` | Ник, ключи, контакты, группы, bootstrap | AES-256-GCM |
| `chat_journal.bin` | Переписки | AES-256-GCM |
| `outbox.bin` | Недоставленное | AES-256-GCM |
| `files/` | Кэш вложений `*.vfc` | AES-256-GCM |
| `voice/` | WAV | каталог данных |
| `void.pwd` | «Запомнить пароль» | Windows: Credential Manager + файл; иначе файл |
| `void.instance.lock` | Один процесс на vault | эксклюзивный open |
| `relay_mailbox.bin` | Локальный ящик (если этот клиент — mailbox) | на диске |

> Никогда не отдавайте пароль vault вместе с `void.key` и `vault.bin`.

---

## Приватность и модель угроз

VOID **скрывает содержимое** от сети и от bootstrap. VOID **не скрывает**, что вы в сети и с какого IP подключились к ноде.

Типичный маршрут за NAT — один Hop (или LAN):

```
Alice ──E2EE──► Relay/Bootstrap ──► Bob
```

Relay не видит plaintext, но **может** сопоставить IP↔PeerId, пару circuit `src→dst`, объём/время, офлайн `sender`/`recipient`/`kind`.

| Наблюдатель | Текст / файлы / голос | IP отправителя | Кто вы |
|-------------|------------------------|----------------|--------|
| Собеседник | Да | Да, если канал прямой (LAN). Через один relay — обычно нет | PeerId + ник |
| Владелец bootstrap | Нет | **Да** | PeerId, circuit, mailbox-метаданные |
| Другой пир в DHT | Нет | Нет (кроме mDNS в LAN) | иногда publisher prekey |

Стабильный идентификатор — **PeerId** (пока живёт vault). Это **псевдонимный E2EE**, не Tor. Не используйте VOID, если модель угроз — «нода не должна знать, кто кому писал».

Одна нода для текущего VOID — нормальный режим (discovery, Hop, mailbox). Анонимности маршрутизации она не даёт — см. [onion](#anonymous-routing-void_onion_v1).

---

## Стек

- **Язык:** Rust 2021
- **Сеть:** libp2p 0.56
- **Десктоп:** Tauri 2 + HTML/JS (`frontend/`); опционально egui 0.29 (`egui-ui`)
- **Аудио:** cpal + hound; WinMM fallback на Windows
- **Крипто:** x25519-dalek, chacha20poly1305, aes-gcm, argon2, hkdf, blake2, zeroize

Tauri-пакет (`src-tauri`) подключает `p2p-messenger` с `default-features = false` — без egui.

---

## Установка и запуск

Нужен **Rust** ≥ 1.77.2 (`stable`) и [Tauri CLI](https://v2.tauri.app/start/prerequisites/).

### Tauri (основной клиент)

```bash
git clone https://github.com/MarshalV/p2p-messenger.git
cd p2p-messenger
cargo tauri dev
# релиз (MSI/NSIS/deb/dmg):
cargo tauri build
```

Скрипты кладут установщики в корневой `target/`: `build.bat` (Windows, перед линковкой гасит запущенный `app.exe` / `VOID-P2P-Messenger.exe`), `./build.sh` (Linux), `./build_mac.sh` (macOS).

На одном vault — **одна** копия процесса. Вторая не стартует (`void.instance.lock` / порт 50001).

### egui (опционально)

```bash
cargo run --release --features egui-ui
```

На Linux для egui могут понадобиться `libxcb`, `libxkbcommon`, `libwayland-dev`.

При первом запуске задаёте пароль vault. Ник вида `User_1A2B` можно сменить в настройках.

### Подключение

1. Свой Peer ID — в настройках.
2. Контакт — по Peer ID (не голый IP без `/p2p/<PeerId>`).
3. Bootstrap в списке seed; в статусе должно быть `bootstrap 1/N` и после резервации — **relay Hop OK**.

---

## Конфигурация клиента

| Переменная | Назначение |
|------------|-----------|
| `VOID_DATA_DIR` | Каталог данных вместо `%APPDATA%\VOID` |
| `VOID_BOOTSTRAP` | multiaddr через запятую |
| `VOID_BOOTSTRAP_URL` | URL текстового списка seed |
| `VOID_BOOTSTRAP_PUBLIC_LIST_URL` | Публичный URL из сборки |
| `VOID_SKIP_PUBLIC_BOOTSTRAP_LIST` | Не грузить вшитый публичный список |
| `VOID_BOOTSTRAP_TRUSTED_HOSTS` | Разрешённые хосты для URL-списка |
| `VOID_BOOTSTRAP_TLS_LEAF_SHA256` | Pin SHA-256 DER листа HTTPS |
| `VOID_BOOTSTRAP_SIGNING_PUB_HEX` | Ed25519 для подписи списка |
| `VOID_BOOTSTRAP_URL_SIG_HEX` | Подпись тела URL-списка |
| `VOID_DISABLE_MDNS` | Выключить LAN-discovery |
| `VOID_ENABLE_NAT` | `1` — включить DCUtR, AutoNAT, UPnP (по умолчанию выкл.) |
| `VOID_APPLY_FIREWALL_RULE` | Разрешить правку файрвола (Windows/macOS) |
| `VOID_SKIP_SUBNETS` | Доп. CIDR «мусорных» listen-адресов |
| `VOID_BUILTIN_BOOTSTRAP` | Вшить seed при сборке |
| `RUST_LOG` | По умолчанию **warn**; `void_net=debug` — адреса в логах |

Инвентаризация рисков: [`SECURITY_REVISION.md`](./SECURITY_REVISION.md).

---

## Развёртывание своей инфраструктуры

Собственные bootstrap/relay ускоряют поиск и NAT.

### Референс: `void-bootstrap-node`

> 🔗 **[github.com/MarshalV/bootstrap_node](https://github.com/MarshalV/bootstrap_node)**

| Роль | Что делает |
|------|-----------|
| **Kademlia Server** | Вход в `/void/kad/1.0.0` |
| **Circuit Relay v2** | Hop для клиентов за NAT; непрозрачные байты circuit |
| **Офлайн-почта / prekey** | Store/query на `/void/chat`; выдача **порциями с удалением** (`take_batch`) |
| **VOID-SEED** | `/void-seed/v1` на отдельном TCP — обмен списками **между нодами** |
| **Onion hop** | Identify `void-bootstrap-node/…;onion=<pk>` — unwrap и forward |

Живой `V1Packet::Encrypted` нода **не форвардит** как сервер чата. Circuit и mailbox — отдельные пути. Onion — ещё один: нода видит следующий hop, не plaintext.

#### Libp2p ноды

| Компонент | Настройка |
|-----------|-----------|
| Транспорты | TCP + QUIC, `LISTEN_PORT` (4001) |
| Identify | `/void/v1`, `void-bootstrap-node/…` (+ `;onion=` если сборка с onion) |
| Kademlia | `/void/kad/1.0.0`, **Mode::Server** |
| Relay | Default + лимиты под NAT |
| Логи | `RUST_LOG` по умолчанию **info** (IP в `endpoint`) |

Клиенту в vault нужен **актуальный** `/p2p/<PeerId>` этой ноды (баннер при старте процесса). Старый ключ ноды + старый `/p2p/` в клиенте = TCP 1 мс и тишина.

#### Протокол `/void-seed/v1`

Обмен списками нод (не клиентский чат): X25519 PFS, HKDF-SHA-512, ChaCha20-Poly1305, Ed25519 той же пары, что libp2p `PeerId`. Сервер пишет фактический IP TCP в `known_nodes.json`.

#### Состояние ноды

| Файл | Что | Делиться |
|------|-----|----------|
| `bootstrap_peer.key` | Идентичность ноды | **нет** |
| `known_nodes.json` | Другие bootstrap | да (публичные адреса) |
| `relay_mailbox.bin` | Офлайн-конверты | **нет** |

#### Переменные ноды

| Переменная | По умолчанию | Назначение |
|-----------|-------------|-----------|
| `LISTEN_PORT` | `4001` | libp2p TCP+QUIC |
| `SEED_PORT` | `4010` | `/void-seed/v1` |
| `SEED_BIND` | `0.0.0.0:$SEED_PORT` | bind seed |
| `PUBLIC_HOST` | пусто | рекламируемый хост |
| `RUST_LOG` | `info` | логи |

```bash
git clone https://github.com/MarshalV/bootstrap_node
cd bootstrap_node
cargo run --release
```

Проброс: **TCP 4001**, **UDP 4001**; **TCP 4010** только для других bootstrap-нод.

```
/ip4/<ПУБЛИЧНЫЙ_IP>/tcp/4001/p2p/<PEER_ID>
```

QUIC-адрес ноды клиент в seed для dial не использует (ломает живой TCP). Одна нода сводит двух за NAT (Hop + mailbox). Для устойчивости сети — **2–3 ноды в разных сетях**. Для анонимности маршрутизации одной мало.

---

## Статус

**Alpha.** Формат vault/журнала ещё может меняться.

### Есть

- [x] P2P + Double Ratchet + Noise + Hello к identity
- [x] Kademlia `/void/kad/1.0.0` после Identify
- [x] Relay v2 Hop (`ReservationReqAccepted`)
- [x] Vault, журнал, outbox, один процесс на vault
- [x] Личные чаты и группы
- [x] Офлайн-почта через bootstrap (порции + удаление на ноде)
- [x] Доставка и read receipt
- [x] Голос и файлы (E2EE-чанки, кэш, Загрузки)
- [x] Tauri UI (push-snapshot) + опциональный egui
- [x] Трей / beacon
- [x] `VOID_ONION_v1` — 1 нода = 1 hop; 2+ до трёх hop'ов

### Опционально / не по умолчанию

- [ ] DCUtR, AutoNAT, UPnP — только `VOID_ENABLE_NAT=1`

### Планы

- [ ] Групповой ratchet (MLS-подобно) вместо fan-out
- [ ] Мобильные сборки
- [ ] Подписанные релизы + reproducible builds
- [ ] Меньше метаданных на relay (конверт без открытого `sender`)

---

## Безопасность

Уязвимости — **не в публичный issue**. Напишите автору приватно.

Проект **не проходил внешний аудит**. Не используйте VOID для защиты жизни или свободы людей.

Практика в коде: только E2EE в чате; Hello привязан к identity; лимиты JSON/HTTP/vault/файлов; кэш вложений под ключом vault. Остаточные риски (IP на ноде, PeerId, офлайн-метаданные, Identify) — выше и в [`SECURITY_REVISION.md`](./SECURITY_REVISION.md).

---

## Лицензия

[MIT](./LICENSE). Без гарантий.

---

<div align="center">

**Made with Rust 🦀 and a lot of `zeroize()`**

</div>
