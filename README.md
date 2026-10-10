<div align="center">

<img src="static/Image_programm.png" alt="VOID Logo" width="160" />

# VOID — P2P Messenger

**Децентрализованный, сквозно-шифрованный мессенджер.**
В репозитории не только приложение: здесь семейство протоколов `/void/…` и десктоп поверх него.
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

**VOID** (Verified Open Independent Dispatcher) — открытый протокол доставки и P2P-приложение на Rust поверх него. Оба слоя лежат в этом репозитории. Протокол — правила потоков и кадры в `src/` (`protocol`, `crypto`, `network`, `onion`, офлайн-конверт). Приложение — десктоп, который эти правила исполняет для человека. Живой чат идёт **между пирами** по `libp2p`: напрямую в LAN или через **Circuit Relay Hop** на bootstrap-ноде, если оба за NAT. Текст, голос и файлы шифруются **Double Ratchet**. Идентичность — `PeerId` из локального vault, без телефона и почты.

Bootstrap-нода нужна, чтобы **найти** собеседника, **зарезервировать Hop** и **хранить офлайн-конверты**. Она не расшифровывает сообщения, но **видит метаданные**: IP, PeerId, кто с кем строит circuit, поля офлайн-почты. Подробнее — [Приватность](#приватность-и-модель-угроз).

Основной десктоп — **Tauri 2** (`frontend/` + `src-tauri/`). Опционально — нативный UI на **egui** (`cargo run --release --features egui-ui`).

---

## Ключевые возможности

- **P2P-чат** — `/void/chat/1.0.0` (request-response). Полезная нагрузка — E2EE (`V1Packet::Encrypted`), поверх — опциональный onion (`VOID_ONION_v1`).
- **E2EE** — транспорт **Noise**, затем `Hello` (X25519 + подпись Ed25519 к `PeerId`), далее **Double Ratchet**.
- **1-на-1 и группы** — группы с invite `void://group/…`, рассылка каждому участнику (не MLS).
- **Голос** — запись, превью, WAV по E2EE; в чате плеер. Автоприём, без баннера «принять файл».
- **Файлы** — до 512 МБ, в том числе пустые (0 байт). Чанки (`VfC1`) и оффер/accept (`VfP1`) идут в E2EE `/void/chat`. `/void/file/1.0.0` — запасной канал, если пир уже на живом TCP.
- **Офлайн-почта** — store-and-forward на bootstrap (`OfflineMailboxStore` / `Query` / `Deliver`). Конверт v2 подписан libp2p-ключом отправителя, конверты без подписи не принимаются. `ct` непрозрачен; `sender` / `recipient` / `kind` на ноде открыты. TTL 7 суток.
- **Свой DHT** — Kademlia `/void/kad/1.0.0`, не IPFS. Текст чата в DHT не пишется.
- **NAT** — рабочий путь: **Relay v2 Hop** (`listen_on(…/p2p-circuit)` → `ReservationReqAccepted`). DCUtR / AutoNAT / UPnP **выключены** (включаются `VOID_ENABLE_NAT=1`: второй dial к ноде рвёт TCP).
- **Транспорт клиента** — listen только **TCP :50001**. К bootstrap — один TCP; `/p2p/` на dial снимается, реальный PeerId пишется в vault после Identify. QUIC к ноде клиент не поднимает.
- **LAN** — mDNS (отключается `VOID_DISABLE_MDNS`).
- **Один процесс** — `void.instance.lock` + порт TCP `50001`; в Tauri повторный запуск (ярлык, пока окно в трее) поднимает уже работающее окно (`tauri-plugin-single-instance`), а не вторую копию.
- **Vault** — ник, ключи, контакты, группы в `vault.bin`; мастер-ключ в `void.key`. Журнал — `chat_journal.bin`, недоставленное — `outbox.bin`.
- **Доставка** — ○ / ✓ / ✓✓; read receipt при открытом чате.
- **Beacon** — закрытие окна прячет в трей, процесс живёт. В шапке UI — логотип `Image_programm.png`.
- **Onion** — `VOID_ONION_v1`: 1 живая нода с ключом → 1 hop, 2 → оба, 3+ → до трёх. Живой путь виден в настройках. Скрывает IP отправителя от выхода, но не пару собеседников — см. [onion](#anonymous-routing-void_onion_v1).

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

UI **не** крутит `get_snapshot` по таймеру в обычном режиме. Состояние уходит событием `void://snapshot` (флашер ~120 мс, `revision` монотонный). Пока в статусе `Hop…`, UI дополнительно опрашивает снимок, чтобы не зависнуть на «ждём Ack».

### Строка статуса

Пример: `в сети · Hop OK · 12D3KooW… · live 1 · контакты 0 · bootstrap 1/2`

Пока Hop нет, к «в сети» добавляется `через ноду` (чат ящиком). Пока ждём Ack — ещё `Hop…`.

| Кусок | Смысл |
|-------|--------|
| `в сети` | Есть TCP хотя бы к одной bootstrap-ноде |
| `через ноду` | Нода жива, **Hop ещё нет** (чат ящиком, live-circuit нет) |
| `Hop…` | `listen_on(…/p2p-circuit)` ушёл, ждём Ack |
| `Hop OK` | Резервация принята (или UI подтвердил её ~2.5 с спустя, если событие Ack не всплыло) |
| `нет Hop` | Нода есть, запрос резервации не висит |
| `live N` | Число живых TCP: bootstrap + контакты |
| `контакты N` | Живые чат-пиры (**без** bootstrap) |
| `bootstrap A/B` | `A` — сколько seed сейчас на TCP; `B` — сколько адресов в vault. `1/2` = одна нода жива из двух в списке |

`1/2` — не ошибка: клиент сначала держит **одну** основную ноду (`147.78.64.22:4001`), вторую добирает после Hop. Для NAT и ящика достаточно одной с `Hop OK`.

### Как два клиента встречаются

```
Alice                         Bootstrap                         Bob
  │ TCP :4001 (без проверки /p2p/)  │
  │ Identify /void/v1               │
  │ vault: реальный PeerId ноды     │
  │ listen …/p2p/<node>/p2p-circuit │
  │ ◄── ReservationReqAccepted ──── │
  │          «Hop OK»               │
  │                                 │
  │  dial …/p2p-circuit/p2p/<Bob>   │
  │  (после Hop; LAN/mDNS отдельно) │
  │                                 │
  │ Hello → Double Ratchet          │
  │ Encrypted  (опц. Onion-обёртка) │
```

1. Один TCP на `IP:4001`. `/p2p/` с dial снимается (`DialOpts::unknown_peer_id()`), иначе старый PeerId в vault рвёт Noise за 1 мс.
2. После Identify клиент переписывает bootstrap в vault на **живой** PeerId ноды.
3. Hop: один `listen_on(/ip4/…/tcp/4001/p2p/<node>/p2p-circuit)` **после Identify** (~1.5 с). Повтор только если Hop всё ещё pending (cooldown ~3 с), без спама Reserve. В статусе **Hop OK** после `ReservationReqAccepted`; если событие не дошло до UI — через ~2.5 с при живом TCP.
4. Circuit к контакту — **после** Hop (пауза ~8 с после Ack), один адрес живого relay, при `NoReservation` пауза ~45 с. LAN/mDNS — отдельно, без подмешивания circuit в тот же dial.
5. `DialBack` просит собеседника набрать нас по circuit (асимметрия NAT).
6. Пока Hop нет, почта на bootstrap не долбит HOP-стримы (откладывается до Ack или ~90 с).

Две копии VOID с одним vault дают два TCP на одну ноду — оба сразу `yamux Closed`. Поэтому instance lock, отказ если `:50001` занят, и в Tauri — один экземпляр окна.

### Сетевой стек (`libp2p`)

| Слой | Как сейчас |
|------|------------|
| Listen клиента | TCP `0.0.0.0:50001`. QUIC listen **нет** |
| Dial bootstrap | один TCP на `host/tcp/port`; QUIC к ноде отфильтрован |
| Мультиплексор | Yamux (до 512 стримов на клиенте; на ноде Hop чувствителен к спаму RR) |
| Канал | Noise |
| Identify | `/void/v1`; bootstrap узнаётся по `agent_version` `void-bootstrap-node…` |
| Чат | `/void/chat/1.0.0` |
| Файлы (оффер, fallback) | `/void/file/1.0.0` |
| Оффер/чанки файла и голоса | E2EE-кадры `VfP1` / `VfC1` внутри `/void/chat` |
| DHT | `/void/kad/1.0.0`, `Mode::Server`, k-bucket **Manual** (адреса после живого TCP) |
| Discovery | mDNS + Kademlia + список bootstrap |
| Relay | клиент: `relay::client`; Hop = `ReservationReqAccepted` |
| DCUtR / AutoNAT / UPnP | `Toggle::off`, пока нет `VOID_ENABLE_NAT=1` |

Выделенного сервера переписки нет. Relay таскает непрозрачные байты circuit. Офлайн-конверты **лежат на ноде** до выдачи (`take_batch`) или TTL.

Kademlia `start_providing` — после Identify с чат-пиром (не с bootstrap). `kad.bootstrap()` — ~30 с **после** Hop Ack, не в момент первого TCP (иначе второй dial убивает сессию).

#### Надёжность

| Механизм | Поведение |
|----------|-----------|
| Dial bootstrap | один endpoint (`host/tcp/port`), cooldown, без параллельного QUIC |
| Автореконнект контакта | тик ~5 с; circuit только после Hop, backoff ~45 с после `NoReservation` |
| Hop | один `listen_on` после Identify (~1.5 с); повтор только если pending (cooldown ~3 с) |
| KAD | `kad.bootstrap()` ~30 с **после** Hop Ack, затем periodic 5 мин |
| E2EE Hello | при `ConnectionEstablished` с контактом (не с bootstrap) |
| Ретрай исходящих | `RESEND_GRACE` 1 с, экспоненциально до 300 с |
| Групповой голос | fan-out + повтор `SendGroupMessage` (~8 с), пока WAV не уйдёт |
| Недоставленное | `outbox.bin` → `OfflineMailboxStore` на bootstrap (Ack ноды = handoff) |
| Офлайн-ящик | Query к bootstrap после Hop; не чаще ~750 мс; остаток порции — через ~500 мс |

### Поиск собеседника

Нужны **bootstrap multiaddr** с `/p2p/<PeerId>` в vault (после первого успешного Identify PeerId ноды подставляется сам). Вшитый seed: `/ip4/147.78.64.22/tcp/4001/p2p/12D3KooWCAH8ykDMThNRRVLAM6LnuVrJeoZrQADzHC2x6ddhZxyG`. Референс ноды: [`MarshalV/bootstrap_node`](https://github.com/MarshalV/bootstrap_node).

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
| `PrekeyPut` / `Get` / `Offer` | X25519 prekey для seal без живого Hello. Ответ ноды без подписи владельца для seal не используется; непрошеный `Offer` игнорируется |
| `BootstrapGossip` | обмен seed |
| `DialBack` | «набери меня по circuit» |
| `Onion` / `OnionDrop` | слои `VOID_ONION_v1`. `OnionDrop` принимается только от bootstrap, объявившего `;onion=` в своём Identify; внутри — только `Hello` / `Encrypted` / `Ack` |

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

Офлайн-конверт v2 (`src/offline_mail.rs`):

- `ct` — ChaCha20-Poly1305 на ключ из X25519(эфемерный, prekey получателя), HKDF с `eph` и ключом получателя;
- внутри `ct` — подпись libp2p-ключа отправителя над `sender`, `recipient`, `sender_pk`, `message_id`, `kind`, `eph` и SHA-256 тела;
- те же поля — AAD шифра: нода не может их переписать или перенаправить конверт другому получателю;
- получатель принимает `dm` / `group` только если `sender_id` внутри совпадает с подписью; `group_sync` — от подписавшего;
- конверты v1 (без подписи) отбрасываются. **Несовместимо со старыми клиентами** — обновлять всех участников.

На ноде открыты `sender`, `recipient`, `kind`, `message_id`.

### Prekey

Prekey — статический X25519 контакта. Для seal используется только проверенный ключ:

| Источник | Принимается |
|----------|-------------|
| `Hello` с подписью к `PeerId` | да |
| DHT `/void/prekey/<peer>`: `pk[32]` + подпись libp2p-ключа владельца | да, если подпись верна |
| DHT-запись без подписи (старый формат) | нет |
| `PrekeyOffer` от bootstrap | нет — у ноды нет подписи владельца; только если совпадает с уже проверенным |
| `PrekeyOffer` без своего `PrekeyGet` | нет |

Первое офлайн-письмо контакту, с которым не было `Hello`, уходит только при подписанной записи в DHT. Иначе письмо ждёт в outbox, пока контакт появится в сети.

### Офлайн-почта

Живой путь — **не DHT**, а RR к bootstrap:

1. Получатель офлайн → проверенный prekey (`Hello` / подписанный DHT) → `OfflineMailboxStore`.
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
| 0 | onion нет — circuit / прямой RR |
| 1 | один hop: нода после unwrap видит пару Alice↔Bob |
| 2 | оба hop'а |
| 3+ | до трёх случайных; entry не видит Bob, exit не видит IP Alice |

Что видит каждый участник цепочки из трёх:

| Участник | Видит |
|----------|-------|
| Entry | IP и PeerId Alice, следующий hop, размер |
| Middle | соседние hop'ы, размер |
| Exit | **PeerId Alice и PeerId Bob** (`OnionDrop.src`), тип пакета, размер |

Ограничения `VOID_ONION_v1`:

- exit знает пару Alice↔Bob; скрыт только IP Alice;
- путь выбирается **заново для каждого пакета** — за разговор пару узнают многие exit;
- onion не используется, если Bob уже подключён напрямую (LAN, circuit, DCUtR), и при ошибке обёртки (слишком большой пакет) — тогда пакет уходит **напрямую**;
- размеры ячеек не выравниваются, ключи hop'ов не ротируются.

Живой маршрут (PeerId hop'ов) показывается в настройках. Старые ноды без `;onion=` в цепочку не входят. Это не mixnet и не защита от глобального наблюдателя. DCUtR (если включён) может открыть прямой канал и снова связать IP.

### Файлы (`src/file_transfer.rs`)

| Параметр | Значение |
|----------|----------|
| Чанк | 32 КБ |
| Макс. размер | 512 МБ (0 байт разрешён) |
| Оффер / Accept | E2EE `VfP1` в `/void/chat`; `/void/file` если пир уже connected |
| Чанки | E2EE `VfC1` в `/void/chat` |
| Кэш | `%APPDATA%\VOID\files` (и аналоги) — AES-256-GCM, `*.vfc` |
| Ключ кэша | HKDF-SHA256 от мастер-ключа (`VOID_FILE_CACHE_v1`) |
| «Скачать» | копия в `Загрузки/VOID Messenger/` |
| Удаление из чата | только кэш |
| Через circuit | ~64 КБ/с |

Имя файла в оффере видит тот, кто терминирует соединение (собеседник; при `/void/file` — ещё и кто видит этот substream). Через relay без E2EE-оффера метаданные не должны светиться на ноде.

### Голосовые (`src/voice.rs`)

WAV mono 48 kHz 16-bit PCM, до 5 мин. Запись — дочерний процесс `--voice-record` (`cpal`). В чат — `VoiceMeta`; WAV как файл с автоприёмом. Офлайн: чанки `voice_chunk` через тот же mailbox. Метаданные по возможности снимаются (`metadata_strip`).

### Группы (`src/group.rs`)

Список участников в vault + тред `group:<id>`. Сообщение/файл/голос — fan-out каждому (у файла и голоса свой `transfer_id` на пира). Голос в группе ставится в очередь и повторяется, пока WAV не уйдёт. Invite: `void://group/…`. **Не MLS**: компрометация участника раскрывает то, что он получил.

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
- **Десктоп:** Tauri 2.6 (`frontend/` + `src-tauri/`); опционально egui 0.29 (`egui-ui`)
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

На одном vault — **одна** копия процесса. Вторая не стартует (`void.instance.lock` / порт 50001). Если VOID уже в трее, ярлык открывает то же окно.

### egui (опционально)

```bash
cargo run --release --features egui-ui
```

На Linux для egui могут понадобиться `libxcb`, `libxkbcommon`, `libwayland-dev`.

При первом запуске задаёте пароль vault. Ник вида `User_1A2B` можно сменить в настройках.

### Подключение

1. Свой Peer ID — в настройках.
2. Контакт — по Peer ID (не голый IP без `/p2p/<PeerId>`).
3. Bootstrap в списке seed; в статусе `bootstrap 1/N` и **Hop OK** (не вечный `Hop…`). `1/2` значит жива одна нода из двух в vault — для чата этого достаточно.

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
| **Офлайн-почта / prekey** | Store/query на `/void/chat`; выдача **порциями с удалением** (`take_batch`). Prekey с ноды клиент для seal не использует, пока нода не хранит подпись владельца |
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
- [x] Kademlia `/void/kad/1.0.0` после Hop (`kad.bootstrap` ~30 с)
- [x] Relay v2 Hop (`ReservationReqAccepted` / UI `Hop OK`)
- [x] Vault, журнал, outbox, один процесс на vault + single-instance в Tauri
- [x] Личные чаты и группы (голос в группе с ретраем)
- [x] Офлайн-почта через bootstrap (порции + удаление на ноде)
- [x] Доставка и read receipt
- [x] Голос и файлы (E2EE `VfP1`/`VfC1`, пустые файлы, кэш, Загрузки)
- [x] Tauri UI (push-snapshot) + опциональный egui
- [x] Трей / beacon, повторный запуск поднимает то же окно
- [x] `VOID_ONION_v1` — 1/2/3 hop по числу нод с ключом; путь в настройках
- [x] `OnionDrop` только от объявленных onion-hop'ов, внутри только `Hello` / `Encrypted` / `Ack`
- [x] Офлайн-конверт v2 с подписью отправителя; prekey только из `Hello` или подписанной DHT-записи

### Опционально / не по умолчанию

- [ ] DCUtR, AutoNAT, UPnP — только `VOID_ENABLE_NAT=1`

### План протокола

Ближайшая работа — вынуть договор доставки, который уже исполняет это приложение, в спецификацию и крейты. Протокол и десктоп сейчас в одном дереве: потоки в `src/`, окно — `frontend/` и `src-tauri/`. Tauri остаётся одним потребителем крейтов. Цель: другая реализация говорит на тех же потоках по спецификации и векторам, без этого репозитория как образца интерфейса.

Код по-прежнему [MIT](./LICENSE). Текст спецификации — CC BY 4.0.

В норматив попадает только то, без чего второй узел не сойдётся с первым. Вне спецификации, как местный выбор этого клиента: раскладка vault, Tauri и egui, listen TCP `:50001`, один TCP к bootstrap, таймауты реконнекта и Hop. У потоков своя версия: смена `format_version` vault не меняет байты на проводе.

Порядок фиксированный: спецификация, затем крейты, затем векторы, затем форма конверта. Векторы пишутся уже по крейтам из задачи 2.

#### 1. Нормативная спецификация

Отделить уже реализованные правила от поведения этого клиента. Один диспетчер встречу видит; onion это не отменяет, пока на пути нет нескольких независимых узлов. Kademlia — индекс обнаружения; текст разговора в DHT спецификация запрещает, а не оставляет комментарием в клиенте.

| Документ | Что фиксирует |
|----------|----------------|
| Личность | PeerId как ключ участника, не аккаунт |
| Hello | Подпись, которая связывает ключи сессии с PeerId обеих сторон |
| Сессия | Кадры Double Ratchet внутри `/void/chat/1.0.0` |
| Вложения | Файлы и голос (`VfP1` / `VfC1`) внутри этой сессии; `/void/file/1.0.0` — запасной канал |
| Конверт | `OfflineMailboxStore` / `Query` / `Deliver`, prekey; что диспетчер хранит и что ещё видит (`sender`, `recipient`, `kind`, пока нет задачи 4) |
| Поиск | `/void/kad/1.0.0` без текста чата |
| Встреча | Какая резервация Hop нужна пиру от диспетчера |
| Seed | `/void-seed/v1` между диспетчерами |
| Onion | `VOID_ONION_v1`: 1 / 2 / 3 hop, что видит каждый hop |

Эталонный диспетчер — [`MarshalV/bootstrap_node`](https://github.com/MarshalV/bootstrap_node). Seed и ящик описываются здесь, даже если код ноды лежит в том репозитории. В тексте спецификации нет внутренних типов десктопной оболочки.

#### 2. Библиотеки без интерфейса

Вынести протокол из клиента в крейты. Десктоп их подключает. Вторым потребителем становится harness из задачи 3.

| Крейт | Содержимое |
|-------|------------|
| Кадры | Типы кадров и пределы длины |
| Сессия | Signed Hello и Double Ratchet |
| Конверт | Seal и open офлайн-почты |
| Onion | Wrap и unwrap `VOID_ONION_v1` |

Оболочка Tauri результатом этой работы не является.

#### 3. Тесты соответствия

Машиночитаемые векторы, по которым протокол можно реализовать без чтения UI:

- Hello принят и Hello отвергнут
- Пропущенные ключи ratchet в пределах текущего потолка **4096**
- Seal и open конверта
- Onion на 1, 2 и 3 hop

Harness — два процесса, без графического окна. Тест, который зелёный только против десктопной программы, считается провалом спецификации.

#### 4. Конверт без постоянного открытого `sender`

Сейчас диспетчер хранит непрозрачный `ct` и видит стабильные `sender`, `recipient` и `kind`. Новая форма конверта: нода по-прежнему просрочивает запись и отдаёт её получателю, но без постоянного отправителя открытым текстом.

В спецификации явно остаётся то, что маршрут всё ещё показывает: размер, время и идентификатор, без которого выдачу сделать нельзя. Если открытым остаётся получатель, это пишется как есть. Называть форму анонимностью нельзя: один диспетчер встречу видит; размеры onion не выравниваются; наблюдатель всего пути связывает вход и выход.

К этой форме — свои векторы.

### Вне этого плана

- [ ] Групповой ratchet. Сейчас группы — fan-out попарных сессий, без групповой прямой секретности. Спецификация так и описывает этот предел. Следующий шаг, если он будет, — OpenMLS или явный отказ от него, не второй самодельный ratchet
- [ ] Мобильные сборки
- [ ] Подписанные релизы и reproducible builds
- [ ] Внешний разбор композиции Hello + ratchet + seal конверта — по уже готовым спецификации и векторам, не вместо них

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
