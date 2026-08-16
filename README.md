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

**VOID** (Verified Open Independent Dispatcher) — P2P-мессенджер на Rust. Живой чат идёт **напрямую между пирами** (или через Circuit Relay, если оба за NAT) по `libp2p`. Текст, голос и содержимое файлов шифруются **Double Ratchet** (как в Signal). Идентичность — `PeerId` из локального vault, без телефона и почты.

Bootstrap-нода нужна, чтобы **найти** собеседника и **пробросить NAT**. Она не расшифровывает сообщения, но **видит метаданные**: IP подключения, PeerId, кто с кем строит circuit, конверты офлайн-почты (отправитель/получатель/тип, не текст). Подробнее — в разделе [Приватность](#приватность-и-модель-угроз).

Основной десктоп — **Tauri 2** (`frontend/` + `src-tauri/`). Опционально собирается нативный UI на **egui** (`cargo run --release` с feature `egui-ui`).

---

## Ключевые возможности

- **P2P-чат** — `/void/chat/1.0.0` (request-response). Полезная нагрузка только E2EE (`V1Packet::Encrypted`).
- **E2EE** — транспорт **Noise**, затем `Hello` (X25519 + подпись Ed25519 к `PeerId`), далее **Double Ratchet** (Forward Secrecy + Post-Compromise Security).
- **1-на-1 и группы** — группы с invite-ссылкой `void://group/…`, рассылка каждому участнику.
- **Голос** — запись с микрофона, предпрослушивание, отправка WAV по E2EE; в чате — плеер с перемоткой. Автоприём, без баннера «принять файл».
- **Файлы** — до 512 МБ. Чанки по E2EE-чату; оффер (имя, размер, хэш) по `/void/file/1.0.0`. В чате — карточка; **Скачать** копирует расшифрованный файл в `Загрузки/VOID Messenger`. Локальный кэш — AES-256-GCM в каталоге данных (`files/`), не в Загрузках.
- **Офлайн-почта** — если пир недоступен, сообщение кладётся на bootstrap (зашифрованный `ct`, открытые поля `sender` / `recipient` / `kind`, TTL 7 суток). Короткие голосовые тоже могут уйти чанками через тот же канал.
- **Свой DHT** — Kademlia `/void/kad/1.0.0`, не IPFS. В DHT не пишется текст чата.
- **NAT** — Relay v2 (сначала circuit), DCUtR (hole-punch → прямое соединение), AutoNAT, UPnP.
- **Транспорты** — TCP и QUIC, Yamux, Noise.
- **LAN** — mDNS (отключается `VOID_DISABLE_MDNS`).
- **Vault** — ник, ключи, контакты, группы в `vault.bin` (AES-256-GCM); мастер-ключ в `void.key` (Argon2id + AES-GCM от пароля). Журнал чата — `chat_journal.bin`, недоставленное — `outbox.bin`.
- **Доставка** — ○ / ✓ / ✓✓; read receipt при открытом чате.
- **Beacon** — закрытие окна прячет в трей, не завершает процесс (как Telegram Desktop).

---

## Архитектура

### 1. Сетевой стек (`libp2p`)

| Слой | Технология |
|------|-----------|
| Транспорт | TCP, QUIC |
| Мультиплексор | Yamux |
| Шифрование канала | Noise |
| Чат | `request-response` `/void/chat/1.0.0` |
| Файлы (оффер/ack) | `request-response` `/void/file/1.0.0` |
| Полезные чанки файлов/голоса | E2EE-кадры внутри `/void/chat` |
| DHT | Kademlia `/void/kad/1.0.0` |
| Discovery | mDNS (LAN) + Kademlia + bootstrap |
| NAT | Relay v2, DCUtR, AutoNAT, UPnP |

Каждый клиент — участник DHT. **Выделенного сервера переписки нет:** живой текст bootstrap не форвардит и не читает. Relay **пересылает непрозрачные байты** circuit-а; офлайн-конверты **хранятся** на ноде до TTL.

Клиент регистрирует `PeerId` в DHT как provider (`start_providing`). Dial к контакту: **сначала circuit через bootstrap**, затем прямые/LAN-адреса (чтобы зависший NAT-dial не блокировал relay).

#### Надёжность

| Механизм | Поведение |
|----------|-----------|
| Поиск пира | Параллельно `get_providers` + `get_closest_peers` |
| Автопереподключение | Тик ~5 с, backoff 2 → 5 → 15 → 60 с |
| KAD bootstrap | Периодически |
| E2EE Hello | При `ConnectionEstablished` с контактом из vault |
| Ретрай | `RESEND_GRACE` 1 с, экспоненциально до 300 с |
| Недоставленное | `outbox.bin` → офлайн-почта на bootstrap (Ack от ноды = durable handoff) |
| Read receipt / голос / файл | Буфер до сессии |

### 2. Поиск собеседника

Чтобы два узла из разных сетей нашли друг друга, нужны **bootstrap-адреса** (вход в DHT + relay). Это не «центральный сервер чата». Референс: [`MarshalV/bootstrap_node`](https://github.com/MarshalV/bootstrap_node) (раздел [инфраструктура](#развёртывание-своей-инфраструктуры)).

Источники bootstrap (склеиваются, дедуплицируются):

1. Вшитые в бинарь (`BUILTIN_VOID_BOOTSTRAP` / `VOID_BUILTIN_BOOTSTRAP`).
2. HTTP(S) список (`VOID_BOOTSTRAP_URL` / `VOID_BOOTSTRAP_PUBLIC_LIST_URL`), лимит тела ~256 KiB. Опционально `VOID_BOOTSTRAP_TRUSTED_HOSTS`, pin листа `VOID_BOOTSTRAP_TLS_LEAF_SHA256`.
3. `VOID_BOOTSTRAP` — multiaddr через запятую.
4. `void-bootstrap.txt` рядом с бинарём. Опционально Ed25519-подпись (`VOID_BOOTSTRAP_SIGNING_PUB_HEX`).
5. UI: настройки bootstrap → сохранить и применить.

```powershell
$env:VOID_BOOTSTRAP = "/dnsaddr/example.com/tcp/4001/p2p/12D3KooW..."
```

Прямой вход: поле подключения принимает `multiaddr`, `IP` или `IP:PORT`.

### 3. Сквозное шифрование (`src/crypto.rs`)

| Этап | Алгоритм |
|------|---------|
| Транспорт | **Noise** |
| Handshake | Статический + эфемерный **X25519** в `Hello`, **Ed25519** к `PeerId` |
| Ratchet | **Double Ratchet** |
| KDF | **HKDF-SHA256** |
| AEAD чата | **ChaCha20-Poly1305** |
| Vault / журнал / кэш файлов | **AES-256-GCM** |
| Целостность файла | **BLAKE2b-512** (первые 32 байта) |
| Память ключей | `zeroize` |
| Skipped keys | до **4096** out-of-order |

Каждое сообщение — свой `message_key`. Компрометация одного ключа не раскрывает прошлые и будущие.

Офлайн-конверт: `ct` запечатан на X25519 prekey получателя (ChaCha20-Poly1305). Поля `sender`, `kind`, `message_id` на ноде **открыты**.

### 4. Файлы (`src/file_transfer.rs`)

| Параметр | Значение |
|----------|---------|
| Чанк | 32 КБ |
| Макс. размер | 512 МБ |
| Кэш чата | `%APPDATA%\VOID\files` (Windows) / аналог `dirs::data_dir()/VOID/files` — **AES-256-GCM**, имена `*.vfc` |
| Ключ кэша | HKDF-SHA256 от мастер-ключа vault (`VOID_FILE_CACHE_v1`) |
| «Скачать» | Расшифрованная копия в `Загрузки/VOID Messenger/` |
| Удаление из чата | Стирает только кэш, не Загрузки |
| Голос | `…/VOID/voice/` (не Загрузки) |

После `Accept` данные чанков идут по E2EE `/void/chat`. По `/void/file` — `Offer` / `Accept` / `Reject` / `Cancel` / `Ack` (имя файла на этом слое видит тот, кто терминирует соединение: пир или relay).

Через Circuit Relay отправка чанков ограничена (~64 КБ/с), прямое соединение — короткая пауза между чанками.

### 5. Голосовые (`src/voice.rs`)

WAV mono 48 kHz 16-bit PCM, до 5 мин. Запись — дочерний процесс `--voice-record` (`cpal`). В чат уходит `VoiceMeta`; WAV — как файл с автоприёмом. Перед отправкой можно прослушать. Метаданные медиа по возможности снимаются (`metadata_strip`).

### 6. Группы (`src/group.rs`)

Группа — список участников в vault + отдельный тред журнала `group:<id>`. Сообщение/файл/голос рассылается каждому члену (у файла — свой `transfer_id` на пира). Invite: `void://group/…`. Это **не MLS**: нет общего группового ratchet на всех сразу, компрометация участника раскрывает то, что он получил.

### 7. Локальное хранилище

Каталог данных (переопределяется `VOID_DATA_DIR`):

| ОС | Путь по умолчанию |
|----|-------------------|
| Windows | `%APPDATA%\VOID` |
| Linux | `~/.local/share/VOID` |
| macOS | `~/Library/Application Support/VOID` |

| Файл / папка | Содержимое | Защита |
|--------------|------------|--------|
| `void.key` | Обёрнутый мастер-ключ (`VOIDKEY2`) | Пароль + Argon2id + AES-GCM |
| `vault.bin` | Ник, ключи, контакты, группы, bootstrap | AES-256-GCM |
| `chat_journal.bin` | Переписки | AES-256-GCM |
| `outbox.bin` | Недоставленное | AES-256-GCM |
| `files/` | Кэш вложений `*.vfc` | AES-256-GCM (отдельный HKDF-ключ) |
| `voice/` | WAV голосовых | каталог данных приложения |
| `void.pwd` | «Запомнить пароль» | Windows: Credential Manager + файл; macOS/Linux: файл |

> Никогда не отдавайте пароль vault вместе с `void.key` и `vault.bin`.

---

## Приватность и модель угроз

VOID **скрывает содержимое** от сети и от bootstrap. VOID **не скрывает**, что вы вообще пользуетесь сетью и с какого IP подключились к ноде.

Сейчас маршрут живого чата — один hop (или прямое соединение после DCUtR):

```
Alice
  │  E2EE (Double Ratchet)
  ▼
Relay / Bootstrap
  │
  ▼
Bob
```

Relay не видит plaintext, но **может** сопоставить:

- IP Alice → PeerId Alice
- IP Bob → PeerId Bob
- пару Alice ↔ Bob (`CircuitReqAccepted` логирует `src` и `dst`)
- время соединения и объём трафика
- офлайн-конверт: `sender` / `recipient` / `kind` (поле `ct` непрозрачно)

| Наблюдатель | Текст / файлы / голос | IP отправителя | Кто есть «вы» |
|-------------|------------------------|----------------|----------------|
| Собеседник | Да, это получатель | Да, если канал **прямой** (LAN, DCUtR). Через один только relay — обычно нет | PeerId + ник |
| Владелец bootstrap/relay | Нет (E2EE / `ct`) | **Да** — вы сами коннектитесь к ноде | PeerId, circuit `src→dst`, офлайн `sender`/`recipient`/`kind` |
| Другой пир в DHT | Нет | Нет (кроме mDNS в LAN) | Иногда publisher mailbox / prekey |

Нет IMEI и серийника устройства. Стабильный идентификатор клиента — **PeerId** (пока живёт vault).

Это **псевдонимный E2EE-мессенджер**, не Tor. E2EE + Noise + Relay + DHT защищают **контент**, не метаданные маршрутизации. Не используйте VOID, если модель угроз — «нода не должна знать, кто кому писал».

Одна инфраструктурная нода для **текущего** VOID — нормальный рабочий режим (discovery, relay, NAT, mailbox). Она **не** даёт анонимности маршрутизации: `Alice → Node A → Bob` позволяет Node A связать отправителя и получателя. Подробнее — в [слое ниже](#anonymous-routing-layer-void_onion_v1).

---

## Anonymous routing layer (`VOID_ONION_v1`)

Отдельный сетевой слой **поверх** libp2p, Relay, DCUtR и E2EE. Это не «ещё один DHT» и не удаление bootstrap: цель — скрыть связь между реальным IP отправителя, получателем и фактом коммуникации.

Целевой стек:

```
Application
     │
Double Ratchet
     │
E2EE packet
     │
Anonymous Routing Layer
     │
┌────┴────┐
│ Route   │
│ Node 1  │
│ Node 2  │
│ Node 3  │
└────┬────┘
     │
     ▼
  Recipient
```

Вместо прямого `Alice → Relay → Bob` — цепочка независимых hop'ов (onion / mixnet):

```
Alice → Node A → Node B → Node C → Bob
```

| Hop | Что знает | Чего не знает |
|-----|-----------|----------------|
| Node A | IP Alice, следующий hop | кто Bob |
| Node B | только соседей по цепи | Alice и Bob |
| Node C | Bob, предыдущий hop | кто Alice |
| любой один hop | непрозрачный E2EE payload | plaintext и полную пару Alice → Bob |

Несколько Circuit Relay в DHT **ещё не** делают routing anonymous. Если один оператор видит входящий и исходящий поток (время, размер пакетов, стабильный PeerId), анонимность деградирует. Пять нод одного человека с точки зрения доверия ≈ одна нода.

| Число независимых routing-нод | Анонимность маршрутизации |
|-------------------------------|---------------------------|
| 1 | практически нет (`Alice → Node A → Bob`) |
| 2 | слабая |
| 3 | уже возможна многослойная цепочка |
| 5+ независимых операторов | существенно лучше |

E2EE при одной ноде **продолжает** работать: нода не получает plaintext. Меняется только то, видна ли пара «кто с кем».

**Сейчас в коде:** `VOID_ONION_v1` — клиент оборачивает Hello/Encrypted (включая чанки файлов) в onion-ячейки и шлёт на первую живую bootstrap-ноду с ключом `onion=` в Identify `agent_version`.

- 1 живая нода → один hop (`Alice → Node A → Bob`). Нода после unwrap видит пару.
- 2 ноды → оба hop'а; 3+ → до трёх случайных из живых. Entry не видит Bob; exit не видит IP Alice.
- Ноды без `;onion=` в agent (старые сборки) в цепочку не входят; чат идёт как раньше (circuit / прямой RR).
- Это не mixnet и не защита от глобального наблюдателя (тайминг, размеры, стабильный PeerId). DCUtR по-прежнему может открыть прямой канал.

---

## Стек

- **Язык:** Rust 2021
- **Сеть:** libp2p 0.56
- **Десктоп:** Tauri 2 + HTML/JS (`frontend/`); опционально egui 0.29
- **Аудио:** cpal + hound; WinMM fallback на Windows
- **Крипто:** x25519-dalek, chacha20poly1305, aes-gcm, argon2, hkdf, blake2, zeroize

---

## Установка и запуск

Нужен **Rust** ≥ 1.77.2 (`stable`) и [Tauri CLI](https://v2.tauri.app/start/prerequisites/) для основной оболочки.

### Tauri (основной клиент)

```bash
git clone https://github.com/MarshalV/p2p-messenger.git
cd p2p-messenger
cargo tauri dev
# релиз (MSI/NSIS/deb/dmg):
cargo tauri build
```

Скрипты сборки копируют установщики в корневой `target/`: `build.bat` (Windows), `./build.sh` (Linux), `./build_mac.sh` (macOS).

### egui (опционально)

```bash
cargo run --release --features egui-ui
```

На Linux для egui могут понадобиться `libxcb`, `libxkbcommon`, `libwayland-dev`.

При первом запуске задаёте пароль vault. Ник вида `User_1A2B` можно сменить в настройках.

### Подключение

1. Свой Peer ID — в настройках; у собеседника — тот же экран.
2. Добавьте контакт по Peer ID (не по голому IP без `/p2p/<PeerId>`).
3. Bootstrap-нода в списке seed — чтобы находить людей за NAT.

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
| `VOID_APPLY_FIREWALL_RULE` | Разрешить правку файрвола (Windows/macOS) |
| `VOID_SKIP_SUBNETS` | Доп. CIDR «мусорных» listen-адресов |
| `VOID_BUILTIN_BOOTSTRAP` | Вшить seed при сборке |
| `RUST_LOG` | По умолчанию **warn**; `void_net=debug` — адреса в логах |

Инвентаризация рисков: [`SECURITY_REVISION.md`](./SECURITY_REVISION.md).

---

## Развёртывание своей инфраструктуры

Собственные bootstrap/relay ускоряют поиск и NAT. Даже Raspberry Pi тянет роль Relay + Kademlia. Разбор железа: [`info`](./info).

### Референс: `void-bootstrap-node`

> 🔗 **[github.com/MarshalV/bootstrap_node](https://github.com/MarshalV/bootstrap_node)**

| Роль | Что делает |
|------|-----------|
| **Kademlia Server** | Вход в `/void/kad/1.0.0` |
| **Circuit Relay v2** | Встреча за NAT, DCUtR; пересылает **зашифрованные** байты circuit-а |
| **Офлайн-почта / prekey** | Store/query конвертов на `/void/chat`; `ct` нечитаем, метаданные на диске (`relay_mailbox.bin`) |
| **VOID-SEED** | `/void-seed/v1` на отдельном TCP-порту — обмен списками **между нодами**, не чат клиентов |

Живой `V1Packet::Encrypted` нода **не форвардит** (чат не идёт «через сервер как у Telegram»). Circuit relay и mailbox — отдельные пути.

#### Libp2p ноды

| Компонент | Настройка |
|-----------|-----------|
| Транспорты | TCP + QUIC, порт `LISTEN_PORT` (4001) |
| Identify | `/void/v1`, `void-bootstrap-node/0.3` |
| Kademlia | `/void/kad/1.0.0`, **Mode::Server** |
| Relay | Default + ослабленные лимиты под один NAT |
| Ping / AutoNAT | Default |
| Логи | `RUST_LOG` по умолчанию **info** — в т.ч. IP в `endpoint` соединений |

Без серверных узлов в DHT новичкам не к кому приземлиться.

#### Протокол `/void-seed/v1`

Обмен списками bootstrap-нод (не клиентский чат): X25519 PFS, HKDF-SHA-512, ChaCha20-Poly1305, Ed25519 той же пары, что libp2p `PeerId`. На проводе — эфемерный ключ и шифротекст.

Сервер при offer запоминает **фактический IP** TCP-сокета (`touch(peer_id, remote_ip, …)`) в `known_nodes.json` — так задумано для mesh нод.

#### Состояние ноды

| Файл | Что | Делиться |
|------|-----|----------|
| `bootstrap_peer.key` | Идентичность ноды | **нет** |
| `known_nodes.json` | Другие bootstrap | да (публичные адреса) |
| `relay_mailbox.bin` | Офлайн-конверты | **нет** (метаданные переписки) |

#### Переменные ноды

| Переменная | По умолчанию | Назначение |
|-----------|-------------|-----------|
| `LISTEN_PORT` | `4001` | libp2p TCP+QUIC |
| `SEED_PORT` | `4010` | `/void-seed/v1` |
| `SEED_BIND` | `0.0.0.0:$SEED_PORT` | bind seed |
| `PUBLIC_HOST` | пусто | рекламируемый хост; иначе `remote_ip` |
| `RUST_LOG` | `info` | логи (IP коннектов на info) |

#### Клиенты VOID

```bash
git clone https://github.com/MarshalV/bootstrap_node
cd bootstrap_node
cargo run --release
```

Проброс: **TCP 4001**, **UDP 4001**; **TCP 4010** только для других bootstrap-нод.

```
/ip4/<ПУБЛИЧНЫЙ_IP>/tcp/4001/p2p/<PEER_ID>
/ip4/<ПУБЛИЧНЫЙ_IP>/udp/4001/quic-v1/p2p/<PEER_ID>
```

Одна нода уже сводит двух клиентов за NAT (discovery + relay + mailbox). Для **устойчивости** сети разумный минимум — **2–3 ноды в разных сетях**. Для **анонимности маршрутизации** одной ноды недостаточно — см. [onion-слой](#anonymous-routing-layer-void_onion_v1).

---

## Статус

**Alpha.** Формат vault/журнала ещё может меняться.

### Есть

- [x] P2P + Double Ratchet + Noise + привязка Hello к identity
- [x] Kademlia `/void/kad/1.0.0` + provider
- [x] Relay v2, DCUtR, UPnP, AutoNAT
- [x] Vault, журнал, outbox
- [x] Личные чаты и группы
- [x] Офлайн-почта через bootstrap
- [x] Доставка и read receipt
- [x] Голос (запись, превью, E2EE, плеер)
- [x] Файлы: E2EE-чанки, шифрованный кэш, выгрузка в Загрузки
- [x] Tauri UI + опциональный egui
- [x] Трей / beacon

### Планы

- [ ] Групповой ratchet (MLS-подобно) вместо fan-out
- [ ] Мобильные сборки
- [ ] Подписанные релизы + reproducible builds
- [ ] Меньше метаданных на relay (офлайн-конверт без открытого `sender`, опционально relay-only без DCUtR)
- [x] **Anonymous routing layer** — 1 живая нода = 1 hop; 2+ ноды комбинируются (до 3 hop'ов, VOID_ONION_v1)

---

## Безопасность

Уязвимости — **не в публичный issue**. Напишите автору приватно.

Проект **не проходил внешний аудит**. Не используйте VOID для защиты жизни или свободы людей.

Практика в коде: только E2EE в чате; Hello привязан к identity; лимиты JSON/HTTP/vault/файлов; кэш вложений под ключом vault. Остаточные риски (IP на ноде, PeerId, офлайн-метаданные, Identify, hole-punch) — выше и в [`SECURITY_REVISION.md`](./SECURITY_REVISION.md).

---

## Лицензия

[MIT](./LICENSE). Без гарантий.

---

<div align="center">

**Made with Rust 🦀 and a lot of `zeroize()`**

</div>
