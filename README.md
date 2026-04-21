<div align="center">

<img src="static/icon.png" alt="VOID Logo" width="160" />

# VOID — P2P Messenger

**Децентрализованный, сквозно-шифрованный мессенджер без серверов.**
Без регистрации. Без телефонов. Без облаков. Только вы, собеседник и немного математики.

<p>
  <img alt="Rust"         src="https://img.shields.io/badge/Rust-2021-CE422B?logo=rust&logoColor=white">
  <img alt="libp2p"       src="https://img.shields.io/badge/libp2p-0.56-4E8EE9?logo=ipfs&logoColor=white">
  <img alt="egui"         src="https://img.shields.io/badge/UI-egui%200.29-111111">
  <img alt="E2EE"         src="https://img.shields.io/badge/E2EE-Double%20Ratchet-16a34a">
  <img alt="Platform"     src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue">
  <img alt="Status"       src="https://img.shields.io/badge/status-alpha-orange">
</p>

<img src="static/preview.png" alt="VOID Preview" width="85%" />

</div>

---

## Что это

**VOID** (Verified Open Independent Dispatcher) — это P2P-мессенджер на Rust, который отправляет сообщения **напрямую между пирами** по протоколу `libp2p`, минуя какие-либо центральные чат-сервера. Вся переписка шифруется end-to-end по схеме **Double Ratchet** (как в Signal/WhatsApp), а локальная записная книга и ключи лежат в зашифрованном `vault.bin`.

> «Void» — потому что между вами и собеседником — пустота. Ни серверов, ни посредников, ни логов.

---

## Ключевые возможности

- **Полностью P2P** — сообщения доставляются напрямую по `/void/chat/1.0.0` (request-response).
- **E2EE из коробки** — Noise IK handshake + Double Ratchet (Forward Secrecy + Post-Compromise Security).
- **Свой DHT** — отдельный Kademlia-рой `/void/kad/1.0.0`, не пересекающийся с публичным IPFS.
- **NAT Traversal** — Relay v2, DCUtR (hole-punching), AutoNAT, UPnP.
- **Транспорты** — TCP и QUIC, мультиплексирование Yamux, шифрование канала Noise.
- **Локальная сеть** — автодискавери соседей через mDNS (без интернета).
- **Зашифрованный vault** — ник, приватные ключи и контакты хранятся в `vault.bin` (AES-256-GCM, ключ в `void.key`).
- **Умный ретрай** — если прямой dial не удался, клиент запускает DHT-lookup пира и повторяет отправку.
- **Красивый UI** — тёмная «cosmic» тема с неон-глассморфизмом на `egui`, эмодзи-шрифт, аватары-идентиконы.
- **Глобальный и приватные чаты** — отдельная «комната» GLOBAL и 1-на-1 переписка с каждым контактом.

---

## Архитектура

### 1. Сетевой стек (`libp2p`)

| Слой | Технология |
|------|-----------|
| Транспорт | TCP, QUIC |
| Мультиплексор | Yamux |
| Шифрование канала | Noise |
| Чат-протокол | `request-response` по `/void/chat/1.0.0` |
| DHT | Kademlia `/void/kad/1.0.0` (свой, не IPFS) |
| Discovery | mDNS (локальная сеть) + Kademlia (глобально) |
| NAT | Relay v2, DCUtR, AutoNAT, UPnP |

Каждый узел — **одновременно и клиент, и часть DHT**. Выделенных чат-серверов не существует. Сообщения никогда не пишутся в DHT — DHT нужен только чтобы найти `multiaddr` пира по его `PeerId`.

### 2. Поиск собеседника на разных континентах

Чтобы два узла из разных сетей нашли друг друга, нужны **bootstrap-адреса** (точки входа в DHT, аналог torrent-tracker). Любой желающий может поднять свой bootstrap — это не «центральный сервер чата», а просто публичный `libp2p`-узел.

Источники bootstrap-адресов (все опциональны, склеиваются и дедуплицируются):

1. **Вшитые в бинарь** (`BUILTIN_VOID_BOOTSTRAP` в `src/main.rs`, или флагом сборки `VOID_BUILTIN_BOOTSTRAP`).
2. **HTTP(S) список** (`VOID_BOOTSTRAP_URL` или `VOID_BOOTSTRAP_PUBLIC_LIST_URL`) — текстовый файл с одной multiaddr на строку.
3. **Переменная окружения** `VOID_BOOTSTRAP` — адреса через запятую.
4. **Файл `void-bootstrap.txt`** рядом с бинарём — одна multiaddr на строку, `#` — комментарий.
5. **UI** — боковая панель **«VOID BOOTSTRAP (DHT)»** → правка текста → **«Сохранить и применить»** (без перезапуска).

```powershell
# Пример PowerShell
$env:VOID_BOOTSTRAP = "/dnsaddr/example.com/tcp/4001/p2p/12D3KooW..."
cargo run
```

Также можно подключиться напрямую: кнопка **«ПОДКЛЮЧИТЬ»** принимает полный `multiaddr`, `IP` или `IP:PORT` — удобно для первого запуска внутри доверенного круга.

### 3. Сквозное шифрование (`src/crypto.rs`)

| Этап | Алгоритм |
|------|---------|
| Handshake | **Noise IK** — статическая аутентификация обеих сторон |
| Ratchet | **Double Ratchet** (symmetric + DH ratchet) |
| KDF | **BLAKE2b-512** |
| AEAD | **ChaCha20-Poly1305** |
| DH | **X25519** (`x25519-dalek`) |
| Защита памяти | `zeroize` (затирание ключей в ОЗУ при Drop) |
| Skipped keys | до **100** out-of-order сообщений (важно для P2P с задержками) |

Каждое сообщение зашифровано своим одноразовым `message_key`. Компрометация одного ключа **не раскрывает** ни прошлые, ни будущие сообщения.

### 4. Локальное хранилище

| Файл | Что внутри | Защита |
|------|-----------|--------|
| `void.key` | 32 байта — ключ AES-256-GCM | сырым на диске, права ОС |
| `vault.bin` | nickname, `StaticSecret`, адресная книга | AES-256-GCM |

Запись — через `vault.bin.tmp` + атомарный `rename`, чтобы сбой посередине не оставил усечённый vault. Есть резервная копия `vault.bin.bak`.

> ⚠️ **Никогда не передавайте `void.key` и `vault.bin` третьим лицам** — это эквивалент всего вашего мессенджера.

---

## Стек технологий

- **Язык:** Rust 2021
- **Сеть:** [`libp2p`](https://libp2p.io/) 0.56 (TCP, QUIC, Noise, Yamux, mDNS, Kademlia, Relay, DCUtR, AutoNAT, UPnP, Identify, Ping, request-response)
- **Рантайм:** `tokio` 1.x
- **UI:** [`eframe`/`egui`](https://github.com/emilk/egui) 0.29 — тёмная тема, glassmorphism, собственные идентиконы-аватары
- **Криптография:** `x25519-dalek`, `chacha20poly1305`, `blake2`, `aes-gcm`, `zeroize`
- **Сериализация:** `serde`, `serde_json`, `bincode`
- **HTTP (bootstrap list):** `reqwest` (rustls)

---

## Установка и запуск

### Требования
- **Rust** ≥ 1.75 (`stable`), установленный через [`rustup`](https://rustup.rs/).
- Для Linux дополнительно могут понадобиться системные библиотеки egui: `libxcb`, `libxkbcommon`, `libwayland-dev`.

### Сборка из исходников

```bash
git clone https://github.com/<you>/p2p-messenger.git
cd p2p-messenger
cargo run --release
```

При первом запуске в каталоге запуска создадутся `void.key` и `vault.bin`. Ник автоматически сгенерируется вида `User_1A2B`, после чего его можно поменять прямо в UI.

### Подключение к существующей сети

1. Получите у друга его `multiaddr` (в приложении он показан в панели «Свои адреса») — например:
   ```
   /ip4/157.22.192.234/tcp/4001/p2p/12D3KooWGQjWMK6Rqcoej4hdCNtcqyYwYzvEnyPdghxp6FtniUEU
   ```
2. Вставьте его в поле **«ПОДКЛЮЧИТЬ»** или в `void-bootstrap.txt`.
3. После handshake он появится в списке контактов — пишите.

---

## Конфигурация

| Переменная окружения | Назначение |
|----------------------|-----------|
| `VOID_BOOTSTRAP` | Список multiaddr через запятую |
| `VOID_BOOTSTRAP_URL` | URL к текстовому файлу со списком seed |
| `VOID_SKIP_PUBLIC_BOOTSTRAP_LIST` | Отключить вшитый `VOID_BOOTSTRAP_PUBLIC_LIST_URL` |
| `VOID_BUILTIN_BOOTSTRAP` | (compile-time) вшить seed прямо в бинарь |
| `RUST_LOG` | Уровень логов (`info`, `debug`, `trace`) |

---

## Развёртывание своей инфраструктуры

VOID работает без какой-либо инфраструктуры, но **собственные bootstrap/relay-узлы** сильно ускоряют поиск собеседников и прохождение NAT. Особенно хорошо для этого подходят **Raspberry Pi**: даже на Pi 3 роль Relay + Kademlia потребляет 5–10% CPU и ~150 МБ RAM, а 5–10 штук в разных сетях образуют отказоустойчивый кластер.

Подробный разбор железа, пропускной способности и тонкостей — см. [`info`](./info).

---

## Статус проекта

**Alpha.** Ядро (P2P, E2EE, DHT, relay, UI) работает, но API и формат `vault.bin` ещё могут меняться без обратной совместимости. Идеи, issues и PR — приветствуются.

### Что уже есть
- [x] Прямой P2P обмен через `libp2p`
- [x] Double Ratchet + Noise IK
- [x] Kademlia DHT `/void/kad/1.0.0`
- [x] NAT Traversal (Relay v2, DCUtR, UPnP, AutoNAT)
- [x] Зашифрованный vault, адресная книга
- [x] Приватные чаты + глобальная комната
- [x] Умный ретрай через DHT-lookup
- [x] Тёмный UI на egui с аватарами-идентиконами

### Планы
- [ ] Передача файлов по отдельному sub-протоколу с rate-limit на relay
- [ ] Голосовые сообщения
- [ ] Группы с общим Double Ratchet (MLS-подобно)
- [ ] Мобильные сборки
- [ ] Подписанные релизы + reproducible builds

---

## Безопасность

Если вы нашли уязвимость — **не открывайте публичный issue**. Свяжитесь приватно (контакт в профиле автора) и дайте немного времени на фикс. Критические баги с доказательством эксплуатации — в приоритете.

⚠️ Проект в alpha и **не прошёл внешний аудит криптографии**. Не используйте VOID для защиты жизни или свободы людей.

---

## Лицензия

Уточняется. До появления `LICENSE` в корне репозитория исходники предоставляются «как есть», без каких-либо гарантий.

---

<div align="center">

**Made with Rust 🦀 and a lot of `zeroize()`**

</div>
