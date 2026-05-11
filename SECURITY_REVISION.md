# Ревизия безопасности VOID (p2p-messenger)

**Дата составления:** 2026-05-09  
**Повторный аудит:** 2026-05-11 — см. §7 ниже.  
**Охват:** исходники `src/` (без полного аудита `Cargo.lock`/CVE по зависимостям и всего стека libp2p).  
**Цель:** инвентаризация уязвимых и рискованных точек проекта.

---

## 1. Критичные / высокие риски

| # | Область | Файлы / узел | Суть |
|---|---------|--------------|------|
| 1 | Протокол чата: Plain | `main.rs`, `V1Packet` | **Исправлено:** вариант `Plain` удалён; принимается только зашифрованный чат (`Encrypted`) + служебные `Hello`/`Ack`. |
| 2 | Привязка E2EE к транспортной личности | `main.rs` (Hello), `crypto.rs` | **Исправлено:** в `Hello` добавлена подпись Ed25519 (libp2p `Keypair`) над привязкой `PeerId` отправителя/получателя и X25519-ключей; без валидной подписи хендшейк отвергается. |
| 3 | Парсинг после E2EE | `main.rs`, `serde_json` | **Исправлено:** после дешифрования — лимит размера JSON и длины полей `ChatMessage` (`parse_decrypted_chat_json`). |
| 4 | Bootstrap HTTP(S) | `main.rs`, `fetch_void_bootstrap_list`, `reqwest` | **Исправлено:** лимит размера тела ответа; allowlist `VOID_BOOTSTRAP_TRUSTED_HOSTS`. **Дополнительно:** `VOID_BOOTSTRAP_TLS_LEAF_SHA256` — pin SHA-256 DER листового сертификата после проверки CA (webpki-roots). |

---

## 2. Средние риски

| # | Область | Файлы / узел | Суть |
|---|---------|--------------|------|
| 5 | Double Ratchet | `crypto.rs`, `SecureSession` | **Частично:** лимит `skipped_keys` поднят до **4096** (меньше ложных срывов при reordering); модель DR / HKDF и внешний обзор — без изменений. |
| 6 | Dial без PeerId | `main.rs`, `parse_seed_input` | **Частично:** при входе по IP без `/p2p/` в UI уходит предупреждение; полный multiaddr по-прежнему предпочтителен. |
| 7 | Vault: JSON после AES | `main.rs`, `Storage::load` | **Исправлено:** лимит размера plaintext перед JSON; поле **`format_version`** (поддерживается только `1`). |
| 8 | Секреты в RAM | `main.rs`, UI unlock | **Частично:** при ошибках создания/миграции vault пароль в форме зероизируется; режим «заблокировать» и полный отказ от `String` для пароля — вне объёма. |
| 9 | Файлы: метаданные оффера | `file_transfer.rs`, `/void/file/1.0.0` | **Частично:** `validate_file_offer` (имя, размер, согласованность чанков) до приёма; **E2EE на метаданные оффера** не внедрялся. |
| 10 | Паники на старте сети | `main.rs`, `build_void_swarm`, `listen_on` | **Исправлено:** сборка swarm и критичные `listen_on` через `Result` + сообщение в UI / `return` из сетевого таска при фатальной ошибке. |
| 11 | Отправка чата | `main.rs`, `SendMessage` | **Исправлено:** `serde_json::to_vec` без `unwrap`; при ошибке — статус в UI и пропуск шифрования. |

---

## 3. Низкие / эксплуатационные

| # | Область | Суть |
|---|---------|------|
| 12 | mDNS | **Исправлено:** при переменной окружения `VOID_DISABLE_MDNS` mDNS не поднимается (`Toggle` в swarm); по умолчанию как раньше. |
| 13 | Элевация файрвола | **Исправлено:** netsh / PowerShell UAC / `sudo` выполняются **только** при `VOID_APPLY_FIREWALL_RULE=1`; иначе одна подсказка в консоль и ручная настройка портов. |
| 14 | `void-bootstrap.txt`, env | **Частично:** опциональная проверка Ed25519 — `VOID_BOOTSTRAP_SIGNING_PUB_HEX` + файл `<stem>.sig` (64 B) для `void-bootstrap.txt`; для HTTP при том же pubkey — `VOID_BOOTSTRAP_URL_SIG_HEX` (128 hex). Без pubkey поведение как раньше. |
| 15 | Консольные логи | **Исправлено:** `println!/eprintln!` в `main.rs` заменены на `tracing::debug!` / `warn!`; стартовые подсказки (файрвол, bootstrap, баннер чата) — `info!` (видны при `RUST_LOG=warn` по умолчанию). |

---

## 4. Что уже сделано хорошо (кратко)

- Транспорт **Noise** + отдельный **E2EE** слой (ChaCha20-Poly1305 и кастомный ratchet после статического обмена в Hello).
- **Vault**: AES-256-GCM; мастер в **`void.key`** с обёрткой **Argon2id + AES-GCM** и экран пароля на старте.
- Явная **зероизация** чувствительных полей и `skipped_keys` в `SecureSession` при `Drop`.
- **Чанки файлов** после установления DR шифруются тем же сеансом — содержимое лучше защищено от оператора relay, чем сырой транспортный поток.

---

## 5. Рекомендуемые меры (по приоритету)

1. ~~Отключить или флагировать приём **`V1Packet::Plain`**~~ — сделано (вариант удалён).
2. ~~**Связать** `Hello` с транспортной личностью~~ — сделано (подпись libp2p identity на содержимое Hello).
3. ~~Жёсткие **лимиты** после `serde_json`~~ — сделано (`parse_decrypted_chat_json`).
4. ~~Bootstrap: лимит тела~~ — сделано; ~~опциональный pin листового TLS-сертификата~~ — `VOID_BOOTSTRAP_TLS_LEAF_SHA256` (rustls + webpki-roots).
5. Заказать **независимый криптоаудит** связки Noise + приложение-хендшейк + Double Ratchet.

---

## 6. Дальнейшие шаги (опционально)

- Прогон **`cargo audit`** / **`cargo deny`** по зависимостям.
- Синхронизация с файлом **`SECURITY_REPORT.md`**, если он ведётся параллельно в этом репозитории.

---

## 7. Повторный аудит (2026-05-11)

**Охват:** статический разбор `src/main.rs`, `src/crypto.rs`, `src/file_transfer.rs`, `src/ui.rs`; grep по `unwrap`/`Command`/`serde_json`/протоколу; сборка и тесты проходят. **Не входило:** fuzzing, анализ `Cargo.lock`/CVE (в среде нет `cargo-audit`), полный аудит libp2p.

### 7.1 Подтверждённые контролы (регрессия не выявлена)

- Чат `/void/chat`: нет `V1Packet::Plain`; после DR — `parse_decrypted_chat_json` с лимитами.
- `Hello`: `transport_sig` + `verify_hello_transport_binding` на приёме (request и response).
- Bootstrap HTTP: лимит тела, опционально `VOID_BOOTSTRAP_TRUSTED_HOSTS`; опционально Ed25519 для файла/URL (`VOID_BOOTSTRAP_SIGNING_PUB_HEX`, `.sig`, `VOID_BOOTSTRAP_URL_SIG_HEX`).
- Vault: лимит plaintext JSON, `format_version == 1`.
- Swarm: `build_void_swarm` / критичные `listen_on` без паники на ожидаемых ошибках; mDNS через `Toggle` + `VOID_DISABLE_MDNS`.
- Файрвол: только при `VOID_APPLY_FIREWALL_RULE=1`.
- Отправка чата: `serde_json::to_vec` без `unwrap`; оффер файла — `validate_file_offer`.

### 7.2 Остаточные и смежные риски (по убыванию важности)

1. **Криптография приложения:** кастомный Double Ratchet / HKDF — по-прежнему нужен **независимый криптообзор** (п. 5 раздела 5).
2. ~~**Привязка Hello к транспорту (hashed PeerId)**~~ — **смягчено:** в `Hello` добавлено поле `transport_pubkey_pb` (protobuf `PublicKey`), если `PeerId` не identity-multihash; проверка `PeerId::from_public_key` + подпись.
3. ~~**TLS bootstrap pin**~~ — реализовано: `VOID_BOOTSTRAP_TLS_LEAF_SHA256` (SHA-256 DER листа, после проверки цепочки CA).
4. ~~**`/void/file/1.0.0`**~~ — `validate_inbound_file_packet`, лимиты `Reject.reason` / `Chunk`; исходящий reject обрезается.
5. ~~**Vault JSON**~~ — лимиты на `nickname`, `keypair_bytes`, число контактов, длины полей и `addrs`.
6. ~~**Логи**~~ — см. п. 15 в таблице §3.
7. ~~**UI unlock unwrap**~~ — убрано: `kind` клонируется до панели, без `unwrap` на `pending_unlock`.
8. **`crypto.rs`:** остаются `unwrap`/`expect` на внутренних путях (HKDF, тесты) — не сетевой ввод.

### 7.3 Рекомендации после повторного аудита

- Установить **`cargo-audit`** / **`cargo-deny`** в CI и гонять по расписанию.
- Для файлового RR: при необходимости — верхняя граница размера всего JSON-пакета до десериализации (сейчас — валидация после decode).
- Метаданные оффера файла по-прежнему не в E2EE-слое чата (архитектурно).
- Приоритет внешнего аудита: Noise + Hello-подпись + DR + модель угроз (relay, out-of-order).

---

*При существенных изменениях протокола или хранилища документ следует обновить.*
