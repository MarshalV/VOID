# VOID — каталог провода

Норматив семейства `/void/…`. По этим файлам можно написать второго участника или диспетчера, не читая клиент.

В норматив входит только то, что видно на проводе, и то, что узел обязан сделать с этими байтами. Не входят локальные решения клиента: хранилище ключей, оболочка окна, порт прослушивания клиента, тайминги повторного набора, журнал на диске.

Статус: **alpha**. Имена потоков ниже — те, что говорят текущие участники. Сдвиг байтов ломает совместимость; смена локального хранилища — нет.

Критерий этого каталога: по [`05-envelope.md`](05-envelope.md) сторонний автор объясняет, что диспетчер делает на `OfflineMailboxStore` и `OfflineMailboxQuery`, не открывая реализацию клиента.

| Файл | О чём |
|------|--------|
| [00-overview.md](00-overview.md) | Роли, потоки, модель угроз |
| [01-identity.md](01-identity.md) | `PeerId`, транспортный ключ, X25519 из Ed25519 |
| [02-hello.md](02-hello.md) | Bind v1/v2/v3, `caps`, свежесть |
| [03-session.md](03-session.md) | Double Ratchet, AAD, пропущенные ключи |
| [04-attachments.md](04-attachments.md) | `VfP1` / `VfC1`, `/void/file/1.0.0` |
| [05-envelope.md](05-envelope.md) | Конверт v3, prekey, Store / Query / Deliver |
| [06-discovery.md](06-discovery.md) | `/void/kad/1.0.0`, что нельзя класть в DHT |
| [07-rendezvous.md](07-rendezvous.md) | Hop reservation, circuit, `DialBack` |
| [08-seed.md](08-seed.md) | `/void-seed/v1` между диспетчерами |
| [09-onion.md](09-onion.md) | v1 и v2, дескриптор, что видит hop |
| [10-groups.md](10-groups.md) | Fan-out и подписанный состав (до MLS) |
| [vectors/README.md](vectors/README.md) | Известные ответы: Hello, ratchet, конверт, prekey, onion |

В каждом файле одна и та же таблица: **Наблюдатель / Видит / Не видит**.

Общие правила кодирования, если файл не говорит иное:

- Поток `/void/chat/1.0.0` и `/void/file/1.0.0` — libp2p request-response. Кадр чата: тело субстрима целиком (длину режет yamux). Схема одна — serde-enum `V1Packet`, внешне тегированный. Юнит-вариант `Ack` — строка `"Ack"`.
- Пока в Hello обеих сторон нет бита `HELLO_CAP_CBOR`, тело — JSON. Массивы байтов в JSON — числа `0..255`. Когда бит есть у обеих, тело — CBOR той же схемы: `Vec<u8>` — байтовая строка, `[u8; N]` — массив чисел.
- Приёмник (участник и диспетчер) читает оба вида. Порядок: content-type `56 43 01 01` (JSON) или `56 43 01 02` (CBOR), затем тело; иначе магия CBOR `d9 d9 f7` и тело без этих трёх байт; иначе первый байт `{`, `[`, `"` или пробел — JSON, любой другой — CBOR.
- На `/void/chat/1.0.0` запрос не длиннее 4 МиБ, ответ не длиннее 16 МиБ. Отдельно, на поле, а не на раздутый JSON: `ct` ≤ 256 КиБ, `ciphertext` ≤ 1 МиБ, конвертов в `OfflineMailboxStore` ≤ 64, в `OfflineMailboxDeliver` ≤ 1024.
- `/void/file/1.0.0` остаётся JSON.
- `PeerId` в JSON-строке — base58btc (как `Display` libp2p). В подписи и в бинарной склейке — байты `PeerId::to_bytes()` (multihash), без base58.
- `HKDF-SHA256(salt, ikm, info, L)` — RFC 5869: Extract(salt, ikm), затем Expand(info) на `L` байт. То же для SHA-512.
- AEAD везде, где не сказано иное, — ChaCha20-Poly1305 (RFC 8439): шифртекст — открытый текст и 16 байт тега.

Эталонный диспетчер: [MarshalV/bootstrap_node](https://github.com/MarshalV/bootstrap_node). Seed и ящик описаны здесь, даже если код диспетчера живёт в том репозитории.
