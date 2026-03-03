# Wire protocol v0.1

Документ фиксирует бинарный frame-формат и базовые правила обработки пакетов.

## 1. Frame envelope

Каждое сообщение передаётся в виде:

1. `frame_len` (`u32`, BE) — длина полезной части после поля длины.
2. `frame` (`frame_len` bytes)

Внутри `frame`:

- `version` (`u8`) — версия wire протокола, для v0.1 = `1`.
- `traffic_class` (`u8`) — `0=control`, `1=net`, `2=data`.
- `msg_type` (`u16`) — тип сообщения протокола.
- `flags` (`u16`) — битовые флаги сообщения.
- `key_id` (`u32`) — идентификатор активного сессионного ключа.
- `seq` (`u64`) — монотонный счётчик в рамках `key_id`.
- `request_id` (`u64`) — корреляция request/response.
- `payload_len` (`u32`) — длина payload.
- `payload` (`payload_len` bytes)

## 2. Ограничения и валидация

- `frame_len` не может превышать **1 MiB + 4 KiB**.
- `payload_len` не может превышать **1 MiB**.
- `payload_len` должен точно соответствовать фактической длине payload.
- Неизвестный `version` => reject.
- Неизвестный `traffic_class` => reject.

## 3. Шифрование и AAD

Для v0.1 используется:

- KEM: **ML-KEM-768** (для установления/обновления сессионных секретов)
- AEAD: **ChaCha20-Poly1305** (для frame payload)

AAD (associated data) обязательно включает минимум:

- `version`
- `traffic_class`
- `msg_type`
- `flags`
- `key_id`
- `seq`
- `request_id`

## 4. Anti-replay

- Пара `key_id + seq` используется для защиты от replay.
- Приёмник обязан хранить replay-window per session/per direction.
- `seq` должен быть строго возрастающим (допускается ограниченное окно для reordering только если это явно реализовано).

## 5. RTT и единицы времени

- Все значения RTT в ответах control-plane кодируются в **микросекундах** (`u64`).

## 6. PoW-проверка

Для сообщений, требующих proof-of-work:

- Узел объявляет `pow_difficulty` (`u8`).
- Клиент подбирает `nonce`.
- Проверка:

```text
leading_zero_bits(blake3(challenge_context || nonce)) >= pow_difficulty
```

`challenge_context` должен включать как минимум:

- `remote_node_id`
- `request_id` (`u64`)
- `pow_difficulty`
- ограничитель времени/эпоху (anti-precompute)

## 7. METRICS policy

- Для `METRICS_REQUEST/METRICS_RESPONSE` в v0.1 применяется только **rate limit**.
- PoW для публичных метрик не требуется.
