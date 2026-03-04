# Wire protocol v0.1

Документ фиксирует бинарный frame-формат и правила обработки пакетов.

## 1. Frame envelope

Каждое сообщение передаётся в виде:

1. `frame_len` (`u32`, BE) — длина полезной части после поля длины.
2. `frame` (`frame_len` bytes).

Внутри `frame`:

- `version` (`u8`) — версия wire протокола, для v0.1 = `1`.
- `traffic_class` (`u8`) — `0=control`, `1=net`, `2=data`.
- `msg_type` (`u16`) — тип сообщения протокола.
- `flags` (`u16`) — битовые флаги сообщения.
- `key_id` (`u32`) — идентификатор активного сессионного ключа.
- `seq` (`u64`) — монотонный счётчик в рамках `key_id`.
- `request_id` (`u64`) — корреляция request/response.
- `payload_len` (`u32`) — длина payload.
- `payload` (`payload_len` bytes).

## 2. Ограничения и валидация

- `frame_len` не может превышать **1 MiB + 4 KiB**.
- `payload_len` не может превышать **1 MiB**.
- `payload_len` должен точно соответствовать фактической длине payload.
- Неизвестный `version` => reject.
- Неизвестный `traffic_class` => reject.

## 3. Traffic class: семантика, приоритет, fairness

### 3.1 Семантика классов

- `control` — служебные сообщения (handshake, ping/pong, session/rekey, ошибки).
- `net` — маршрутизация, DHT и overlay-сигнализация.
- `data` — прикладной трафик.

### 3.2 Приоритет

При перегрузке приоритет обработки и отправки: `control > net > data`.

- `control` не должен блокироваться `data`-очередями.
- `net` может вытеснять `data`, но не `control`.

### 3.3 Fairness и backpressure

- Fairness реализуется между классами через раздельные очереди и weighted scheduling.
- Backpressure применяется в первую очередь к `data`, затем к `net`.
- Для `control` допускается отдельный «защищённый» бюджет, чтобы поддерживать liveness (ping/rekey/ack).

## 4. Flags

`flags` — `u16` битовая маска.

Минимальный набор v0.1:

- `REQ` — сообщение является request.
- `RESP` — сообщение является response.
- `ACK` — подтверждение (в т.ч. handshake/rekey ack).
- `ERR` — сообщение об ошибке.
- `COMPRESSED` — payload сжат (используется только при явно согласованной поддержке).
- `RESERVED` — биты зарезервированы для расширений, при приёме неизвестных битов: ignore + логирование.

Правила:

- `REQ` и `RESP` не могут быть установлены одновременно.
- `ACK` может сочетаться с `RESP`.
- `ERR` не должен сочетаться с обычным `data` payload-форматом без error-body.

## 5. Шифрование и AAD

Для v0.1 используется:

- KEM: **ML-KEM-768** (для установления/обновления сессионных секретов).
- AEAD: **ChaCha20-Poly1305** (для frame payload).

AAD (associated data) обязательно включает минимум:

- `version`
- `traffic_class`
- `msg_type`
- `flags`
- `key_id`
- `seq`
- `request_id`

## 6. `seq` и anti-replay

- Пара `key_id + seq` используется для защиты от replay.
- `seq` монотонно возрастает **per `key_id` и per direction**.
- При смене `key_id` счётчик `seq` начинается заново для нового ключа.
- Приёмник хранит replay-window per session/per direction и отвергает:
  - уже виденный `seq`;
  - `seq` вне окна.

Рекомендуемая модель окна:

- хранить `max_seen_seq`;
- хранить битовую маску последних `N` позиций (например `N=64/128`);
- принимать только новые номера в пределах окна, помечать принятые и отбрасывать повторы.

## 7. RTT и единицы времени

- Все значения RTT в ответах control-plane кодируются в **микросекундах** (`u64`).

## 8. PoW-проверка

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

## 9. METRICS policy

- Для `METRICS_REQUEST/METRICS_RESPONSE` в v0.1 применяется только **rate limit**.
- PoW для публичных метрик не требуется.
