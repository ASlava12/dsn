# Session and crypto lifecycle v0.1

Документ фиксирует жизненный цикл сессии, условия rekey и правила хранения.

## 1. Криптопримитивы v0.1

- KEM: **ML-KEM-768**
- AEAD: **ChaCha20-Poly1305**
- Подпись identity: **ed25519** (falcon512 — future)

## 2. Состояние сессии

Минимальные поля session state:

- `session_id` (`[u8; 32]`)
- `peer_node_id` (`[u8; 32]`)
- `active_key_id` (`u32`)
- `created_at`
- `last_rekey_at`
- `bytes_sent_on_active_key` (`u64`)
- `last_ping_ok_at`
- `rtt_us_last5` (`[u64; <=5]`, µs)

## 3. Rekey условия (обязательные)

Новый ключ инициируется, если выполняется хотя бы одно:

1. `bytes_sent_on_active_key >= 64 GiB`
2. `key_age >= 24h`

Дополнительно:

- Hard TTL ключа: **36h**
- При превышении hard TTL ключ без успешного обновления считается недействительным.

## 4. Rekey протокол

Двухфазный процесс:

1. `SESSION_CHANGE_REQUEST` с предложением нового `key_id` и криптоматериалом.
2. `SESSION_CHANGE_ACK` на старом ключе.
3. Переключение на новый `key_id` после ACK.
4. `grace window` разрешает приём ограниченного числа сообщений на старом ключе для мягкого перехода.

## 5. Тайм-ауты доступности

- `ping_interval` настраиваемый (дефолт: 30s).
- `session_timeout` настраиваемый (пример: 300s).
- При отсутствии успешного ping/pong дольше `session_timeout` сессия инвалидируется.

## 6. Session storage backends

Поддерживаемые режимы:

- `memory` (default)
- `file`
- `redis`

Для `redis` обязателен отдельный namespace/prefix per node, чтобы избежать коллизий ключей:

```text
dsn:v0:session:<local_node_id>:<peer_node_id>:...
```

## 7. Безопасность replay

- `key_id + seq` обязательно участвуют в AAD.
- Для каждого направления хранится последний подтверждённый `seq` + replay-window.
