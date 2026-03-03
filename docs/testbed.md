# Testbed plan v0.1

Документ фиксирует минимальный стенд и проверочные сценарии для transport/mux/session/addressing.

## 1. Топология

Минимум 3 узла:

- `node-a` (initiator)
- `node-b` (relay/counterparty)
- `node-c` (destination)

Режимы прогонов:

1. SingleConn + Mux
2. MultiConn (control/net/data отдельными соединениями)

## 2. Базовые тестовые профили

### 2.1 Transport smoke

- Проверка connect/listen для `tcp`, `udp`, `tls`, `quic`, `ws`, `wss`, `unix`.
- Валидация frame limits:
  - payload <= 1 MiB проходит
  - payload > 1 MiB отклоняется

### 2.2 Mux priority

- Создать конкуренцию трафика `control/net/data`.
- Под нагрузкой `data` подтвердить приоритетную доставку `control`.

### 2.3 Session lifecycle

- Проверка rekey по порогу `64 GiB` (ускоренный тест через уменьшенный тестовый порог).
- Проверка rekey по возрасту ключа (`>=24h`, в тесте через time control).
- Проверка hard TTL `36h`.
- Проверка grace window.

### 2.4 Anti-replay

- Повтор отправки frame с тем же `key_id + seq` должен отклоняться.
- Out-of-window `seq` должен отклоняться.

### 2.5 PoW validation

- Проверка формулы:

```text
leading_zero_bits(blake3(challenge_context || nonce)) >= difficulty
```

- Запросы с неверным nonce должны отклоняться.

### 2.6 Metrics access

- `METRICS_REQUEST` обслуживается без PoW.
- Включён rate-limit, превышение лимита приводит к отказу/замедлению согласно политике.

### 2.7 Address filtering

Покрыть pipeline:

1. hard deny
2. address_mode
3. include
4. exclude

Проверить все режимы:

- `public_only` (default)
- `gray_only`
- `all`

## 3. Типы и единицы в тестах

- `request_id` — `u64`
- RTT — `u64` в **микросекундах**

## 4. Критерии приёмки v0.1

- Единый wire frame совместим в single/multi режимах.
- Rekey отрабатывает по обоим триггерам + hard TTL.
- Anti-replay работает на `key_id + seq`.
- PoW валидация детерминированна.
- Address filtering pipeline выполняется в фиксированном порядке.


## 5. In-process testbed (3–5 nodes)

Для CI используется быстрый in-process сценарий (`dsn-core/tests/testbed_in_process.rs`) без реального сетевого развёртывания.

Сценарии:

- bootstrap + handshake
- ping mesh
- store/find
- rekey (пониженный порог в тесте)
- address publish

Целевой SLA: стабильное выполнение < 30s на типичном CI runner.
