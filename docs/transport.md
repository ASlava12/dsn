# Transport v0.1

Документ фиксирует транспортный слой DSN для версии v0.1.

## 1. Цели

- Единая транспортная модель поверх уже поддерживаемых endpoint-схем: `tcp/udp/tls/quic/ws/wss/h2/g2/unix`.
- Mux приоритезация трафика (`control/net/data`).
- Возможность как single-connection, так и multi-connection режима.

## 2. Endpoint схемы

Поддерживаются URL endpoint'ы:

- `tcp://host:port`
- `udp://host:port`
- `tls://host:port?...`
- `quic://host:port?...`
- `ws://host:port/path?...`
- `wss://host:port/path?...`
- `h2://host:port/path?...`
- `g2://host:port/path?...`
- `unix:///path/to/socket`

## 3. Режимы connection layout

### 3.1 Default (обязательный для v0.1)

**SingleConn + Mux**

- На peer устанавливается **одно** транспортное соединение.
- Внутри него работают 3 логических класса трафика.

### 3.2 Опциональный режим

**MultiConn**

- Допускается отдельное транспортное соединение на каждый класс:
  - `control`
  - `net`
  - `data`
- Реализация должна использовать тот же wire frame и те же правила безопасности.

## 4. Mux классы и приоритет

- `control` — highest priority (служебный трафик, ping/pong, DHT control messages, route/session control)
- `net` — medium priority (пакеты внутренних приложений/оверлей-протоколов)
- `data` — lowest priority (инкапсулированный IP payload, bulk data)

Рекомендуемая политика scheduler:

1. strict priority между классами,
2. внутри класса — FIFO,
3. при перегрузке сначала ограничивается `data`, затем `net`.

## 5. Общие лимиты v0.1

- Максимальный размер plaintext payload в одном frame: **1 MiB**.
- Максимальный размер ciphertext frame (после шифрования и заголовков): **1 MiB + 4 KiB**.
- Значения больше лимита должны отклоняться на receive path с инкрементом error-метрики.
- Для datagram transport рекомендуется soft MTU профилирование и сегментация на уровне протокола выше transport runtime.

## 6. Типы и единицы

- `request_id`: **`u64`**.
- RTT/latency метрики в control-plane: **микросекунды (`u64`, µs)**.
- `pow_difficulty`: `u8`.

## 7. Backpressure и отказоустойчивость

- Реализация обязана применять bounded очереди per class.
- При переполнении очередей:
  - для `data`: drop + сигнал в метрики,
  - для `net`: ограниченный retry,
  - для `control`: приоритетное прохождение, drop только в критическом случае.

## 8. Совместимость

- Wire формат и крипто-параметры для single/multi режима идентичны.
- Изменение transport режима не должно ломать семантику протокола верхнего уровня.
