# CLI команды и влияние на подсистемы (v0.1)

Подсистемы:

- **node** — runtime узла (процесс, state dir, control socket, lifecycle).
- **dht** — DHT runtime/namespace операции.
- **transport** — listen/connect endpoint-операции и transport-конфиг.

## Матрица влияния

| CLI команда | Node | DHT | Transport | Комментарий |
|---|:---:|:---:|:---:|---|
| `dsn config locate` | ✅ | ❌ | ❌ | Только поиск пути конфига. |
| `dsn config init [path]` | ✅ | ✅ | ✅ | Создаёт базовый конфиг для всех подсистем. |
| `dsn config validate [path]` | ✅ | ✅ | ✅ | Валидирует весь конфиг (`node`, address filters, transport endpoints). |
| `dsn config fix [path]` | ✅ | ✅ | ✅ | Пытается исправить конфиг (в т.ч. identity.id), затем валидирует целиком. |
| `dsn config keygen [-t ed25519]` | ✅ | ✅ | ✅ | Обновляет identity-ключи, косвенно влияет на node/dht/transport идентичность. |
| `dsn config show` | ✅ | ✅ | ✅ | Показывает весь конфиг, без изменения состояния. |
| `dsn config get <parameter>` | ✅ | ✅ | ✅ | Чтение параметра конфига. |
| `dsn config set [--force] <parameter> <value>` | ✅ | ✅ | ✅ | Запись параметра; по умолчанию с валидацией всего конфига. |
| `dsn config del [--force] <parameter>` | ✅ | ✅ | ✅ | Удаление параметра; по умолчанию с валидацией всего конфига. |
| `dsn node up [--state-dir ...]` | ✅ | ✅ | ✅ | Старт node runtime; поднимает фоновые циклы, включая DHT publication/rekey/ping. |
| `dsn node down [--state-dir ...]` | ✅ | ❌ | ❌ | Остановка runtime через node state/control channel. |
| `dsn node status [--state-dir ...]` | ✅ | ⚠️ | ⚠️ | Сводный runtime status узла; DHT/transport косвенно через статистику. |
| `dsn node run [--state-dir ...]` *(hidden)* | ✅ | ✅ | ✅ | Внутренний режим запуска node runtime. |
| `dsn transport listen <transport>` | ⚠️ | ❌ | ✅ | Настройка/использование транспортного listen endpoint. |
| `dsn transport connect <transport>` | ⚠️ | ❌ | ✅ | Точечное transport-подключение. |
| `dsn dht namespaces` | ❌ | ✅ | ❌ | Вывод поддерживаемых DHT namespace. |
| `dsn dht main my` | ❌ | ✅ | ❌ | Операция в main namespace. |
| `dsn dht ip4 on/off/status/get ...` | ⚠️ | ✅ | ⚠️ | DHT-операции для IPv4 namespace; адреса проходят config-фильтры. |
| `dsn dht ip6 on/off/status/get ...` | ⚠️ | ✅ | ⚠️ | DHT-операции для IPv6 namespace; адреса проходят config-фильтры. |
| `dsn dht name check/get/take/challenge ...` | ⚠️ | ✅ | ❌ | Управление name namespace и challenge-потоком. |

> Примечание: метка ⚠️ означает косвенное влияние (через runtime/конфиг), а не прямое управление подсистемой.
