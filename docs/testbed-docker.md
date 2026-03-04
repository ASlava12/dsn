# Docker testbed (v0.1 e2e)

Минимальный стенд для e2e-проверок:
- `bootstrap` (seed),
- `node2`,
- `relay`,
- `checker` (прогон проверок).

## Быстрый запуск

```bash
make testbed-up
make testbed-check
make testbed-down
```

Или одной командой (поднять + прогнать проверки):

```bash
make testbed
```

## Что проверяется

`checker` выполняет:
1. Проверку доступности daemon/admin socket через `dsn node status` для всех 3 нод.
2. `dsn dht namespaces` на `node2`.
3. Тесты `dsn-core`:
   - `two_nodes_exchange_ping_over_control` (handshake + ping),
   - `find_node_request_goes_over_network_with_retries_timeouts_manager` (DHT find_node),
   - `route_send_node_goes_via_one_relay_and_updates_ttl_cache` (route через relay),
   - `rekey_triggers_by_bytes_or_age` (rekey на низком пороге в тестовом policy).

## Файлы

- `testbed/docker/docker-compose.yml`
- `testbed/docker/scripts/node-start.sh`
- `testbed/docker/scripts/testbed-check.sh`
- `Makefile` (`testbed-up`, `testbed-check`, `testbed-down`, `testbed`)
