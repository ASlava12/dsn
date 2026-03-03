# Docker testbed: LB + деградации

Этот стенд добавляет проверку сценариев с балансировщиком и сетевыми деградациями.

## Состав

- `node1..node3` — инстансы узла (через `dsn-cli node run`)
- `nginx` — входной TLS endpoint (`wss`)
- `haproxy` — L4 балансировщик между узлами
- `toxiproxy` — инъекция деградаций

Файлы:

- `testbed/docker/docker-compose.yml`
- `testbed/docker/nginx/nginx.conf`
- `testbed/docker/haproxy/haproxy.cfg`
- `testbed/docker/scripts/node-start.sh`

## Запуск

```bash
cd testbed/docker
docker compose up -d
```

## Сценарии

### 1) WSS за nginx

`nginx` слушает `:8443` с TLS и проксирует в `node1:8080`.

Проверка (пример):

```bash
dsn transport connect "wss://127.0.0.1:8443/chat?insecure=1"
```

Ожидаемое поведение:

- соединение устанавливается;
- control трафик продолжает обслуживаться при умеренной data-нагрузке (по приоритетам mux).

### 2) Latency 200ms

```bash
curl -s -XPOST localhost:8474/proxies/node1_data/toxics \
  -H 'Content-Type: application/json' \
  -d '{"name":"latency_200ms","type":"latency","stream":"downstream","attributes":{"latency":200,"jitter":10}}'
```

Ожидаемое поведение:

- RTT растёт;
- сессия не инвалидируется, если ping/pong укладывается в `session.timeout`.

### 3) Loss 5%

```bash
curl -s -XPOST localhost:8474/proxies/node1_data/toxics \
  -H 'Content-Type: application/json' \
  -d '{"name":"loss_5pct","type":"limit_data","stream":"downstream","attributes":{"bytes":95}}'
```

Ожидаемое поведение:

- растут ретраи/потери на data-канале;
- control канал сохраняет работоспособность.

### 4) Падение data (MultiConn)

```bash
curl -s -XPOST localhost:8474/proxies/node1_data/toxics \
  -H 'Content-Type: application/json' \
  -d '{"name":"cut","type":"timeout","stream":"downstream","attributes":{"timeout":30000}}'
```

Ожидаемое поведение (по документации v0.1):

- падение data-соединения не рвёт control-соединение;
- ping/rekey/service-control продолжают работать.

## Очистка токсиков

```bash
curl -s -XDELETE localhost:8474/proxies/node1_data/toxics/latency_200ms
curl -s -XDELETE localhost:8474/proxies/node1_data/toxics/loss_5pct
curl -s -XDELETE localhost:8474/proxies/node1_data/toxics/cut
```

## Остановка

```bash
docker compose down -v
```


## Масштабирование до 20 нод

Теперь в `docker-compose.yml` есть сервис `node`, поэтому можно поднимать 20 экземпляров одной командой:

```bash
cd testbed/docker
docker compose up -d --scale node=20
```

- `node1..node3` остаются seed-нодами.
- `node`-экземпляры автоматически используют bootstrap на `node1..node3`.
- Пример статического конфига ноды: `testbed/docker/configs/node-dht-listen.toml`.


## Параметры рантайма в конфиге

Поддерживаются поля:

```yaml
node:
  state_dir: node-state
  control_socket: control.sock
```

- `state_dir` — директория runtime-состояния (`pid/status/control socket`),
- `control_socket` — путь сокета (абсолютный или относительный от `state_dir`).

CLI-команды `dsn node up/down/status/run` принимают `--state-dir` как override поверх конфига.
