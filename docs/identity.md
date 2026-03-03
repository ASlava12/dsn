# Identity и выбор overlay-адресов v0.1

Документ фиксирует формат identity и правила отбора IP-адресов для публикации в overlay.

## 1. Структуры identity

## 1.1 PrivateIdentity

- `algo` — алгоритм подписи (`ed25519`, `falcon512` в будущем).
- `public_key` — публичный ключ.
- `private_key` — приватный ключ.
- `id` — `blake3(public_key)` длиной 256 бит (64 hex-символа).
- `ip4_nonce` — 32 случайных бита.
- `ip6_nonce` — 128 случайных бит.
- `ip4` — публикуемый IPv4 адрес.
- `ip6` — публикуемый IPv6 адрес.
- `name` — строка до 32 символов.
- `name_nonce` — часть, влияющая на `difficulty` имени.

## 1.2 PublicIdentity

- `algo`
- `public_key`
- `id`
- `ip4_nonce`
- `ip6_nonce`
- `ip4`
- `ip6`
- `name`
- `name_nonce`
- `peers` — до 20 пиров для достижимости ноды.
- `sign` — подпись всех полей выше (порядок `peers` значим).
- `publication_date` — время публикации, используется совместно с TTL namespace.

## 2. Режимы выбора адресов

Поддерживаемые режимы (конфигурационный enum):

- `public_only` — default, только публичные адреса.
- `gray_only` — только gray-адреса.
- `all` — все адреса, кроме hard-deny.

Для UX/документации им соответствуют формулировки:

- **only public** → `public_only`.
- **only gray** → `gray_only`.
- **all** → `all`.

## 3. Что считается gray (по RFC)

### IPv4 gray ranges

- RFC1918:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- CGNAT:
  - `100.64.0.0/10`

### IPv6 gray range

- ULA: `fd00::/8`

## 4. Hard deny

Адреса loopback исключаются всегда.

Дополнительно (текущая реализация v0.1) также запрещены:

- unspecified
- multicast
- link-local

## 5. Конфигурация include/exclude netlist

```yaml
ip4_include_net: [ ...CIDR... ]
ip4_exclude_net: [ ...CIDR... ]
ip6_include_net: [ ...CIDR... ]
ip6_exclude_net: [ ...CIDR... ]
```

- Списки пусты по умолчанию.
- CIDR валидируются при загрузке конфигурации.

## 6. Порядок применения фильтров

Обязательный порядок принятия решения (`allow/deny`):

1. `loopback`/hard-deny exclude.
2. `exclude_net`.
3. `include_net` (только если include-список не пуст).
4. `address_mode` (`public_only` / `gray_only` / `all`).

Результат фильтрации должен быть детерминированным и пригодным для debug-логирования.

## 7. Публикация и конфликты

- Перед публикацией адреса узел проверяет занятость в DHT namespace.
- При конфликте публикация отклоняется до выбора нового nonce/адреса.
