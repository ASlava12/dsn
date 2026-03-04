# Addressing and filtering v0.1

Документ фиксирует режимы адресации и pipeline фильтрации IP-адресов в overlay.

## 1. Address mode

```yaml
address_mode:
  public_only   # default
  gray_only
  all
```

Человекочитаемые синонимы режимов:

- `only public` -> `public_only`
- `only gray` -> `gray_only`
- `all` -> `all`

## 2. Gray address definition

### IPv4 gray ranges

- RFC1918:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- CGNAT:
  - `100.64.0.0/10`

### IPv6 gray range

- ULA: `fd00::/8`

## 3. Hard deny ranges (always denied)

Независимо от `address_mode` всегда запрещены:

- loopback
- unspecified
- multicast
- link-local

## 4. Дополнительная фильтрация

```yaml
ip4_include_net: [CIDR]
ip4_exclude_net: [CIDR]
ip6_include_net: [CIDR]
ip6_exclude_net: [CIDR]
```

## 5. Filtering pipeline (обязательный порядок)

1. **hard deny** (включая loopback)
2. **exclude**
3. **include** (если список непустой)
4. **address_mode**

Решение `allow/deny` должно быть детерминированным и логироваться в debug trace.

## 6. Identity и публикация

- `PublicIdentity` публикуется в namespace по правилам TTL верхнего уровня.
- При использовании `use_ip4/use_ip6` адрес должен проходить pipeline выше.
- Для namespace lookup latencies рекомендуется хранить RTT в **микросекундах** (`u64`, µs).

## 7. Конфликт адресов

- Перед публикацией адреса узел проверяет занятость в соответствующем namespace.
- При конфликте публикация отклоняется до выбора нового nonce/адреса.
