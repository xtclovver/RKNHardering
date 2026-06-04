[Русский](#руководство-по-участию-в-маркетплейсе) | [English](#marketplace-contributing-guide)

# Руководство по участию в маркетплейсе

## Что такое `.rkncheck`

Файл `.rkncheck` — это JSON-документ, описывающий профиль кастомных проверок для RKNHardering. Он определяет, какие проверки включены, их параметры и дополнительные кастомные сетевые эндпоинты.

## Схема файла

```json
{
  "schema_version": 1,
  "id": "unique-profile-id",
  "name": "Название профиля",
  "description": "Что проверяет этот профиль",
  "author": "ваш-github-username",
  "version": "1.0.0",
  "created_at": 1747699200000,
  "updated_at": 1747699200000,
  "checks": {
    "geo_ip": { "enabled": true, "timeout_ms": 10000, "builtin_providers": {}, "custom_providers": [] },
    "ip_comparison": { "enabled": true, "timeout_ms": 8000, "builtin_ru_checkers_enabled": true, "builtin_non_ru_checkers_enabled": true, "custom_endpoints": [] },
    "cdn_pulling": { "enabled": false, "timeout_ms": 10000, "meduza_enabled": false, "rutracker_enabled": false, "builtin_targets_enabled": false, "custom_targets": [] },
    "direct_signs": { "enabled": true, "check_transport_vpn": true, "check_http_proxy": true, "check_socks_proxy": true, "check_proxy_info": true, "check_vpn_service": true },
    "indirect_signs": { "enabled": true, "check_not_vpn_cap": true, "check_vpn_interfaces": true, "check_mtu_anomaly": true, "check_ipsec": true, "check_routing": true, "check_dns": true, "check_proxy_tools": true, "check_local_listeners": true, "check_dumpsys": true, "listener_port_threshold": 5 },
    "native_signs": { "enabled": false },
    "location_signals": { "enabled": true, "check_beacondb": true, "check_cell_towers": true, "check_wifi_signals": true },
    "icmp_spoofing": { "enabled": false, "timeout_ms": 5000, "ping_count": 3, "builtin_targets_enabled": true, "custom_targets": [] },
    "rtt_triangulation": { "enabled": false, "timeout_ms": 5000, "ping_count": 5, "builtin_targets_enabled": true, "custom_targets": [] },
    "call_transport": { "enabled": false, "timeout_ms": 5000, "builtin_global_stun_enabled": true, "builtin_ru_stun_enabled": true, "check_mtproto": true, "custom_stun_servers": [] },
    "split_tunnel": { "enabled": true, "proxy_scan": true, "xray_api_scan": true, "port_range": "popular", "port_range_start": 1024, "port_range_end": 65535, "connect_timeout_ms": 300, "check_underlying_network": true, "check_vpn_network_binding": true, "check_mtproto_via_proxy": true },
    "domain_reachability_enabled": true
  },
  "custom_domains": [
    {
      "domain": "yandex.ru",
      "check_type": "reachable-without-vpn",
      "description": "Должен быть доступен без VPN",
      "expected_dns_available": true,
      "expected_tcp_available": true,
      "expected_tls_available": true
    }
  ],
  "network": {
    "network_requests_enabled": true,
    "dns_mode": "system",
    "dns_preset": "custom",
    "dns_servers": "",
    "doh_url": "",
    "doh_bootstrap": ""
  },
  "marketplace": {
    "source_url": "https://raw.githubusercontent.com/your-username/RKNHardering/main/marketplace/checks/unique-profile-id.rkncheck",
    "official": false,
    "verified": false,
    "marketplace_id": "unique-profile-id"
  }
}
```

### Кастомные провайдеры GeoIP (`custom_providers`)

```json
{
  "name": "My GeoIP",
  "url": "https://example.com/api/ip",
  "enabled": true,
  "response_mapping": {
    "response_type": "JSON",
    "ip_path": "$.ip",
    "country_code_path": "$.country_code",
    "isp_path": "$.isp"
  }
}
```

Возможные значения `response_type`: `JSON`, `PLAIN_TEXT`, `KEY_VALUE`, `REGEX`.

### Кастомные эндпоинты сравнения IP (`custom_endpoints`)

```json
{
  "label": "My checker",
  "url": "https://example.com/myip",
  "scope": "RU",
  "enabled": true,
  "response_mapping": { "response_type": "PLAIN_TEXT" }
}
```

Возможные значения `scope`: `RU`, `NON_RU`.

### Кастомные цели CDN (`custom_targets` в cdn_pulling)

```json
{
  "label": "My CDN",
  "url": "https://example.com/cdn-cgi/trace",
  "enabled": true,
  "response_mapping": { "response_type": "KEY_VALUE", "ip_path": "ip" }
}
```

### Кастомные цели ICMP/RTT

```json
{ "host": "example.com", "label": "Control host", "is_control": true }
```

```json
{ "host": "example.com", "label": "Foreign server", "expected_location": "foreign" }
```

### Кастомные STUN-серверы

```json
{ "host": "stun.example.com", "port": 3478, "label": "My STUN" }
```

### Кастомная проверка доменов (`custom_domains`)

Если `"domain_reachability_enabled"` установлен в `true`, вы можете указать список доменов для проверки в разделе `"custom_domains"`:

```json
{
  "domain": "example.com",
  "check_type": "reachable-without-vpn",
  "description": "Описание домена",
  "expected_dns_available": true,
  "expected_tcp_available": true,
  "expected_tls_available": true
}
```

- `check_type`: тег/метка для проверки (например, `reachable-without-vpn`, `blocked-without-vpn`, `telegram`).
- `expected_dns_available`, `expected_tcp_available`, `expected_tls_available`: ожидаемый результат (boolean) для DNS-разрешения, TCP-подключения к порту 443 и TLS-рукопожатия.

### Данные маркетплейса (`marketplace`)

Каждый профиль содержит блок метаданных `"marketplace"`. Обратите внимание, что поле `"install_count"` устарело и было удалено как из каталога, так и из файлов профилей.

```json
{
  "source_url": "https://raw.githubusercontent.com/.../profile.rkncheck",
  "official": false,
  "verified": false,
  "marketplace_id": "unique-profile-id"
}
```

- `official`: `true`, если профиль поддерживается разработчиками проекта.
- `verified`: `true`, если профиль проверен и одобрен мейнтейнерами.
- `marketplace_id`: уникальный идентификатор, соответствующий ID в каталоге.
- `source_url`: URL-адрес исходного JSON-файла профиля.

## Как предложить профиль

1. Сделайте форк репозитория.
2. Добавьте ваш `.rkncheck`-файл в папку `marketplace/checks/`.
3. Добавьте запись в `marketplace/catalog.json`, указывающую на ваш файл через `profile_url` (используйте raw-ссылку с GitHub).
4. Вычислите значение `expected_hash` для записи в каталоге (см. ниже) и укажите его.
5. Откройте Pull Request с понятным описанием того, что делает ваш профиль.

## Хеш целостности (`expected_hash`)

Каждая запись в каталоге должна содержать `expected_hash` — SHA-256 хэш канонического JSON-представления файла профиля (исключая блоки `marketplace`, `id` и временные метки).
Android-клиент откажется устанавливать загруженный профиль, если пересчитанный хэш не совпадает с каталогом. Приложение также активирует кнопку «Обновить» для установленных профилей, если хэш в репозитории отличается от хэша, сохраненного при установке.

Чтобы рассчитать хэш, выполните из корня репозитория:

```
gradlew :app:testDebugUnitTest --tests "com.notcvnt.rknhardering.customcheck.MarketplaceHashGeneratorTest" -i
```

Этот тест выводит хэш для каждого `.rkncheck` файла в `marketplace/checks/`. Скопируйте полученное значение в поле `expected_hash` соответствующей записи в каталоге.

При любом редактировании тела профиля хэш должен быть обновлен в каталоге в рамках того же PR — иначе пользователи не смогут обновиться, а новые установки будут отклонены.

## Требования

- Профиль должен быть валидным JSON и успешно парситься.
- `id` должен быть уникальным в каталоге.
- `name` должен быть понятным и на английском языке.
- `author` должен быть вашим именем пользователя на GitHub.
- Если ваш профиль содержит `custom_providers`, `custom_endpoints` или `custom_targets` со сторонними URL, объясните в описании PR, что это за эндпоинты и зачем они нужны.
- Запрещены любые вредоносные, обманные или нарушающие приватность эндпоинты.

## Процесс проверки

Предложенные профили проходят ручную проверку мейнтейнерами:

1. PR проверяется на соответствие указанным выше требованиям.
2. Если профиль содержит кастомные эндпоинты, они проверяются на легитимность.
3. Проверенные профили получают `"verified": true` в каталоге.
4. Официальные профили (поддерживаемые проектом) получают и `"official": true`, и `"verified": true`.
5. После слияния PR каталог подписывается приватным ключом разработчиков с созданием/обновлением файла `marketplace/catalog.sig`. Эта подпись проверяется приложением с помощью встроенного публичного ключа.

Непроверенные профили сообщества все равно будут отображаться в списке, но приложение покажет предупреждение безопасности перед их установкой с перечнем всех объявленных в профиле URL-адресов.

***

# Marketplace Contributing Guide

## What is `.rkncheck`

A `.rkncheck` file is a JSON document that describes a custom check profile for RKNHardering. It specifies which checks are enabled, their parameters, and optional custom network endpoints.

## File Schema

```json
{
  "schema_version": 1,
  "id": "unique-profile-id",
  "name": "Profile Name",
  "description": "What this profile checks",
  "author": "your-github-username",
  "version": "1.0.0",
  "created_at": 1747699200000,
  "updated_at": 1747699200000,
  "checks": {
    "geo_ip": { "enabled": true, "timeout_ms": 10000, "builtin_providers": {}, "custom_providers": [] },
    "ip_comparison": { "enabled": true, "timeout_ms": 8000, "builtin_ru_checkers_enabled": true, "builtin_non_ru_checkers_enabled": true, "custom_endpoints": [] },
    "cdn_pulling": { "enabled": false, "timeout_ms": 10000, "meduza_enabled": false, "rutracker_enabled": false, "builtin_targets_enabled": false, "custom_targets": [] },
    "direct_signs": { "enabled": true, "check_transport_vpn": true, "check_http_proxy": true, "check_socks_proxy": true, "check_proxy_info": true, "check_vpn_service": true },
    "indirect_signs": { "enabled": true, "check_not_vpn_cap": true, "check_vpn_interfaces": true, "check_mtu_anomaly": true, "check_ipsec": true, "check_routing": true, "check_dns": true, "check_proxy_tools": true, "check_local_listeners": true, "check_dumpsys": true, "listener_port_threshold": 5 },
    "native_signs": { "enabled": false },
    "location_signals": { "enabled": true, "check_beacondb": true, "check_cell_towers": true, "check_wifi_signals": true },
    "icmp_spoofing": { "enabled": false, "timeout_ms": 5000, "ping_count": 3, "builtin_targets_enabled": true, "custom_targets": [] },
    "rtt_triangulation": { "enabled": false, "timeout_ms": 5000, "ping_count": 5, "builtin_targets_enabled": true, "custom_targets": [] },
    "call_transport": { "enabled": false, "timeout_ms": 5000, "builtin_global_stun_enabled": true, "builtin_ru_stun_enabled": true, "check_mtproto": true, "custom_stun_servers": [] },
    "split_tunnel": { "enabled": true, "proxy_scan": true, "xray_api_scan": true, "port_range": "popular", "port_range_start": 1024, "port_range_end": 65535, "connect_timeout_ms": 300, "check_underlying_network": true, "check_vpn_network_binding": true, "check_mtproto_via_proxy": true },
    "domain_reachability_enabled": true
  },
  "custom_domains": [
    {
      "domain": "yandex.ru",
      "check_type": "reachable-without-vpn",
      "description": "Should be reachable without VPN",
      "expected_dns_available": true,
      "expected_tcp_available": true,
      "expected_tls_available": true
    }
  ],
  "network": {
    "network_requests_enabled": true,
    "dns_mode": "system",
    "dns_preset": "custom",
    "dns_servers": "",
    "doh_url": "",
    "doh_bootstrap": ""
  },
  "marketplace": {
    "source_url": "https://raw.githubusercontent.com/your-username/RKNHardering/main/marketplace/checks/unique-profile-id.rkncheck",
    "official": false,
    "verified": false,
    "marketplace_id": "unique-profile-id"
  }
}
```

### Custom GeoIP providers (`custom_providers`)

```json
{
  "name": "My GeoIP",
  "url": "https://example.com/api/ip",
  "enabled": true,
  "response_mapping": {
    "response_type": "JSON",
    "ip_path": "$.ip",
    "country_code_path": "$.country_code",
    "isp_path": "$.isp"
  }
}
```

`response_type` values: `JSON`, `PLAIN_TEXT`, `KEY_VALUE`, `REGEX`.

### Custom IP comparison endpoints (`custom_endpoints`)

```json
{
  "label": "My checker",
  "url": "https://example.com/myip",
  "scope": "RU",
  "enabled": true,
  "response_mapping": { "response_type": "PLAIN_TEXT" }
}
```

`scope` values: `RU`, `NON_RU`.

### Custom CDN targets (`custom_targets` in cdn_pulling)

```json
{
  "label": "My CDN",
  "url": "https://example.com/cdn-cgi/trace",
  "enabled": true,
  "response_mapping": { "response_type": "KEY_VALUE", "ip_path": "ip" }
}
```

### Custom ICMP/RTT targets

```json
{ "host": "example.com", "label": "Control host", "is_control": true }
```

```json
{ "host": "example.com", "label": "Foreign server", "expected_location": "foreign" }
```

### Custom STUN servers

```json
{ "host": "stun.example.com", "port": 3478, "label": "My STUN" }
```

### Custom Domain checks (`custom_domains`)

If `"domain_reachability_enabled"` is set to `true`, you can specify custom domains to check under `"custom_domains"`:

```json
{
  "domain": "example.com",
  "check_type": "reachable-without-vpn",
  "description": "Domain description",
  "expected_dns_available": true,
  "expected_tcp_available": true,
  "expected_tls_available": true
}
```

- `check_type`: tag/label for the check (e.g. `reachable-without-vpn`, `blocked-without-vpn`, `telegram`).
- `expected_dns_available`, `expected_tcp_available`, `expected_tls_available`: boolean expected outcomes for DNS resolution, TCP port 443 connection, and TLS handshake.

### Marketplace Info (`marketplace`)

Each profile includes a `"marketplace"` metadata block. Note that `"install_count"` is deprecated and has been removed from both catalog entries and profile files.

```json
{
  "source_url": "https://raw.githubusercontent.com/.../profile.rkncheck",
  "official": false,
  "verified": false,
  "marketplace_id": "unique-profile-id"
}
```

- `official`: set to `true` if maintained by the project developers.
- `verified`: set to `true` if reviewed and verified by maintainers.
- `marketplace_id`: unique identifier matching the catalog ID.
- `source_url`: URL of the raw profile JSON.

## How to Submit a Profile

1. Fork this repository.
2. Add your `.rkncheck` file to `marketplace/checks/`.
3. Add an entry to `marketplace/catalog.json` pointing to your file via `profile_url` (use the raw GitHub URL).
4. Compute the `expected_hash` field for the catalog entry (see below) and include it.
5. Open a pull request with a clear description of what your profile does.

## Integrity Hash (`expected_hash`)

Every catalog entry must declare an `expected_hash` — the SHA-256 of the canonical
JSON projection of the profile file (excluding `marketplace`, `id`, and timestamps).
The Android client refuses to install a downloaded profile when the recomputed
hash does not match the catalog. It also bumps the "Update" button on installed
profiles when the upstream hash differs from the one captured at install time.

To compute the hash, run from the repository root:

```
gradlew :app:testDebugUnitTest --tests "com.notcvnt.rknhardering.customcheck.MarketplaceHashGeneratorTest" -i
```

The test prints one line per `.rkncheck` under `marketplace/checks/` with the
computed hash. Paste the matching value into `expected_hash` for the catalog
entry that references the profile.

Whenever a profile body is edited, the hash must be regenerated and the catalog
updated in the same PR — otherwise existing installations cannot upgrade and
new installations are rejected.

## Requirements

- The profile must be valid JSON and parse correctly.
- `id` must be unique in the catalog.
- `name` must be descriptive and in English.
- `author` should be your GitHub username.
- If your profile includes `custom_providers`, `custom_endpoints`, or `custom_targets` with third-party URLs, explain what those endpoints are and why they are needed in your PR description.
- No malicious, deceptive, or privacy-invasive endpoints.

## Verification Process

Submitted profiles go through manual review by maintainers:

1. The PR is reviewed for compliance with the requirements above.
2. If the profile includes custom endpoints, those endpoints are inspected for legitimacy.
3. Verified profiles get `"verified": true` in the catalog entry.
4. Official profiles (maintained by the project) get both `"official": true` and `"verified": true`.
5. Once a PR is merged, the catalog is signed by the maintainers with their private key, creating/updating `marketplace/catalog.sig`. This signature is verified by the app using its bundled public key.

Unverified community profiles are still listed but the app shows a security warning before installation, displaying all custom URLs declared in the profile.
