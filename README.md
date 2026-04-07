# RKNHardering

Android-приложение для обнаружения VPN и прокси на устройстве. Реализует методику РКН по выявлению средств обхода блокировок.

Минимальная версия Android: 8.0 (API 26).

## Архитектура

Четыре независимых модуля проверки запускаются параллельно, результаты передаются в `VerdictEngine` для вынесения итогового вердикта.

```
VpnCheckRunner
├── GeoIpChecker       — внешний IP через ip-api.com
├── DirectSignsChecker — системные флаги и переменные
├── IndirectSignsChecker — сетевые интерфейсы, маршруты, DNS, dumpsys
└── BypassChecker      — сканирование портов + Xray API
        └── VerdictEngine — логика итогового вердикта
```

---

## Модули проверки

### 1. GeoIP (`GeoIpChecker`)

Источник: `http://ip-api.com/json/` с полями `status,country,countryCode,isp,org,as,proxy,hosting,query`.

| Поле API | Что проверяется | Флаг детекта |
|----------|-----------------|--------------|
| `countryCode` | Страна IP не `RU` | да |
| `hosting` | IP принадлежит хостинг-провайдеру | да |
| `proxy` | IP в базе известных прокси/VPN | да |
| `country`, `isp`, `org`, `as`, `query` | Информационно (в вывод) | нет |

Детект срабатывает если хотя бы одно из трёх полей положительно.

Таймаут соединения и чтения: 10 секунд. При ошибке сети детект = false.

---

### 2. Прямые признаки (`DirectSignsChecker`)

Системные признаки без сетевых запросов.

#### 2.1 NetworkCapabilities (`checkVpnTransport`)

API: `ConnectivityManager.getNetworkCapabilities(activeNetwork)`

| Проверка | Метод/поле | Флаг детекта |
|----------|------------|--------------|
| `NetworkCapabilities.TRANSPORT_VPN` | `caps.hasTransport(TRANSPORT_VPN)` | да |
| `IS_VPN` | `caps.toString().contains("IS_VPN")` | да |
| `VpnTransportInfo` | `caps.toString().contains("VpnTransportInfo")` | да |

`IS_VPN` и `VpnTransportInfo` — внутренние флаги Android, не раскрытые в публичном API, проверяются через строковое представление объекта.

#### 2.2 Системные прокси-переменные (`checkSystemProxy`)

| Системная переменная | Назначение | Флаг детекта |
|----------------------|------------|--------------|
| `System.getProperty("http.proxyHost")` | Хост HTTP-прокси | да (если не пусто) |
| `System.getProperty("http.proxyPort")` | Порт HTTP-прокси | нет (инфо) |
| `System.getProperty("socksProxyHost")` | Хост SOCKS-прокси | да (если не пусто) |
| `System.getProperty("socksProxyPort")` | Порт SOCKS-прокси | нет (инфо) |

Дополнительно: если порт входит в список известных, фиксируется отдельная находка.

Известные порты: `1080`, `9000`, `5555` (SOCKS), `8080`, `3128` (HTTP proxy), `9050`, `9150` (Tor).

---

### 3. Косвенные признаки (`IndirectSignsChecker`)

#### 3.1 Capability NOT_VPN (`checkNotVpnCapability`)

`ConnectivityManager.getNetworkCapabilities(activeNetwork).toString()` проверяется на наличие строки `NOT_VPN`. Отсутствие этого флага в активной сети подозрительно.

| Результат | Флаг детекта |
|-----------|--------------|
| `NOT_VPN` присутствует | нет |
| `NOT_VPN` отсутствует | да |

#### 3.2 Сетевые интерфейсы (`checkNetworkInterfaces`)

API: `NetworkInterface.getNetworkInterfaces()`. Проверяются активные (`isUp`) интерфейсы.

| Паттерн интерфейса | Протокол | Флаг детекта |
|--------------------|----------|--------------|
| `tun\d+` | TUN (OpenVPN, WireGuard в режиме TUN) | да |
| `tap\d+` | TAP (OpenVPN в режиме TAP) | да |
| `wg\d+` | WireGuard | да |
| `ppp\d+` | PPP (L2TP/PPTP) | да |
| `ipsec.*` | IPSec | да |

#### 3.3 Аномалия MTU (`checkMtu`)

Проверяется MTU интерфейсов. VPN-туннели обычно имеют MTU < 1500 из-за инкапсуляции.

| Условие | Флаг детекта |
|---------|--------------|
| VPN-подобный интерфейс (tun/tap/wg/ppp/ipsec) с MTU 1–1499 | да |
| Нестандартный интерфейс (не wlan/rmnet/eth/lo) с MTU 1–1499 | да |

Стандартные интерфейсы (`wlan.*`, `rmnet.*`, `eth.*`, `lo`) не проверяются на MTU.

#### 3.4 Таблица маршрутизации (`checkRoutingTable`)

Источник: `/proc/net/route`. Строки с `destination=00000000` — маршрут по умолчанию (0.0.0.0/0).

| Условие | Флаг детекта |
|---------|--------------|
| Маршрут по умолчанию через `wlan.*`, `rmnet.*`, `eth.*`, `lo` | нет |
| Маршрут по умолчанию через любой другой интерфейс | да |

#### 3.5 DNS-серверы (`checkDns`)

API: `ConnectivityManager.getLinkProperties(activeNetwork).dnsServers`.

| Адрес DNS | Интерпретация | Флаг детекта |
|-----------|---------------|--------------|
| `127.x.x.x` | Localhost — локальный DNS-резолвер VPN | да |
| `10.x.x.x` / `172.16–31.x.x` / `192.168.x.x` | Частная подсеть — типично для VPN-туннеля | да |
| `169.254.x.x` | Link-local | нет |
| Публичный адрес | Норма | нет |

#### 3.6 dumpsys vpn_management (`checkDumpsysVpn`)

Только Android 12+ (API 31+). Запускает `dumpsys vpn_management` через `Runtime.exec`.

| Результат | Флаг детекта |
|-----------|--------------|
| Строка `Active package name:` в выводе | да |
| Строка `Active vpn type:` в выводе | да |
| Запись вида `\d+:...` в секции `VPNs:` | да |
| Пустой вывод / `Permission Denial` / `Can't find service` | нет |

#### 3.7 dumpsys activity services VpnService (`checkDumpsysVpnService`)

Запускает `dumpsys activity services android.net.VpnService` через `Runtime.exec`.

| Результат | Флаг детекта |
|-----------|--------------|
| `ServiceRecord` с `VpnService` в выводе | да |
| `(nothing)` или нет `ServiceRecord` | нет |
| Пустой вывод / `Permission Denial` | нет |

Из найденных записей извлекается имя пакета VPN-приложения.

---

### 4. Bypass-проверка (`BypassChecker`)

Сканирование localhost на наличие открытых прокси и Xray/V2Ray API. Запускается параллельно в двух потоках.

#### 4.1 Сканер прокси (`ProxyScanner` + `ProxyProber`)

Сканирует `127.0.0.1` и `::1`. Режимы:

| Режим | Описание |
|-------|----------|
| `AUTO` | Сначала популярные порты, при неудаче — полное сканирование |
| `MANUAL` | Конкретный порт |

Популярные порты (AUTO, фаза 1): `1080`, `2080`, `1081`, `10808`, `10809`, `12334`, `7890`.

Полное сканирование (AUTO, фаза 2): диапазон `1024–65535`, параллельность 200 воркеров, таймаут соединения 80 мс, таймаут чтения 120 мс.

Определение типа прокси (`ProxyProber.probeNoAuthProxyType`):

| Тип | Протокол обнаружения |
|-----|----------------------|
| `SOCKS5` |握手: `\x05\x01\x00` → ожидание `\x05\x00` (version=5, method=NO_AUTH) |
| `HTTP` | `CONNECT ifconfig.me:443 HTTP/1.1` → ожидание `HTTP/x.x 200` |

Обнаруживаются только прокси без аутентификации.

При нахождении прокси дополнительно: запрашивается прямой IP (`ifconfig.me`) и IP через прокси. Если они различаются — фиксируется per-app split bypass.

#### 4.2 Сканер Xray gRPC API (`XrayApiScanner`)

Сканирует `127.0.0.1` и `::1`, диапазон `1024–65535`, параллельность 100 воркеров, таймаут 200 мс.

Метод обнаружения (`isGrpcEndpoint`): отправка HTTP/2 connection preface + пустой SETTINGS-фрейм, ожидание SETTINGS-фрейма в ответе (тип `0x04`). Не требует protobuf/gRPC зависимостей.

| Результат | Флаг детекта |
|-----------|--------------|
| Открытый SOCKS5 или HTTP прокси на localhost | да |
| Xray gRPC API на localhost | да |

---

## Вердикт (`VerdictEngine`)

| Bypass | GeoIP | Прямые | Косвенные | Вердикт |
|--------|-------|--------|-----------|---------|
| да | любой | любые | любые | `DETECTED` |
| нет | да | да или косв. | да или прям. | `DETECTED` |
| нет | да | нет | нет | `NEEDS_REVIEW` |
| нет | нет | да | да | `NEEDS_REVIEW` |
| нет | нет | нет или да | нет или да | `NOT_DETECTED` |

Bypass — наиболее сильный сигнал, перекрывает остальные.

---

## Сборка

Требования: JDK 17+, Android SDK с Build Tools для API 36.
```bash
./gradlew assembleDebug
```
