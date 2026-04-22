> **Язык / Language:** [Русский](README.md) | [English](docs/README.en.md) | [فارسی](docs/README.fa.md) | [中文](docs/README.zh-CN.md)

# RKNHardering

Android-приложение для обнаружения VPN и прокси на устройстве. Реализует методику РКН по выявлению средств обхода блокировок.

Минимальная версия Android: 8.0 (API 26).

## Нужна помощь сообщества / Community Help Wanted

> **RU**

Этот проект документирует методы обнаружения VPN и прокси на Android-устройствах. Однако **обратная задача**, как предотвратить детектирование наличия VPN, исследована значительно хуже.

Я ищу людей, готовых помочь собрать, систематизировать и протестировать информацию о способах обхода детектов, включая, но не ограничиваясь:

- **Маскировка сетевых интерфейсов** (как скрыть `tun0`, `wg0` и другие VPN-подобные интерфейсы от `NetworkInterface.getNetworkInterfaces()` и `/proc/net/route`)
- **Подмена NetworkCapabilities** (способы убрать `TRANSPORT_VPN`, `IS_VPN`, `VpnTransportInfo` из ответов `ConnectivityManager`)
- **Скрытие от dumpsys** (предотвращение утечки информации через `dumpsys vpn_management` и `dumpsys activity services android.net.VpnService`)
- **MTU-нормализация** (выставление стандартного MTU (1500) для туннельных интерфейсов на различных клиентах)
- **DNS-утечки** (предотвращение обнаружения loopback/private DNS при активном VPN)
- **Скрытие localhost-прокси** (как предотвратить обнаружение через `/proc/net/tcp` и сканирование портов)
- **Обход нативных проверок** (противодействие JNI-проверкам через `/proc/self/maps`, `getifaddrs()`, `dlsym`)
- **Маскировка установленных приложений** (скрытие пакетов VPN-приложений от `PackageManager`)

Если вы обладаете знаниями в этих областях, пожалуйста, откройте Issue или Pull Request с описанием метода, условий применимости и ограничений. Любая информация ценна — от теоретических идей до работающих PoC.

> **EN**

This project documents methods for detecting VPNs and proxies on Android devices. However, **the inverse problem** how to prevent the detection of an active VPN has been studied much less thoroughly.

I am looking for people willing to help collect, organize, and test information about ways to bypass detection, including, but not limited to:

- **Network interface masking** (how to hide `tun0`, `wg0`, and other VPN-like interfaces from `NetworkInterface.getNetworkInterfaces()` and `/proc/net/route`)
- **NetworkCapabilities spoofing** (ways to remove `TRANSPORT_VPN`, `IS_VPN`, and `VpnTransportInfo` from `ConnectivityManager` responses)
- **Hiding from dumpsys** (preventing information leakage through `dumpsys vpn_management` and `dumpsys activity services android.net.VpnService`)
- **MTU normalization** (setting a standard MTU of 1500 for tunnel interfaces across different clients)
- **DNS leaks** (preventing detection of loopback/private DNS while a VPN is active)
- **Hiding localhost proxies** (how to prevent detection via `/proc/net/tcp` and port scanning)
- **Bypassing native checks** (countering JNI-based checks through `/proc/self/maps`, `getifaddrs()`, and `dlsym`)
- **Masking installed applications** (hiding VPN app packages from `PackageManager`)

If you have expertise in these areas, please open an Issue or Pull Request describing the method, the conditions under which it applies, and its limitations. Any information is valuable, from theoretical ideas to working PoCs.

## Архитектура

Шесть независимых модулей проверки запускаются параллельно. Итоговый вердикт рассчитывается в `VerdictEngine`.

`IpComparisonChecker` сохраняется в результат и показывается в UI как диагностический блок, но в текущей версии не участвует в `VerdictEngine`.

```text
VpnCheckRunner
├── GeoIpChecker           — GeoIP + hosting/proxy-сигналы
├── IpComparisonChecker    — RU/не-RU IP-чекеры (диагностика)
├── DirectSignsChecker     — NetworkCapabilities, системный proxy, установленные VPN apps
├── IndirectSignsChecker   — интерфейсы, маршруты, DNS, dumpsys, proxy-tech signals
├── CallTransportChecker   — STUN/MTProto (утечки и доступность)
├── CdnPullingChecker      — HTTPS-запросы к CDN/redirector
├── LocationSignalsChecker — MCC/SIM/cell/Wi-Fi/BeaconDB
├── BypassChecker          — localhost proxy, Xray gRPC API, underlying-network leak
└── NativeSignsChecker     — JNI-проверки (маршруты, интерфейсы, хуки, root)
        └── VerdictEngine  — логика итогового вердикта
```

---

## Модули проверки

### 1. GeoIP (`GeoIpChecker`)

Источники:

- `https://api.ipapi.is/` — основной источник полей GeoIP и сигналов proxy/VPN/Tor/datacenter
- `https://www.iplocate.io/api/lookup` — fallback-источник полей GeoIP и дополнительный голос за hosting (`privacy.is_hosting`)

Логика:

| Сигнал | Что делает код | Итог |
|--------|----------------|------|
| `countryCode != RU` | IP считается иностранным | `needsReview`, если одновременно нет `hosting` и `proxy` |
| `hosting` | Используется majority vote по совместимым ответам одного и того же IP (`ipapi.is`, `iplocate.io`) | `detected = true`, если большинство совместимых источников говорят `hosting=true` |
| `proxy` | Используются совместимые HTTPS-провайдеры (`ipapi.is`, `iplocate.io`) | `detected = true`, если хотя бы один совместимый провайдер говорит о proxy/VPN/Tor |
| `country`, `isp`, `org`, `as`, `query` | Берутся из `ipapi.is`, а недостающие поля заполняются из `iplocate.io` только для совместимого IP | не влияют напрямую |

Итог категории:

- `detected = isHosting || isProxy`
- `needsReview = foreignIp && !isHosting && !isProxy`

Таймаут соединения и чтения для HTTP(S)-запросов: 10 секунд. `GeoIpChecker` использует только HTTPS-провайдеры и возвращает ошибку только если ни один GeoIP-провайдер не ответил данными.

---

### 2. Сравнение IP-чекеров (`IpComparisonChecker`)

Модуль сравнивает ответы RU- и не-RU публичных IP-чекеров. Это диагностический блок: он отображается в UI, но сейчас не участвует в `VerdictEngine`.

Группы сервисов:

| Группа | Сервисы |
|--------|---------|
| `RU` | `Yandex IPv4`, `2ip.ru`, `Yandex IPv6` |
| `NON_RU` | `ifconfig.me IPv4`, `ifconfig.me IPv6`, `checkip.amazonaws.com`, `ipify`, `ip.sb IPv4`, `ip.sb IPv6` |

Логика:

- внутри каждой группы строится `canonicalIp`, если сервисы согласованы;
- несовпадение IP внутри группы, частичные ответы и конфликт семейств `IPv4/IPv6` переводят группу в `needsReview` или `detected` в зависимости от полноты данных;
- общий `detected` ставится только если обе группы дали полный консенсус внутри себя, но RU- и не-RU группы вернули разные canonical IP;
- ожидаемые ошибки IPv6-эндпоинтов могут игнорироваться и не ломают консенсус IPv4.

---

### 3. Прямые признаки (`DirectSignsChecker`)

Системные признаки без активного сетевого сканирования localhost.

#### 3.1 NetworkCapabilities (`checkVpnTransport`)

API: `ConnectivityManager.getNetworkCapabilities(activeNetwork)`

| Проверка | Метод/поле | Итог |
|----------|------------|------|
| `NetworkCapabilities.TRANSPORT_VPN` | `caps.hasTransport(TRANSPORT_VPN)` | `detected = true` |
| `IS_VPN` | `caps.toString().contains("IS_VPN")` | `detected = true` |
| `VpnTransportInfo` | `caps.toString().contains("VpnTransportInfo")` | `detected = true` |

`IS_VPN` и `VpnTransportInfo` проверяются через строковое представление `NetworkCapabilities`.

#### 3.2 Системный proxy (`checkSystemProxy`)

Используются:

- `System.getProperty("http.proxyHost")` с fallback на `Proxy.getDefaultHost()`
- `System.getProperty("http.proxyPort")` с fallback на `Proxy.getDefaultPort()`
- `System.getProperty("socksProxyHost")`
- `System.getProperty("socksProxyPort")`
- `ConnectivityManager.getDefaultProxy()`
- `ConnectivityManager.allNetworks` + `ConnectivityManager.getLinkProperties(network).httpProxy`
- `ProxyInfo.getPacFileUrl()`, `ProxyInfo.getExclusionList()`, на API 30+ также `ProxyInfo.isValid()`

Логика:

| Состояние | Итог |
|-----------|------|
| host отсутствует | proxy считается ненастроенным |
| host есть, но порт невалиден | `needsReview = true` |
| host есть и порт валиден | `detected = true` |
| порт относится к известным proxy-портам | добавляется отдельная находка |
| `ProxyInfo` содержит `PAC URL` | `detected = true` |
| `ProxyInfo` задан на конкретной сети | в вывод добавляется отдельная строка с interface name |
| `ProxyInfo` содержит exclusion list | exclusions показываются пользователю |
| на API 30+ `!ProxyInfo.isValid()` | `needsReview = true` без detected-evidence |
| на отслеживаемых сетях `ProxyInfo` не найден | добавляется агрегированная строка `ProxyInfo ...: не обнаружен` |

Известные proxy-порты: `80`, `443`, `1080`, `3127`, `3128`, `4080`, `5555`, `7000`, `7044`, `8000`, `8080`, `8081`, `8082`, `8888`, `9000`, `9050`, `9051`, `9150`, `12345`, а также диапазон `16000..16100`.

#### 3.3 Установленные VPN/Proxy-приложения (`InstalledVpnAppDetector`)

Модуль проверяет три источника:

- известные сигнатуры пакетов из [`VpnAppCatalog`](app/src/main/java/com/notcvnt/rknhardering/vpn/VpnAppCatalog.kt);
- приложения, которые объявляют `VpnService.SERVICE_INTERFACE` через `PackageManager.queryIntentServices`.
- в приложении есть "VPN" в названии (это конечно не на 100% дает что это впн)
Это диагностические сигналы установки или декларации `VpnService`, а не подтверждение активного туннеля. Совпадения переводят категорию в `needsReview`, но сами по себе не делают `DirectSignsChecker.detected = true`.

---

### 4. Косвенные признаки (`IndirectSignsChecker`)

#### 4.1 Capability `NOT_VPN` (`checkNotVpnCapability`)

`ConnectivityManager.getNetworkCapabilities(activeNetwork).toString()` проверяется на наличие строки `NOT_VPN`.

| Результат | Итог |
|-----------|------|
| `NOT_VPN` присутствует | норма |
| `NOT_VPN` отсутствует | `detected = true` |

#### 4.2 Сетевые интерфейсы (`checkNetworkInterfaces`)

API: `NetworkInterface.getNetworkInterfaces()`. Проверяются активные (`isUp`) интерфейсы.

Паттерны VPN-подобных интерфейсов:

- `tun\d+`
- `tap\d+`
- `wg\d+`
- `ppp\d+`
- `ipsec.*`

Любой активный интерфейс, попавший под эти паттерны, даёт `detected = true`.

#### 4.3 Аномалия MTU (`checkMtu`)

Логика:

| Условие | Итог |
|---------|------|
| VPN-подобный интерфейс с MTU `1..1499` | `detected = true` |
| Нестандартный активный интерфейс (не `wlan.*`, `rmnet.*`, `eth.*`, `lo`) с MTU `1..1499` | `detected = true` |

#### 4.4 Маршрутизация (`checkRoutingTable`)

Источник данных:

- в первую очередь `LinkProperties.routes` из Android API;
- fallback: `/proc/net/route`, если через API не удалось получить default route.

Детекты:

- default route через нестандартный интерфейс;
- выделенные non-default routes через VPN/нестандартный интерфейс;
- паттерн split tunneling: одновременно видны tunnel routes и обычный default route через стандартную сеть.

Default route через `wlan.*`, `rmnet.*`, `eth.*`, `lo` считается нормой, если сама сеть не помечена как VPN.

#### 4.5 DNS (`checkDns`)

API: `ConnectivityManager.getLinkProperties(activeNetwork).dnsServers`.

DNS оценивается вместе со snapshot underlying-сетей, если они доступны.

| Сигнал | Итог |
|--------|------|
| loopback DNS (`127.x.x.x`, `::1`) | `detected = true` |
| private DNS, унаследованный из той же private/ULA-подсети основной non-VPN сети | норма |
| private DNS при активном VPN и отличии от underlying сети | `detected = true` |
| private DNS без достаточного контекста | `needsReview = true` |
| public DNS, заменённый при активном VPN | `needsReview = true` |
| link-local (`169.254.x.x`, `fe80::/10`) | информационно |

#### 4.6 Дополнительные proxy-технические сигналы (`checkProxyTechnicalSignals`)

Проверяются:

- установленные proxy-only утилиты из `VpnAppCatalog` с сигналом `LOCAL_PROXY` без `VPN_SERVICE`;
- локальные listeners из `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` на известных proxy-портах;
- большое число localhost listeners на высоких портах.

Логика:

- listener на известном localhost proxy-порту даёт `detected = true`;
- наличие proxy-only утилиты или множества localhost listeners даёт `needsReview = true`.

Отдельно фиксируется ограничение: проверки процессов, `iptables`/`pf` и системных сертификатов неполны без root/privileged access.

#### 4.7 `dumpsys vpn_management` (`checkDumpsysVpn`)

Только Android 12+ (API 31+). Запускается `dumpsys vpn_management`.

Если парсер (`VpnDumpsysParser`) находит активные записи VPN, они дают `detected = true`. Из записей извлекается пакет, затем он сопоставляется с `VpnAppCatalog`:

- известный пакет: высокая уверенность;
- неизвестный пакет: `detected = true` и одновременно `needsReview = true`.

Пустой вывод, `Permission Denial` или недоступность сервиса считаются отсутствием детекта.

#### 4.8 `dumpsys activity services android.net.VpnService` (`checkDumpsysVpnService`)

Запускается `dumpsys activity services android.net.VpnService`.

Если найдены активные `VpnService`, создаются `activeApps` и evidence:

- известный пакет из каталога: высокая уверенность;
- неизвестный пакет: `detected = true` и `needsReview = true`.

Пустой вывод или отсутствие записей `VpnService` детекта не дают.

---

### 5. Сигналы местоположения (`LocationSignalsChecker`)

Модуль собирает признаки, подтверждающие, что устройство физически находится в РФ или, наоборот, что telephony-сигналы выглядят нетипично.

Источники:

- `TelephonyManager.networkOperator`, `networkCountryIso`, `networkOperatorName`
- `TelephonyManager.simOperator`, `simCountryIso`, `isNetworkRoaming`
- `requestCellInfoUpdate` / `allCellInfo`
- `WifiManager.scanResults` и текущий `BSSID`
- `BeaconDB` (`https://api.beacondb.net/v1/geolocate`) для cell/Wi-Fi geolocation
- reverse geocoding для `countryCode`

Разрешения:

- `ACCESS_FINE_LOCATION` нужен для cell lookup;
- на Android 13+ `NEARBY_WIFI_DEVICES` нужен для Wi-Fi lookup.

Логика:

| Сигнал | Итог |
|--------|------|
| `networkMcc == 250` | добавляется служебная находка `network_mcc_ru:true` |
| `BeaconDB`/reverse geocode вернул `RU` | добавляются `cell_country_ru:true` и `location_country_ru:true` |
| `networkMcc != 250` | `needsReview = true` |
| отсутствие разрешений или radio data | информационно |

В текущей реализации `LocationSignalsChecker.detected` всегда `false`. Его основная роль в `VerdictEngine` — подтверждать Россию и усиливать иностранный GeoIP-сигнал.

---

### 6. Bypass-проверка (`BypassChecker`)

Три проверки запускаются параллельно:

- `ProxyScanner`
- `XrayApiScanner`
- `UnderlyingNetworkProber`

#### 6.1 Сканер прокси (`ProxyScanner` + `ProxyProber`)

Сканируются `127.0.0.1` и `::1`.

Режимы:

| Режим | Описание |
|-------|----------|
| `AUTO` | сначала популярные порты, затем полный диапазон |
| `MANUAL` | проверка одного указанного порта |

Популярные порты в `AUTO` формируются из `VpnAppCatalog.localhostProxyPorts` и дополнительно включают `1081`, `7890`, `7891`.

Полное сканирование:

- диапазон `1024..65535`
- параллельность `200`
- таймаут соединения `80 мс`
- таймаут чтения `120 мс`

Определяются только proxy без аутентификации:

| Тип | Как определяется |
|-----|------------------|
| `SOCKS5` | greeting `0x05 0x01 0x00` и ответ `0x05 0x00` |
| `HTTP CONNECT` | `CONNECT ifconfig.me:443 HTTP/1.1` и ответ `HTTP/1.x 200` |

Открытый localhost proxy сам по себе не считается подтверждённым обходом: он фиксируется как `needsReview`. Подтверждение обхода ставится только если удалось получить прямой IP и IP через proxy, и они различаются.

Дополнительно:

- если найден `SOCKS5`, но HTTP-получение IP через него не удалось и порт не похож на Xray, запускается `MtProtoProber`;
- успешный MTProto probe добавляет информативную находку, но не влияет на итоговый verdict.

#### 6.2 Сканер Xray gRPC API (`XrayApiScanner` + `XrayApiClient`)

Сканируются `127.0.0.1` и `::1`.

Параметры:

- диапазон `1024..65535`
- параллельность `100`
- TCP connect timeout `200 мс`
- gRPC deadline `2000 мс` с повтором на увеличенном дедлайне

Проверка выполняется не через сырой HTTP/2 preface, а через реальный gRPC-вызов `HandlerServiceGrpc.listOutbounds(...)`.

При успехе:

- endpoint даёт `detected = true`;
- в findings добавляются до 10 summary по outbound'ам (`tag`, `protocol`, `address`, `port`, `sni`) и счётчик оставшихся.

#### 6.3 Underlying network leak / VPN network binding (`UnderlyingNetworkProber`)

Если на устройстве активен VPN, модуль:

- перебирает все `ConnectivityManager.allNetworks`;
- ищет internet-capable сеть без `TRANSPORT_VPN`;
- привязывает HTTP(S)-запросы к этой сети;
- запрашивает публичный IP через `ifconfig.me`, `checkip.amazonaws.com`, `ipv4-internet.yandex.net`, `ipv6-internet.yandex.net`.

Если underlying-сеть доступна при активном VPN, это трактуется как `VPN gateway leak` и даёт `detected = true`.

Итог категории:

- `detected = confirmed split tunnel || xrayApiFound || vpnGatewayLeak || vpnNetworkBinding`
- `needsReview = true`, если найден открытый proxy, но подтверждения обхода нет

---

### 7. CDN Pulling (`CdnPullingChecker`)

Отправляет HTTPS-запросы к известным endpoint-ам типа trace и redirector (Google Video, Cloudflare trace, Meduza), чтобы узнать, какой публичный IP или метаданные сети возвращаются. Различия в ответах могут указывать на туннелирование или проксирование.

### 8. Call Transport (`CallTransportChecker`)

Проверяет доступность UDP/STUN (как глобальных, так и региональных), а также TCP-доступность Telegram MTProto через локальные прокси-серверы. Это позволяет выявить утечки трафика мимо стандартных туннелей или обнаружить подмену IP-адресов.

### 9. Native Signs (`NativeSignsChecker`)

Выполняет низкоуровневые JNI-проверки прямо из C++:
- Перечисление нативных интерфейсов и работа `getifaddrs()`
- Прямой парсинг `/proc/net/route`
- Сканирование `/proc/self/maps` на известные признаки hook-ов
- Целостность разрешения символов `libc` (dlsym)
- Обнаружение root (su binary, параметры magisk, selinux, rw /system и др.)

Нативные находки транслируются в `needsReview` или общие indirect-признаки.

---

## Вердикт (`VerdictEngine`)

`VerdictEngine` использует не все собранные блоки одинаково.

Сначала применяются безусловные правила:

1. `DETECTED`, если в bypass-evidence есть `SPLIT_TUNNEL_BYPASS`.
2. `DETECTED`, если найден `XRAY_API`.
3. `DETECTED`, если найден `VPN_GATEWAY_LEAK`.
4. `DETECTED`, если location-сигналы подтверждают РФ (`network_mcc_ru:true`, `cell_country_ru:true` или `location_country_ru:true`), а `GeoIP` одновременно даёт иностранный сигнал.

После этого считается матрица:

- `geoMatrixHit` = иностранный GeoIP-сигнал (`geoIp.needsReview` или evidence `GEO_IP`)
- `directMatrixHit` = evidence из `DIRECT_NETWORK_CAPABILITIES` или `SYSTEM_PROXY`
- `indirectMatrixHit` = evidence из `INDIRECT_NETWORK_CAPABILITIES`, `ACTIVE_VPN`, `NETWORK_INTERFACE`, `ROUTING`, `DNS`, `PROXY_TECHNICAL_SIGNAL`

Комбинации:

| Geo | Direct | Indirect | Вердикт |
|-----|--------|----------|---------|
| нет | нет | нет | `NOT_DETECTED` |
| нет | да | нет | `NOT_DETECTED` |
| нет | нет | да | `NOT_DETECTED` |
| да | нет | нет | `NEEDS_REVIEW` |
| нет | да | да | `NEEDS_REVIEW` |
| любые остальные комбинации | | | `DETECTED` |

Примечания:

- `IpComparisonChecker` сейчас не участвует в `VerdictEngine`;
- сигналы `INSTALLED_APP` и `VPN_SERVICE_DECLARATION` тоже не входят в матрицу и остаются диагностическими;
- Действенные (actionable) утечки из `CallTransportChecker` или находки требующие проверки из `NativeSignsChecker` (например, маркеры хуков) переводят вердикт из `NOT_DETECTED` в `NEEDS_REVIEW`.

---

## Сборка

Требования: JDK 17+, Android SDK с Build Tools для API 36.

```bash
./gradlew assembleDebug
```

---

## Благодарности

[runetfreedom](https://github.com/runetfreedom) — за [per-app-split-bypass-poc](https://github.com/runetfreedom/per-app-split-bypass-poc), на основе которого реализована детекция per-app split bypass.
