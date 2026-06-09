> **Language:** [Русский](../README.md) | [English](README.en.md) | [فارسی](README.fa.md) | [中文](README.zh-CN.md)

# RKNHardering

<a href="https://matrix.to/#/%23RKN_Hardering:matrix.kangel.tech"><img src="https://img.shields.io/badge/matrix-%23000000?style=for-the-badge&logo=matrix&logoColor=white" alt="Matrix" width="200"></a>
<a href="https://t.me/RKNHardering"><img src="https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram" width="200"></a>



برنامه Android برای شناسایی VPN و proxy روی دستگاه. این پروژه روش مبتنی بر منطق روس‌کومنادزور برای تشخیص ابزارهای دور زدن مسدودسازی را پیاده‌سازی می‌کند.

حداقل نسخه Android: 8.0 (API 26).

می‌توانید پروژه را از اینجا دانلود کنید:
<table>
  <tr>
    <th align="center">GitHub</th>
    <th align="center">F-Droid</th>
  </tr>
  <tr>
    <td align="center">
      <a href="https://github.com/xtclovver/RKNHardering/releases/latest">
        <img src="https://github.com/machiav3lli/oandbackupx/blob/034b226cea5c1b30eb4f6a6f313e4dadcbb0ece4/badge_github.png" alt="Download from GitHub" height="75">
      </a>
    </td>
    <td align="center">
      <a href="https://f-droid.org/en/packages/com.notcvnt.rknhardering/">
        <img src="https://fdroid.gitlab.io/artwork/badge/get-it-on.png" alt="Download from F-Droid" height="75">
      </a>
    </td>
  </tr>
</table>

## به کمک جامعه نیاز داریم / Community Help Wanted

این پروژه روش‌های شناسایی VPN و proxy روی دستگاه‌های Android را مستند می‌کند. با این حال، **مسئله معکوس** — یعنی چگونه از شناسایی VPN فعال جلوگیری کنیم — بسیار کمتر بررسی شده است.

من به دنبال افرادی هستم که مایل به جمع‌آوری، سازمان‌دهی و آزمایش اطلاعات درباره روش‌های دور زدن شناسایی باشند، شامل اما نه محدود به:

- **پنهان‌سازی اینترفیس‌های شبکه** (چگونه `tun0`، `wg0` و دیگر اینترفیس‌های شبیه VPN را از `NetworkInterface.getNetworkInterfaces()` و `/proc/net/route` مخفی کنیم)
- **جعل NetworkCapabilities** (روش‌های حذف `TRANSPORT_VPN`، `IS_VPN` و `VpnTransportInfo` از پاسخ‌های `ConnectivityManager`)
- **پنهان‌سازی از dumpsys** (جلوگیری از نشت اطلاعات از طریق `dumpsys vpn_management` و `dumpsys activity services android.net.VpnService`)
- **نرمال‌سازی MTU** (تنظیم MTU استاندارد 1500 برای اینترفیس‌های تانلی در کلاینت‌های مختلف)
- **نشتی‌های DNS** (جلوگیری از شناسایی loopback/private DNS هنگام فعال بودن VPN)
- **پنهان‌سازی proxyهای localhost** (چگونه از شناسایی از طریق `/proc/net/tcp` و اسکن پورت جلوگیری کنیم)
- **دور زدن بررسی‌های بومی/native** (مقابله با بررسی‌های مبتنی بر JNI از طریق `/proc/self/maps`، `getifaddrs()` و `dlsym`)
- **پنهان‌سازی برنامه‌های نصب‌شده** (مخفی کردن بسته‌های برنامه VPN از `PackageManager`)

اگر در این زمینه‌ها تخصص دارید، لطفاً یک Issue یا Pull Request باز کنید، یا در [چت Matrix](https://matrix.to/#/%23RKN_Hardering:matrix.kangel.tech)/[Telegram](https://t.me/RKNHardering) روش خود را همراه با شرایط کاربرد و محدودیت‌های آن شرح دهید. هر اطلاعاتی ارزشمند است — از ایده‌های تئوری تا PoCهای کاربردی.

## معماری

ماژول‌های مستقل بررسی به‌صورت موازی اجرا می‌شوند. نتیجه نهایی در `VerdictEngine` محاسبه می‌شود.

`IpComparisonChecker` در نتیجه ذخیره می‌شود و در رابط کاربری به‌عنوان یک بلوک تشخیصی نمایش داده می‌شود. مستقیماً در `VerdictEngine` نقشی ندارد، اما داده‌هایش به `IpConsensusBuilder` می‌رسد.

```text
VpnCheckRunner
├── GeoIpChecker             — GeoIP + نشانه‌های hosting/proxy
├── IpComparisonChecker      — checkerهای IP برای RU/غیر RU (تشخیصی)
├── DirectSignsChecker       — NetworkCapabilities، system proxy، TUN probe، برنامه‌های VPN نصب‌شده
├── IndirectSignsChecker     — اینترفیس‌ها، routeها، DNS، dumpsys، proxy-tech signals
├── CallTransportChecker     — نشست‌های STUN/MTProto (نشت‌ها و دسترسی‌پذیری)
├── CdnPullingChecker        — درخواست‌های HTTPS به CDN/redirector
├── LocationSignalsChecker   — MCC/SIM/cell/Wi-Fi/BeaconDB
├── BypassChecker            — localhost proxy، Xray gRPC API، underlying-network leak
├── RttTriangulationChecker  — SNITCH (β): مثلث‌بندی RTT با هاست‌های RU/خارجی
├── IcmpSpoofingChecker      — جعل ICMP اپراتور (هاست مسدودشده به ping پاسخ می‌دهد)
├── DomainReachabilityChecker — پایپ‌لاین DNS→TCP→TLS برای تشخیص فیلترینگ DPI
├── NativeSignsChecker       — بررسی‌های JNI (مسیرها، اینترفیس‌ها، هوک‌ها، root)
└── IpConsensusBuilder       — اجماع IP بین‌ماژولی
        └── VerdictEngine    — منطق نتیجه نهایی
```

---

## ماژول‌های بررسی

### 1. GeoIP (`GeoIpChecker`)

منابع:

- `https://api.ipapi.is/` — منبع اصلی برای فیلدهای GeoIP و نشانه‌های proxy/VPN/Tor/datacenter
- `https://www.iplocate.io/api/lookup` — منبع fallback برای فیلدهای GeoIP و یک رأی اضافه برای hosting (`privacy.is_hosting`)

منطق:

| سیگنال | کد چه کاری انجام می‌دهد | نتیجه |
|--------|-------------------------|-------|
| `countryCode != RU` | IP خارجی در نظر گرفته می‌شود | `needsReview` اگر هم‌زمان `hosting` و `proxy` وجود نداشته باشند |
| `hosting` | رأی اکثریت بین پاسخ‌های سازگار برای یک IP یکسان (`ipapi.is`, `iplocate.io`) استفاده می‌شود | اگر بیشتر منابع سازگار `hosting=true` بگویند، `detected = true` |
| `proxy` | از ارائه‌دهندگان HTTPS سازگار (`ipapi.is`, `iplocate.io`) استفاده می‌شود | اگر حداقل یک ارائه‌دهنده سازگار proxy/VPN/Tor گزارش کند، `detected = true` |
| `country`, `isp`, `org`, `as`, `query` | از `ipapi.is` گرفته می‌شوند و فیلدهای خالی فقط برای IP سازگار از `iplocate.io` پر می‌شوند | اثر مستقیم ندارند |

نتیجه نهایی دسته:

- `detected = isHosting || isProxy`
- `needsReview = foreignIp && !isHosting && !isProxy`

timeout اتصال و خواندن برای درخواست‌های HTTP(S): ده ثانیه. `GeoIpChecker` فقط از ارائه‌دهندگان HTTPS استفاده می‌کند و تنها وقتی خطا برمی‌گرداند که هیچ ارائه‌دهنده GeoIP داده‌ای برنگرداند.

---

### 2. مقایسه IP checkerها (`IpComparisonChecker`)

این ماژول پاسخ checkerهای عمومی IP در RU و غیر RU را مقایسه می‌کند. در UI به‌عنوان یک بلوک تشخیصی نمایش داده می‌شود. مستقیماً در `VerdictEngine` شرکت نمی‌کند، اما داده‌های آن به `IpConsensusBuilder` می‌رسد که نتایجش در R3 استفاده می‌شود.

گروه سرویس‌ها:

| گروه | سرویس‌ها |
|------|----------|
| `RU` | `Yandex IPv4`, `2ip.ru`, `Yandex IPv6` |
| `NON_RU` | `ifconfig.me IPv4`, `ifconfig.me IPv6`, `checkip.amazonaws.com`, `ipify`, `ip.sb IPv4`, `ip.sb IPv6` |

منطق:

- درون هر گروه، اگر سرویس‌ها با هم سازگار باشند یک `canonicalIp` ساخته می‌شود؛
- اختلاف IP داخل گروه، پاسخ‌های ناقص و تعارض بین `IPv4/IPv6` گروه را بسته به کامل بودن داده‌ها به `needsReview` یا `detected` می‌برد؛
- `detected` کلی فقط وقتی فعال می‌شود که هر دو گروه درون خود به اجماع کامل برسند، ولی گروه RU و غیر RU دو canonical IP متفاوت برگردانند؛
- خطاهای مورد انتظار برای endpointهای IPv6 می‌توانند نادیده گرفته شوند و اجماع IPv4 را نشکنند.

---

### 3. نشانه‌های مستقیم (`DirectSignsChecker`)

نشانه‌های سیستمی بدون اسکن فعال localhost.

#### 3.1 NetworkCapabilities (`checkVpnTransport`)

API: `ConnectivityManager.getNetworkCapabilities(activeNetwork)`

| بررسی | متد/فیلد | نتیجه |
|-------|----------|-------|
| `NetworkCapabilities.TRANSPORT_VPN` | `caps.hasTransport(TRANSPORT_VPN)` | `detected = true` |
| `IS_VPN` | `caps.toString().contains("IS_VPN")` | `detected = true` |
| `VpnTransportInfo` | `caps.toString().contains("VpnTransportInfo")` | `detected = true` |

`IS_VPN` و `VpnTransportInfo` از روی نمایش رشته‌ای `NetworkCapabilities` بررسی می‌شوند.

#### 3.2 System proxy (`checkSystemProxy`)

منابع:

- `System.getProperty("http.proxyHost")` با fallback به `Proxy.getDefaultHost()`
- `System.getProperty("http.proxyPort")` با fallback به `Proxy.getDefaultPort()`
- `System.getProperty("socksProxyHost")`
- `System.getProperty("socksProxyPort")`

منطق:

| وضعیت | نتیجه |
|-------|-------|
| host وجود ندارد | proxy پیکربندی‌نشده در نظر گرفته می‌شود |
| host وجود دارد اما پورت نامعتبر است | `needsReview = true` |
| host و پورت هر دو معتبرند | `detected = true` |
| پورت جزو پورت‌های شناخته‌شده proxy است | یک finding اضافی اضافه می‌شود |

پورت‌های شناخته‌شده proxy: `80`, `443`, `1080`, `3127`, `3128`, `4080`, `5555`, `7000`, `7044`, `8000`, `8080`, `8081`, `8082`, `8888`, `9000`, `9050`, `9051`, `9150`, `12345` و همچنین بازه `16000..16100`.

#### 3.3 TUN Active Probe (`checkTunActiveProbe`)

اگر در هنگام راه‌اندازی یک اینترفیس TUN شناسایی شود، `UnderlyingNetworkProber` درخواست‌های HTTP را از طریق شبکه VPN به هدف‌های RU و non-RU ارسال می‌کند. اختلاف در IP (DNS path mismatch) یا خروج صریح برنامه از per-app VPN (tun0 وجود دارد اما `vpnActive = false`) منجر به `detected = true` می‌شود. این سیگنال از طریق `EvidenceSource.TUN_ACTIVE_PROBE` وارد `VerdictEngine` می‌شود.

#### 3.4 برنامه‌های نصب‌شده VPN/Proxy (`InstalledVpnAppDetector`)

ماژول سه منبع را بررسی می‌کند:

- امضاهای شناخته‌شده package از [`VpnAppCatalog`](../app/src/main/java/com/notcvnt/rknhardering/vpn/VpnAppCatalog.kt)؛
- برنامه‌هایی که از طریق `PackageManager.queryIntentServices`، رابط `VpnService.SERVICE_INTERFACE` را اعلان می‌کنند؛
- برنامه‌هایی که «VPN» در نام خود دارند.

این‌ها سیگنال‌های تشخیصی نصب برنامه یا اعلان `VpnService` هستند، نه تأیید یک تونل فعال. تطبیق‌ها دسته را به `needsReview` می‌برند، اما به‌تنهایی باعث `DirectSignsChecker.detected = true` نمی‌شوند.

---

### 4. نشانه‌های غیرمستقیم (`IndirectSignsChecker`)

#### 4.1 قابلیت `NOT_VPN` (`checkNotVpnCapability`)

روی `ConnectivityManager.getNetworkCapabilities(activeNetwork).toString()` بررسی می‌شود که آیا رشته `NOT_VPN` وجود دارد یا نه.

| نتیجه | خروجی |
|-------|-------|
| `NOT_VPN` وجود دارد | عادی |
| `NOT_VPN` وجود ندارد | `detected = true` |

#### 4.2 اینترفیس‌های شبکه (`checkNetworkInterfaces`)

API: `NetworkInterface.getNetworkInterfaces()`. فقط اینترفیس‌های فعال (`isUp`) بررسی می‌شوند.

الگوهای اینترفیس شبیه VPN:

- `tun\d+`
- `tap\d+`
- `wg\d+`
- `ppp\d+`
- `ipsec.*`

هر اینترفیس فعالی که با این الگوها تطبیق کند، `detected = true` می‌دهد.

#### 4.3 ناهنجاری MTU (`checkMtu`)

منطق:

| شرط | نتیجه |
|-----|-------|
| اینترفیس شبیه VPN با MTU در بازه `1..1499` | `detected = true` |
| اینترفیس فعال غیر استاندارد (نه `wlan.*`, `rmnet.*`, `eth.*`, `lo`) با MTU در بازه `1..1499` | `detected = true` |

#### 4.4 مسیریابی (`checkRoutingTable`)

منابع داده:

- در اولویت اول `LinkProperties.routes` از Android API؛
- fallback: فایل `/proc/net/route` اگر از طریق API نتوان default route را به‌دست آورد.

موارد شناسایی:

- default route از طریق اینترفیس غیر استاندارد؛
- routeهای non-default اختصاصی از طریق VPN/اینترفیس غیر استاندارد؛
- الگوی split tunneling: هم‌زمان routeهای tunnel و یک default route معمولی از طریق شبکه استاندارد دیده می‌شوند.

اگر default route از طریق `wlan.*`, `rmnet.*`, `eth.*`, `lo` باشد و خود شبکه VPN نباشد، حالت عادی محسوب می‌شود.

#### 4.5 DNS (`checkDns`)

API: `ConnectivityManager.getLinkProperties(activeNetwork).dnsServers`

DNS همراه با snapshot شبکه‌های underlying ارزیابی می‌شود، اگر آن‌ها در دسترس باشند.

| سیگنال | نتیجه |
|--------|-------|
| loopback DNS (`127.x.x.x`, `::1`) | `detected = true` |
| private DNS که از همان private/ULA subnet شبکه non-VPN اصلی به ارث رسیده | عادی |
| private DNS هنگام فعال بودن VPN و تفاوت با شبکه underlying | `detected = true` |
| private DNS بدون زمینه کافی | `needsReview = true` |
| public DNS که هنگام VPN جایگزین شده | `needsReview = true` |
| link-local (`169.254.x.x`, `fe80::/10`) | informational |

#### 4.6 نشانه‌های فنی اضافی proxy (`checkProxyTechnicalSignals`)

بررسی می‌شود:

- ابزارهای proxy-only نصب‌شده از `VpnAppCatalog` با سیگنال `LOCAL_PROXY` و بدون `VPN_SERVICE`؛
- listenerهای محلی در `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` روی پورت‌های شناخته‌شده proxy؛
- تعداد زیاد localhost listener روی پورت‌های بالا.

منطق:

- listener روی localhost proxy port شناخته‌شده، `detected = true` می‌دهد؛
- وجود ابزار proxy-only یا تعداد زیاد localhost listener، `needsReview = true` می‌دهد.

یک محدودیت جداگانه هم ثبت می‌شود: بررسی processها، `iptables`/`pf` و گواهی‌های سیستمی بدون root/privileged access ناقص هستند.

#### 4.7 `dumpsys vpn_management` (`checkDumpsysVpn`)

فقط Android 12+ (API 31+). دستور `dumpsys vpn_management` اجرا می‌شود.

اگر parser (`VpnDumpsysParser`) رکوردهای فعال VPN را پیدا کند، آن‌ها `detected = true` می‌دهند. از رکوردها package استخراج می‌شود و با `VpnAppCatalog` تطبیق داده می‌شود:

- package شناخته‌شده: اطمینان بالا؛
- package ناشناخته: `detected = true` و هم‌زمان `needsReview = true`.

خروجی خالی، `Permission Denial` یا دردسترس‌نبودن سرویس به‌عنوان عدم شناسایی در نظر گرفته می‌شود.

#### 4.8 `dumpsys activity services android.net.VpnService` (`checkDumpsysVpnService`)

دستور `dumpsys activity services android.net.VpnService` اجرا می‌شود.

اگر `VpnService` فعال پیدا شود، `activeApps` و evidence ساخته می‌شوند:

- package شناخته‌شده از catalog: اطمینان بالا؛
- package ناشناخته: `detected = true` و `needsReview = true`.

خروجی خالی یا نبودن رکوردهای `VpnService` باعث شناسایی نمی‌شود.

---

### 5. نشانه‌های مکان (`LocationSignalsChecker`)

این ماژول نشانه‌هایی را جمع می‌کند که تأیید می‌کنند دستگاه واقعاً در روسیه قرار دارد یا برعکس، سیگنال‌های تلفنی غیرعادی به نظر می‌رسند.

منابع:

- `TelephonyManager.networkOperator`, `networkCountryIso`, `networkOperatorName`
- `TelephonyManager.simOperator`, `simCountryIso`, `isNetworkRoaming`
- `requestCellInfoUpdate` / `allCellInfo`
- `WifiManager.scanResults` و `BSSID` فعلی
- `BeaconDB` (`https://api.beacondb.net/v1/geolocate`) برای cell/Wi-Fi geolocation
- reverse geocoding برای `countryCode`

مجوزها:

- `ACCESS_FINE_LOCATION` برای cell lookup لازم است؛
- در Android 13+، `NEARBY_WIFI_DEVICES` برای Wi-Fi lookup لازم است.

منطق:

| سیگنال | نتیجه |
|--------|-------|
| `networkMcc == 250` | finding داخلی `network_mcc_ru:true` اضافه می‌شود |
| اگر `BeaconDB`/reverse geocode مقدار `RU` برگرداند | `cell_country_ru:true` و `location_country_ru:true` اضافه می‌شوند |
| `networkMcc != 250` | `needsReview = true` |
| نبود مجوز یا radio data | informational |

در پیاده‌سازی فعلی، `LocationSignalsChecker.detected` همیشه `false` است. نقش اصلی آن در `VerdictEngine` تأیید روسیه و تقویت سیگنال GeoIP خارجی است.

---

### 6. بررسی bypass (`BypassChecker`)

سه بررسی به‌صورت موازی اجرا می‌شوند:

- `ProxyScanner`
- `XrayApiScanner`
- `UnderlyingNetworkProber`

#### 6.1 اسکنر proxy (`ProxyScanner` + `ProxyProber`)

آدرس‌های `127.0.0.1` و `::1` اسکن می‌شوند.

حالت‌ها:

| حالت | توضیح |
|------|-------|
| `AUTO` | ابتدا پورت‌های رایج، سپس کل بازه |
| `MANUAL` | بررسی یک پورت مشخص |

پورت‌های رایج در `AUTO` از `VpnAppCatalog.localhostProxyPorts` ساخته می‌شوند و علاوه بر آن `1081`, `7890`, `7891` نیز اضافه می‌شوند.

اسکن کامل:

- بازه `1024..65535`
- موازی‌سازی `200`
- timeout اتصال `80 ms`
- timeout خواندن `120 ms`

فقط proxyهای بدون احراز هویت شناسایی می‌شوند:

| نوع | روش شناسایی |
|-----|-------------|
| `SOCKS5` | greeting `0x05 0x01 0x00` و پاسخ `0x05 0x00` |
| `HTTP CONNECT` | `CONNECT ifconfig.me:443 HTTP/1.1` و پاسخ `HTTP/1.x 200` |

open localhost proxy به‌تنهایی bypass تأییدشده محسوب نمی‌شود: فقط به‌صورت `needsReview` ثبت می‌شود. تأیید bypass فقط وقتی انجام می‌شود که هم IP مستقیم و هم IP از طریق proxy به‌دست بیاید و با هم متفاوت باشند.

علاوه بر این:

- اگر `SOCKS5` پیدا شود، ولی دریافت HTTP IP از طریق آن ناموفق باشد و پورت شبیه Xray نباشد، `MtProtoProber` اجرا می‌شود؛
- MTProto probe موفق فقط یک finding اطلاعاتی اضافه می‌کند و روی verdict نهایی اثری ندارد.

#### 6.2 اسکنر Xray gRPC API (`XrayApiScanner` + `XrayApiClient`)

آدرس‌های `127.0.0.1` و `::1` اسکن می‌شوند.

پارامترها:

- بازه `1024..65535`
- موازی‌سازی `100`
- TCP connect timeout برابر `200 ms`
- gRPC deadline برابر `2000 ms` با retry روی deadline بزرگ‌تر

این بررسی از طریق raw HTTP/2 preface انجام نمی‌شود، بلکه از یک فراخوانی واقعی gRPC یعنی `HandlerServiceGrpc.listOutbounds(...)` استفاده می‌کند.

در صورت موفقیت:

- endpoint مقدار `detected = true` می‌دهد؛
- در findings حداکثر 10 خلاصه از outboundها (`tag`, `protocol`, `address`, `port`, `sni`) و یک شمارنده برای بقیه اضافه می‌شود.

#### 6.3 Underlying network leak / VPN network binding (`UnderlyingNetworkProber`)

اگر VPN روی دستگاه فعال باشد، ماژول:

- تمام `ConnectivityManager.allNetworks` را پیمایش می‌کند؛
- یک شبکه دارای اینترنت ولی بدون `TRANSPORT_VPN` پیدا می‌کند؛
- درخواست‌های HTTP(S) را به آن شبکه bind می‌کند؛
- IP عمومی را از طریق `ifconfig.me`, `checkip.amazonaws.com`, `ipv4-internet.yandex.net`, `ipv6-internet.yandex.net` درخواست می‌کند.

اگر هنگام فعال بودن VPN، شبکه underlying در دسترس باشد، این وضعیت به‌عنوان `VPN gateway leak` تعبیر می‌شود و `detected = true` می‌دهد.

نتیجه نهایی دسته:

- `detected = confirmed split tunnel || xrayApiFound || vpnGatewayLeak || vpnNetworkBinding`
- اگر open proxy پیدا شود ولی bypass تأیید نشود، `needsReview = true`

---

### 7. CDN Pulling (`CdnPullingChecker`)

درخواست‌های HTTPS را به redirectorها و endpointهای شناخته‌شده trace (مانند Google Video, Cloudflare trace, Meduza) ارسال می‌کند تا ببیند چه IP عمومی یا متادیتا شبکه‌ای نمایش داده می‌شود. تفاوت در پاسخ‌ها می‌تواند نشان‌دهنده پروکسی یا تونل باشد.

### 8. Call Transport (`CallTransportChecker`)

دسترسی‌پذیری UDP/STUN را در endpointهای جهانی و منطقه‌ای بررسی می‌کند و دسترسی‌پذیری TCP MTProto را از طریق پروکسی‌های محلی آزمایش می‌کند. این می‌تواند IPهای عمومی نگاشت‌شده (mapped) یا نشت‌های شبکه‌های زیرین که تونل‌های معمولی را دور می‌زنند، آشکار کند.

### 9. SNITCH — مثلث‌بندی RTT (`RttTriangulationChecker`) β

پینگ ICMP به مجموعه‌ای از هاست‌های روسی و خارجی ارسال می‌کند و میانه‌های زمان رفت‌وبرگشت را مقایسه می‌کند.

اهداف روسی: `yandex.ru`, `mail.ru`, `vk.com`, `sberbank.ru`, `gosuslugi.ru`.

اهداف خارجی: `facebook.com`, `github.com`, `twitter.com`, `reddit.com`, `instagram.com`.

منطق:

- اگر میانه RTT به هاست‌های RU از آستانه (`80 ms`) بیشتر باشد، دستگاه احتمالاً در روسیه نیست؛
- jitter بالا (> 60 ms) اطمینان به نتیجه را کاهش می‌دهد؛
- نتیجه verdict را به `NEEDS_REVIEW` ارتقا می‌دهد، اما به‌تنهایی `DETECTED` تولید نمی‌کند.

این بررسی اختیاری است و به‌طور پیش‌فرض غیرفعال است.

---

### 10. جعل ICMP (`IcmpSpoofingChecker`)

بررسی می‌کند که آیا اپراتور پاسخ‌های ICMP برای هاست‌های مسدودشده را جعل می‌کند.

هدف‌های پیش‌فرض:

- `instagram.com` — هاست مسدودشده (`BLOCKED`)؛
- `google.com` — هاست کنترلی (`CONTROL`).

هدف‌ها از طریق بررسی‌های سفارشی قابل تنظیم هستند. حداقل یک جفت BLOCKED + CONTROL لازم است.

منطق:

| شرط | نتیجه |
|-----|-------|
| هاست BLOCKED به ping پاسخ داد | `needsReview = true` — احتمال جعل ICMP توسط اپراتور |
| هاست CONTROL با RTT < 10 ms پاسخ داد | `needsReview = true` — تأخیر مشکوک کم (احتمال رهگیری محلی) |
| هر دو شرط همزمان | `needsReview = true` با سیگنال قوی‌تر |
| هاست CONTROL پاسخ نداد | نتیجه نامشخص (inconclusive) |
| هیچ‌کدام از موارد بالا | عادی |

`IcmpSpoofingChecker.detected` همیشه `false` است. نتیجه می‌تواند verdict را از `NOT_DETECTED` به `NEEDS_REVIEW` از طریق R6 در `VerdictEngine` ارتقا دهد. به‌طور پیش‌فرض فعال است. در صورت تشخیص home-routed roaming، سیگنال‌ها به‌طور خودکار سرکوب می‌شوند.

---

### 11. دسترسی‌پذیری دامنه (`DomainReachabilityChecker`)

هر دامنه از لیست کاربر را از طریق پایپ‌لاین DNS → TCP → TLS بررسی می‌کند:

| مرحله | فیلترینگ قابل تشخیص | timeout |
|-------|---------------------|---------|
| DNS | NXDOMAIN، timeout | 8 ثانیه |
| TCP :443 | Connection refused، timeout | 8 ثانیه |
| TLS (SNI) | Connection reset — نشانه DPI | 10 ثانیه |

مرحله TLS از trust-all X.509 manager استفاده می‌کند، چون هدف تشخیص قطع اتصال توسط DPI است نه اعتبارسنجی گواهی. `SSLHandshakeException` ناشی از گواهی نامعتبر به‌عنوان موفقیت TLS تلقی می‌شود.

نتایج روی verdict تأثیر نمی‌گذارند. این ماژول به‌طور پیش‌فرض غیرفعال است (`domainReachabilityEnabled = false`) و فقط با ارائه لیست غیرخالی دامنه در تنظیمات بررسی سفارشی فعال می‌شود.

---

### 12. نشانه‌های بومی/Native (`NativeSignsChecker`)

بررسی‌های JNI سطح پایین را مستقیماً از C++ انجام می‌دهد:
- لیست کردن اینترفیس‌های بومی و بررسی‌های `getifaddrs()`
- پردازش مستقیم `/proc/net/route`
- اسکن کردن متنی `/proc/self/maps` برای نشانگرهای شناخته‌شده hook
- بررسی یکپارچگی تفکیک نمادهای `libc`
- تشخیص Root (فایل‌های باینری su، ویژگی‌های magisk، حالت selinux، دسترسی rw مسیر /system و غیره)

یافته‌های سطح بومی می‌توانند به حالت‌های `needsReview` یا نشانه‌های عمومی غیرمستقیم مسیریابی ترجمه شوند.

---

## نتیجه نهایی (`VerdictEngine`)

`VerdictEngine` از تمام بلوک‌های جمع‌آوری‌شده به یک اندازه استفاده نمی‌کند.

**R1 — تشخیص بدون شرط از طریق bypass-evidence:**

اگر هر detected-evidence منبع `SPLIT_TUNNEL_BYPASS`، `XRAY_API`، `VPN_GATEWAY_LEAK` یا `VPN_NETWORK_BINDING` داشته باشد → `DETECTED`.

**R3 — اجماع IP:**

`IpConsensusBuilder` سیگنال‌های GeoIP، IpComparison، CDN Pulling، TUN probe، bypass و callTransportLeaks را یکپارچه می‌کند. اگر `geoAxis` مشخص شود (IP خارجی، geo-country mismatch یا نشانگر Warp) و همزمان `probeTargetDivergence`، `probeTargetDirectDivergence` یا `crossChannelMismatch` وجود داشته باشد → `DETECTED`.

**R4 — مکان در مقابل GeoIP:**

- اگر سیگنال‌های مکان روسیه را تأیید کنند (`network_mcc_ru:true`، `cell_country_ru:true` یا `location_country_ru:true`) و GeoIP همزمان IP خارجی (`outsideRu = true`) نشان دهد → `DETECTED`، مگر در صورت home-routed roaming.
- اگر مکان روسیه را تأیید کند و GeoIP hosting/proxy بدون IP خارجی نشان دهد و سیگنال دیگری نباشد → `NEEDS_REVIEW`.

فلگ `expectedRoamingExit` (توسط `HomeNetworkCatalog` از MCC/MNC سیم‌کارت و ASN تعیین می‌شود) از false positive هنگام رومینگ بین‌المللی با مسیریابی از طریق اپراتور خانگی جلوگیری می‌کند.

**R5 — ماتریس سه‌محوری (geo × direct × indirect):**

- `geoHit` = `GeoIP.outsideRu == true` (به جز رومینگ)
- `directHit` = detected-evidence از `DIRECT_NETWORK_CAPABILITIES` یا `SYSTEM_PROXY`
- `indirectHit` = detected-evidence از `INDIRECT_NETWORK_CAPABILITIES`، `ACTIVE_VPN`، `NETWORK_INTERFACE`، `ROUTING`، `DNS`، `PROXY_TECHNICAL_SIGNAL`، `NATIVE_INTERFACE`، `NATIVE_ROUTE`، `NATIVE_JVM_MISMATCH`

| Geo | Direct | Indirect | Verdict |
|-----|--------|----------|---------|
| خیر | خیر | خیر | `NOT_DETECTED` |
| خیر | بله | خیر | `NOT_DETECTED` |
| خیر | خیر | بله | `NOT_DETECTED` |
| بله | خیر | خیر | `NEEDS_REVIEW` |
| خیر | بله | بله | `NEEDS_REVIEW` (اگر geo در دسترس باشد)، در غیر این صورت `DETECTED` |
| بله | بله | خیر | `DETECTED` |
| بله | خیر | بله | `DETECTED` |
| بله | بله | بله | `DETECTED` |

**R6 — بازگشت به `NEEDS_REVIEW`:**

اگر ماتریس `NOT_DETECTED` داد اما حداقل یکی از شرایط زیر برقرار باشد، نتیجه به `NEEDS_REVIEW` ارتقا می‌یابد:
- `bypassResult.needsReview` (proxy باز بدون تأیید bypass)
- `directSigns.needsReview` یا `indirectSigns.needsReview`
- `locationSignalHit` (location.detected && !expectedRoamingExit)
- نشت actionable از `CallTransportChecker` (وضعیت `NEEDS_REVIEW`، نه از طریق local proxy)
- `icmpSpoofing.needsReview`
- `NativeSignsChecker` نشانگرهای hook (`NATIVE_HOOK_MARKERS`) یا نقض یکپارچگی (`NATIVE_LIBRARY_INTEGRITY`) پیدا کرد
- `ipConsensus.needsReview`، `ipConsensus.channelConflict` غیرخالی، یا `ipConsensus.probeTargetDivergence`
- evidence از نوع `TUN_ACTIVE_PROBE` با `detected = false` (tun وجود دارد اما VPN برای این برنامه فعال نیست)

نکات:

- `IpComparisonChecker` اکنون به‌صورت غیرمستقیم از طریق `IpConsensusBuilder` در R3 شرکت می‌کند؛
- سیگنال‌های `INSTALLED_APP` و `VPN_SERVICE_DECLARATION` وارد ماتریس نمی‌شوند و فقط نقش تشخیصی دارند؛
- `DomainReachabilityChecker` روی verdict تأثیر نمی‌گذارد.

---

## ساخت

نیازمندی‌ها: JDK 17+ و Android SDK با Build Tools برای API 36.

```bash
./gradlew assembleDebug
```

---

## قدردانی

[runetfreedom](https://github.com/runetfreedom) — بابت [per-app-split-bypass-poc](https://github.com/runetfreedom/per-app-split-bypass-poc) که تشخیص per-app split bypass بر پایه آن پیاده‌سازی شده است.
