> **Language:** [Русский](../README.md) | [English](README.en.md) | [فارسی](README.fa.md) | [中文](README.zh-CN.md)

# RKNHardering

Android app for detecting VPNs and proxies on a device. Implements the Roskomnadzor-style methodology for identifying censorship circumvention tools.

Minimum Android version: 8.0 (API 26).

## Architecture

Six independent check modules run in parallel. The final verdict is calculated in `VerdictEngine`.

`IpComparisonChecker` is stored in the result and shown in the UI as a diagnostic block, but in the current version it does not participate in `VerdictEngine`.

```text
VpnCheckRunner
├── GeoIpChecker           — GeoIP + hosting/proxy signals
├── IpComparisonChecker    — RU/non-RU IP checkers (diagnostics)
├── DirectSignsChecker     — NetworkCapabilities, system proxy, installed VPN apps
├── IndirectSignsChecker   — interfaces, routes, DNS, dumpsys, proxy-tech signals
├── CallTransportChecker   — STUN/MTProto (leaks and connectivity)
├── CdnPullingChecker      — HTTPS requests to CDN/redirector
├── LocationSignalsChecker — MCC/SIM/cell/Wi-Fi/BeaconDB
├── BypassChecker          — localhost proxy, Xray gRPC API, underlying-network leak
└── NativeSignsChecker     — JNI checks (routes, hooks, root)
        └── VerdictEngine  — final verdict logic
```

---

## Check Modules

### 1. GeoIP (`GeoIpChecker`)

Sources:

- `https://api.ipapi.is/` — primary source for GeoIP fields and proxy/VPN/Tor/datacenter signals
- `https://www.iplocate.io/api/lookup` — fallback source for GeoIP fields and an additional vote for hosting (`privacy.is_hosting`)

Logic:

| Signal | What the code does | Result |
|--------|--------------------|--------|
| `countryCode != RU` | The IP is treated as foreign | `needsReview` if neither `hosting` nor `proxy` is present |
| `hosting` | Uses majority vote across compatible answers for the same IP (`ipapi.is`, `iplocate.io`) | `detected = true` if most compatible sources say `hosting=true` |
| `proxy` | Uses compatible HTTPS providers (`ipapi.is`, `iplocate.io`) | `detected = true` if at least one compatible provider reports proxy/VPN/Tor |
| `country`, `isp`, `org`, `as`, `query` | Taken from `ipapi.is`, and missing fields are filled from `iplocate.io` only for a compatible IP | no direct effect |

Final category result:

- `detected = isHosting || isProxy`
- `needsReview = foreignIp && !isHosting && !isProxy`

HTTP(S) connect and read timeout: 10 seconds. `GeoIpChecker` uses only HTTPS providers and returns an error only if no GeoIP provider returns data.

---

### 2. IP checker comparison (`IpComparisonChecker`)

This module compares responses from RU and non-RU public IP checkers. It is a diagnostic block: it is shown in the UI, but currently does not participate in `VerdictEngine`.

Service groups:

| Group | Services |
|-------|----------|
| `RU` | `Yandex IPv4`, `2ip.ru`, `Yandex IPv6` |
| `NON_RU` | `ifconfig.me IPv4`, `ifconfig.me IPv6`, `checkip.amazonaws.com`, `ipify`, `ip.sb IPv4`, `ip.sb IPv6` |

Logic:

- inside each group, a `canonicalIp` is built if the services agree;
- IP mismatches within a group, partial responses, and `IPv4/IPv6` family conflicts move the group to `needsReview` or `detected` depending on data completeness;
- the overall `detected` flag is set only if both groups reached full internal consensus but RU and non-RU groups returned different canonical IPs;
- expected IPv6 endpoint errors can be ignored and do not break IPv4 consensus.

---

### 3. Direct signs (`DirectSignsChecker`)

System signs without active localhost network scanning.

#### 3.1 NetworkCapabilities (`checkVpnTransport`)

API: `ConnectivityManager.getNetworkCapabilities(activeNetwork)`

| Check | Method/field | Result |
|-------|--------------|--------|
| `NetworkCapabilities.TRANSPORT_VPN` | `caps.hasTransport(TRANSPORT_VPN)` | `detected = true` |
| `IS_VPN` | `caps.toString().contains("IS_VPN")` | `detected = true` |
| `VpnTransportInfo` | `caps.toString().contains("VpnTransportInfo")` | `detected = true` |

`IS_VPN` and `VpnTransportInfo` are checked through the string representation of `NetworkCapabilities`.

#### 3.2 System proxy (`checkSystemProxy`)

Uses:

- `System.getProperty("http.proxyHost")` with fallback to `Proxy.getDefaultHost()`
- `System.getProperty("http.proxyPort")` with fallback to `Proxy.getDefaultPort()`
- `System.getProperty("socksProxyHost")`
- `System.getProperty("socksProxyPort")`

Logic:

| State | Result |
|-------|--------|
| host is missing | proxy is treated as not configured |
| host exists but port is invalid | `needsReview = true` |
| host exists and port is valid | `detected = true` |
| port matches a known proxy port | an extra finding is added |

Known proxy ports: `80`, `443`, `1080`, `3127`, `3128`, `4080`, `5555`, `7000`, `7044`, `8000`, `8080`, `8081`, `8082`, `8888`, `9000`, `9050`, `9051`, `9150`, `12345`, and the range `16000..16100`.

#### 3.3 Installed VPN/Proxy apps (`InstalledVpnAppDetector`)

The module checks two sources:

- known package signatures from [`VpnAppCatalog`](../app/src/main/java/com/notcvnt/rknhardering/vpn/VpnAppCatalog.kt);
- apps that declare `VpnService.SERVICE_INTERFACE` through `PackageManager.queryIntentServices`.
- the app has "VPN" in the name (this, of course, doesn't 100% guarantee that it's a VPN)
These are diagnostic signals of installation or `VpnService` declaration, not confirmation of an active tunnel. Matches move the category into `needsReview`, but do not by themselves make `DirectSignsChecker.detected = true`.

---

### 4. Indirect signs (`IndirectSignsChecker`)

#### 4.1 `NOT_VPN` capability (`checkNotVpnCapability`)

`ConnectivityManager.getNetworkCapabilities(activeNetwork).toString()` is checked for the presence of `NOT_VPN`.

| Result | Outcome |
|--------|---------|
| `NOT_VPN` present | normal |
| `NOT_VPN` absent | `detected = true` |

#### 4.2 Network interfaces (`checkNetworkInterfaces`)

API: `NetworkInterface.getNetworkInterfaces()`. Only active (`isUp`) interfaces are checked.

VPN-like interface patterns:

- `tun\d+`
- `tap\d+`
- `wg\d+`
- `ppp\d+`
- `ipsec.*`

Any active interface matching these patterns yields `detected = true`.

#### 4.3 MTU anomaly (`checkMtu`)

Logic:

| Condition | Result |
|-----------|--------|
| VPN-like interface with MTU `1..1499` | `detected = true` |
| Non-standard active interface (not `wlan.*`, `rmnet.*`, `eth.*`, `lo`) with MTU `1..1499` | `detected = true` |

#### 4.4 Routing (`checkRoutingTable`)

Data sources:

- primarily `LinkProperties.routes` from the Android API;
- fallback: `/proc/net/route` if the default route could not be obtained via API.

Detections:

- default route through a non-standard interface;
- dedicated non-default routes through VPN/non-standard interfaces;
- split tunneling pattern: tunnel routes visible together with a normal default route through a standard network.

A default route through `wlan.*`, `rmnet.*`, `eth.*`, `lo` is treated as normal if the network itself is not marked as VPN.

#### 4.5 DNS (`checkDns`)

API: `ConnectivityManager.getLinkProperties(activeNetwork).dnsServers`.

DNS is evaluated together with underlying network snapshots when they are available.

| Signal | Result |
|--------|--------|
| loopback DNS (`127.x.x.x`, `::1`) | `detected = true` |
| private DNS inherited from the same private/ULA subnet as the main non-VPN network | normal |
| private DNS while VPN is active and different from the underlying network | `detected = true` |
| private DNS without enough context | `needsReview = true` |
| public DNS replaced while VPN is active | `needsReview = true` |
| link-local (`169.254.x.x`, `fe80::/10`) | informational |

#### 4.6 Additional proxy-technical signals (`checkProxyTechnicalSignals`)

Checks:

- installed proxy-only utilities from `VpnAppCatalog` with `LOCAL_PROXY` signal but without `VPN_SERVICE`;
- local listeners from `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` on known proxy ports;
- a large number of localhost listeners on high ports.

Logic:

- a listener on a known localhost proxy port yields `detected = true`;
- a proxy-only utility or many localhost listeners yields `needsReview = true`.

A separate limitation is recorded: checks for processes, `iptables`/`pf`, and system certificates are incomplete without root/privileged access.

#### 4.7 `dumpsys vpn_management` (`checkDumpsysVpn`)

Android 12+ only (API 31+). Runs `dumpsys vpn_management`.

If the parser (`VpnDumpsysParser`) finds active VPN entries, they yield `detected = true`. A package is extracted from the entries and matched against `VpnAppCatalog`:

- known package: high confidence;
- unknown package: `detected = true` and also `needsReview = true`.

Empty output, `Permission Denial`, or service unavailability are treated as no detection.

#### 4.8 `dumpsys activity services android.net.VpnService` (`checkDumpsysVpnService`)

Runs `dumpsys activity services android.net.VpnService`.

If active `VpnService` instances are found, `activeApps` and evidence are created:

- known package from the catalog: high confidence;
- unknown package: `detected = true` and `needsReview = true`.

Empty output or no `VpnService` entries produce no detection.

---

### 5. Location signals (`LocationSignalsChecker`)

This module collects signs confirming that the device is physically in Russia or, conversely, that telephony signals look atypical.

Sources:

- `TelephonyManager.networkOperator`, `networkCountryIso`, `networkOperatorName`
- `TelephonyManager.simOperator`, `simCountryIso`, `isNetworkRoaming`
- `requestCellInfoUpdate` / `allCellInfo`
- `WifiManager.scanResults` and current `BSSID`
- `BeaconDB` (`https://api.beacondb.net/v1/geolocate`) for cell/Wi-Fi geolocation
- reverse geocoding for `countryCode`

Permissions:

- `ACCESS_FINE_LOCATION` is needed for cell lookup;
- on Android 13+, `NEARBY_WIFI_DEVICES` is needed for Wi-Fi lookup.

Logic:

| Signal | Result |
|--------|--------|
| `networkMcc == 250` | adds the internal finding `network_mcc_ru:true` |
| `BeaconDB`/reverse geocode returned `RU` | adds `cell_country_ru:true` and `location_country_ru:true` |
| `networkMcc != 250` | `needsReview = true` |
| missing permissions or radio data | informational |

In the current implementation, `LocationSignalsChecker.detected` is always `false`. Its main role in `VerdictEngine` is to confirm Russia and strengthen a foreign GeoIP signal.

---

### 6. Bypass check (`BypassChecker`)

Three checks run in parallel:

- `ProxyScanner`
- `XrayApiScanner`
- `UnderlyingNetworkProber`

#### 6.1 Proxy scanner (`ProxyScanner` + `ProxyProber`)

Scans `127.0.0.1` and `::1`.

Modes:

| Mode | Description |
|------|-------------|
| `AUTO` | first common ports, then full range |
| `MANUAL` | check a single specified port |

Popular ports in `AUTO` are built from `VpnAppCatalog.localhostProxyPorts` and additionally include `1081`, `7890`, `7891`.

Full scan:

- range `1024..65535`
- parallelism `200`
- connect timeout `80 ms`
- read timeout `120 ms`

Only proxies without authentication are detected:

| Type | How it is detected |
|------|--------------------|
| `SOCKS5` | greeting `0x05 0x01 0x00` and reply `0x05 0x00` |
| `HTTP CONNECT` | `CONNECT ifconfig.me:443 HTTP/1.1` and reply `HTTP/1.x 200` |

An open localhost proxy is not treated as confirmed bypass by itself: it is recorded as `needsReview`. Bypass confirmation is set only if both a direct IP and a proxy IP can be obtained and they differ.

Additionally:

- if `SOCKS5` is found, but HTTP IP retrieval through it fails and the port does not look like Xray, `MtProtoProber` is launched;
- a successful MTProto probe adds an informative finding, but does not affect the final verdict.

#### 6.2 Xray gRPC API scanner (`XrayApiScanner` + `XrayApiClient`)

Scans `127.0.0.1` and `::1`.

Parameters:

- range `1024..65535`
- parallelism `100`
- TCP connect timeout `200 ms`
- gRPC deadline `2000 ms` with retry on an increased deadline

The check is performed not through a raw HTTP/2 preface, but through a real gRPC call `HandlerServiceGrpc.listOutbounds(...)`.

On success:

- the endpoint yields `detected = true`;
- findings include up to 10 outbound summaries (`tag`, `protocol`, `address`, `port`, `sni`) plus a counter for remaining ones.

#### 6.3 Underlying network leak / VPN network binding (`UnderlyingNetworkProber`)

If VPN is active on the device, the module:

- iterates through all `ConnectivityManager.allNetworks`;
- looks for an internet-capable network without `TRANSPORT_VPN`;
- binds HTTP(S) requests to that network;
- requests the public IP through `ifconfig.me`, `checkip.amazonaws.com`, `ipv4-internet.yandex.net`, `ipv6-internet.yandex.net`.

If the underlying network is reachable while VPN is active, this is treated as `VPN gateway leak` and yields `detected = true`.

Final category result:

- `detected = confirmed split tunnel || xrayApiFound || vpnGatewayLeak || vpnNetworkBinding`
- `needsReview = true` if an open proxy is found but the bypass is not confirmed

---

### 7. CDN Pulling (`CdnPullingChecker`)

Sends HTTPS requests to known redirectors and trace endpoints (e.g., Google Video, Cloudflare trace, Meduza) to see what public IP or network metadata is exposed.

### 8. Call Transport (`CallTransportChecker`)

Checks UDP/STUN accessibility across global and regional endpoints, and tests TCP MTProto reachability via local proxies. This can reveal mapped public IPs or underlying leaks that bypass conventional tunnels.

### 9. Native Signs (`NativeSignsChecker`)

Performs low-level JNI checks directly from C++:
- Native interface listing and `getifaddrs()` checks
- Direct `/proc/net/route` parsing
- `/proc/self/maps` scanning for known hook markers
- `libc` symbol resolution integrity
- Root detection (su binaries, magisk properties, selinux, rw /system, etc.)

Native findings can translate into `needsReview` or generic indirect routing signals.

---

## Verdict (`VerdictEngine`)

`VerdictEngine` does not use all collected blocks equally.

First, unconditional rules are applied:

1. `DETECTED` if bypass evidence contains `SPLIT_TUNNEL_BYPASS`.
2. `DETECTED` if `XRAY_API` is found.
3. `DETECTED` if `VPN_GATEWAY_LEAK` is found.
4. `DETECTED` if location signals confirm Russia (`network_mcc_ru:true`, `cell_country_ru:true`, or `location_country_ru:true`) while `GeoIP` simultaneously reports a foreign signal.

Then a matrix is computed:

- `geoMatrixHit` = foreign GeoIP signal (`geoIp.needsReview` or `GEO_IP` evidence)
- `directMatrixHit` = evidence from `DIRECT_NETWORK_CAPABILITIES` or `SYSTEM_PROXY`
- `indirectMatrixHit` = evidence from `INDIRECT_NETWORK_CAPABILITIES`, `ACTIVE_VPN`, `NETWORK_INTERFACE`, `ROUTING`, `DNS`, `PROXY_TECHNICAL_SIGNAL`

Combinations:

| Geo | Direct | Indirect | Verdict |
|-----|--------|----------|---------|
| no | no | no | `NOT_DETECTED` |
| no | yes | no | `NOT_DETECTED` |
| no | no | yes | `NOT_DETECTED` |
| yes | no | no | `NEEDS_REVIEW` |
| no | yes | yes | `NEEDS_REVIEW` |
| any other combination | | | `DETECTED` |

Notes:

- `IpComparisonChecker` currently does not participate in `VerdictEngine`;
- `INSTALLED_APP` and `VPN_SERVICE_DECLARATION` signals are also not part of the matrix and remain diagnostic;
- Actionable leaks from `CallTransportChecker` or review hits from `NativeSignsChecker` (e.g., hook markers) upgrade `NOT_DETECTED` to `NEEDS_REVIEW`.

---

## Build

Requirements: JDK 17+, Android SDK with Build Tools for API 36.

```bash
./gradlew assembleDebug
```

---

## Acknowledgements

[runetfreedom](https://github.com/runetfreedom) — for [per-app-split-bypass-poc](https://github.com/runetfreedom/per-app-split-bypass-poc), which the per-app split bypass detection is based on.
