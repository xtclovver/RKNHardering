> **Language:** [Русский](../README.md) | [English](README.en.md) | [فارسی](README.fa.md) | [中文](README.zh-CN.md)

# RKNHardering

<a href="https://matrix.to/#/%23RKN_Hardering:matrix.kangel.tech"><img src="https://img.shields.io/badge/matrix-%23000000?style=for-the-badge&logo=matrix&logoColor=white" alt="Matrix" width="200"></a>
<a href="https://t.me/RKNHardering"><img src="https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram" width="200"></a>

用于检测设备上 VPN 和代理的 Android 应用。该项目实现了一套类似 Roskomnadzor 的封锁绕过工具识别方法。

最低 Android 版本：8.0（API 26）。

您可以从以下位置下载本项目：
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


## 需要社区帮助 / Community Help Wanted

本项目记录了在 Android 设备上检测 VPN 和代理的方法。然而，**反向问题**——如何防止 VPN 被检测到——的研究还远不够充分。

我正在寻找愿意帮忙收集、整理和测试绕过检测方法的人，包括但不限于：

- **隐藏网络接口**（如何让 `NetworkInterface.getNetworkInterfaces()` 和 `/proc/net/route` 无法看到 `tun0`、`wg0` 等类 VPN 接口）
- **伪造 NetworkCapabilities**（从 `ConnectivityManager` 的响应中移除 `TRANSPORT_VPN`、`IS_VPN`、`VpnTransportInfo`）
- **隐藏 dumpsys 信息**（防止通过 `dumpsys vpn_management` 和 `dumpsys activity services android.net.VpnService` 泄露信息）
- **MTU 标准化**（在不同客户端上将隧道接口的 MTU 设置为标准的 1500）
- **DNS 泄漏**（防止在 VPN 激活时检测到 loopback/private DNS）
- **隐藏 localhost 代理**（如何防止通过 `/proc/net/tcp` 和端口扫描被发现）
- **绕过原生检查**（对抗通过 `/proc/self/maps`、`getifaddrs()`、`dlsym` 进行的 JNI 检查）
- **隐藏已安装的应用**（对 `PackageManager` 隐藏 VPN 应用的包名）

如果你在这些领域有专业知识，请提交 Issue 或 Pull Request，或在 [Matrix 聊天室](https://matrix.to/#/%23RKN_Hardering:matrix.kangel.tech)/[Telegram](https://t.me/RKNHardering) 中描述方法、适用条件和限制。任何信息都很有价值——从理论想法到可用的 PoC。

## 架构

各独立检查模块并行运行。最终结论由 `VerdictEngine` 计算。

`IpComparisonChecker` 会保存在结果中，并在 UI 中作为诊断模块显示。不直接参与 `VerdictEngine`，但其数据会输入 `IpConsensusBuilder`。

```text
VpnCheckRunner
├── GeoIpChecker             — GeoIP + hosting/proxy 信号
├── IpComparisonChecker      — RU/非 RU IP checker（诊断）
├── DirectSignsChecker       — NetworkCapabilities、系统代理、TUN 探测、已安装 VPN 应用
├── IndirectSignsChecker     — 接口、路由、DNS、dumpsys、proxy-tech signals
├── CallTransportChecker     — STUN/MTProto 探测（泄漏与连通性）
├── CdnPullingChecker        — 对 CDN/redirector 的 HTTPS 请求
├── LocationSignalsChecker   — MCC/SIM/cell/Wi-Fi/BeaconDB
├── BypassChecker            — localhost 代理、Xray gRPC API、underlying-network leak
├── RttTriangulationChecker  — SNITCH（β）：针对 RU/境外主机的 RTT 三角测量
├── IcmpSpoofingChecker      — 运营商 ICMP 欺骗检测（被封锁主机回复 ping）
├── DomainReachabilityChecker — DNS→TCP→TLS 流水线，用于检测 DPI 封锁
├── NativeSignsChecker       — JNI 检查（路由、接口、钩子、root 等）
└── IpConsensusBuilder       — 跨模块 IP 共识
        └── VerdictEngine    — 最终结论逻辑
```

---

## 检查模块

### 1. GeoIP (`GeoIpChecker`)

数据源：

- `https://api.ipapi.is/` — GeoIP 字段以及 proxy/VPN/Tor/datacenter 信号的主来源
- `https://www.iplocate.io/api/lookup` — GeoIP 字段的 fallback 来源，并提供一票额外的 hosting 判断（`privacy.is_hosting`）

逻辑：

| 信号 | 代码行为 | 结果 |
|------|----------|------|
| `countryCode != RU` | 将 IP 视为境外地址 | 如果同时不存在 `hosting` 和 `proxy`，则 `needsReview` |
| `hosting` | 对同一 IP 的兼容响应使用多数投票（`ipapi.is`, `iplocate.io`） | 如果多数兼容来源都说 `hosting=true`，则 `detected = true` |
| `proxy` | 使用兼容的 HTTPS 提供方（`ipapi.is`, `iplocate.io`） | 如果至少一个兼容提供方报告 proxy/VPN/Tor，则 `detected = true` |
| `country`, `isp`, `org`, `as`, `query` | 首先取自 `ipapi.is`，仅对兼容 IP 用 `iplocate.io` 补齐缺失字段 | 不直接影响判定 |

类别最终结果：

- `detected = isHosting || isProxy`
- `needsReview = foreignIp && !isHosting && !isProxy`

HTTP(S) 连接与读取超时：10 秒。`GeoIpChecker` 只使用 HTTPS 提供方，并且只有在没有任何 GeoIP 提供方返回数据时才会返回错误。

---

### 2. IP checker 比较 (`IpComparisonChecker`)

该模块比较 RU 与非 RU 公网 IP checker 的响应。在 UI 中作为诊断模块显示。不直接参与 `VerdictEngine`，但其数据会输入 `IpConsensusBuilder`，后者的结果用于 R3。

服务分组：

| 组别 | 服务 |
|------|------|
| `RU` | `Yandex IPv4`, `2ip.ru`, `Yandex IPv6` |
| `NON_RU` | `ifconfig.me IPv4`, `ifconfig.me IPv6`, `checkip.amazonaws.com`, `ipify`, `ip.sb IPv4`, `ip.sb IPv6` |

逻辑：

- 在每个组内，如果各服务结果一致，则构建 `canonicalIp`；
- 同组内 IP 不一致、响应不完整以及 `IPv4/IPv6` 地址族冲突，会根据数据完整性将该组标记为 `needsReview` 或 `detected`；
- 总体 `detected` 仅在两个组内部都完全一致、但 RU 与非 RU 组返回不同 canonical IP 时才会置为 true；
- 对 IPv6 endpoint 的预期错误可以被忽略，不会破坏 IPv4 共识。

---

### 3. 直接迹象 (`DirectSignsChecker`)

不进行 localhost 主动网络扫描时的系统级迹象。

#### 3.1 NetworkCapabilities (`checkVpnTransport`)

API：`ConnectivityManager.getNetworkCapabilities(activeNetwork)`

| 检查项 | 方法/字段 | 结果 |
|--------|-----------|------|
| `NetworkCapabilities.TRANSPORT_VPN` | `caps.hasTransport(TRANSPORT_VPN)` | `detected = true` |
| `IS_VPN` | `caps.toString().contains("IS_VPN")` | `detected = true` |
| `VpnTransportInfo` | `caps.toString().contains("VpnTransportInfo")` | `detected = true` |

`IS_VPN` 和 `VpnTransportInfo` 都是通过 `NetworkCapabilities` 的字符串表示来检查的。

#### 3.2 系统代理 (`checkSystemProxy`)

使用：

- `System.getProperty("http.proxyHost")`，回退到 `Proxy.getDefaultHost()`
- `System.getProperty("http.proxyPort")`，回退到 `Proxy.getDefaultPort()`
- `System.getProperty("socksProxyHost")`
- `System.getProperty("socksProxyPort")`

逻辑：

| 状态 | 结果 |
|------|------|
| host 不存在 | 视为未配置代理 |
| host 存在但端口无效 | `needsReview = true` |
| host 与端口都有效 | `detected = true` |
| 端口属于已知代理端口 | 增加一条额外 finding |

已知代理端口：`80`, `443`, `1080`, `3127`, `3128`, `4080`, `5555`, `7000`, `7044`, `8000`, `8080`, `8081`, `8082`, `8888`, `9000`, `9050`, `9051`, `9150`, `12345`，以及范围 `16000..16100`。

#### 3.3 TUN 主动探测 (`checkTunActiveProbe`)

如果初始化时检测到 TUN 接口，`UnderlyingNetworkProber` 会通过 VPN 网络向 RU 和非 RU 目标发送 HTTP 请求。若出现 DNS 路径不一致（VPN 与直连路径的 IP 不同），或应用被明确排除在 per-app VPN 之外（tun0 存在但 `vpnActive = false`），则 `detected = true`。该信号通过 `EvidenceSource.TUN_ACTIVE_PROBE` 进入 `VerdictEngine`。

#### 3.4 已安装的 VPN/代理应用 (`InstalledVpnAppDetector`)

该模块检查三个来源：

- [`VpnAppCatalog`](../app/src/main/java/com/notcvnt/rknhardering/vpn/VpnAppCatalog.kt) 中的已知包名签名；
- 通过 `PackageManager.queryIntentServices` 声明了 `VpnService.SERVICE_INTERFACE` 的应用；
- 名称中包含”VPN”的应用。

这些只是安装状态或 `VpnService` 声明的诊断信号，并不表示活动隧道已被确认。匹配结果会将该类别标记为 `needsReview`，但不会单独让 `DirectSignsChecker.detected = true`。

---

### 4. 间接迹象 (`IndirectSignsChecker`)

#### 4.1 `NOT_VPN` capability (`checkNotVpnCapability`)

通过 `ConnectivityManager.getNetworkCapabilities(activeNetwork).toString()` 检查是否包含 `NOT_VPN`。

| 结果 | 含义 |
|------|------|
| `NOT_VPN` 存在 | 正常 |
| `NOT_VPN` 不存在 | `detected = true` |

#### 4.2 网络接口 (`checkNetworkInterfaces`)

API：`NetworkInterface.getNetworkInterfaces()`。仅检查活动接口（`isUp`）。

类 VPN 接口模式：

- `tun\d+`
- `tap\d+`
- `wg\d+`
- `ppp\d+`
- `ipsec.*`

任何匹配这些模式的活动接口都会产生 `detected = true`。

#### 4.3 MTU 异常 (`checkMtu`)

逻辑：

| 条件 | 结果 |
|------|------|
| 类 VPN 接口的 MTU 位于 `1..1499` | `detected = true` |
| 非标准活动接口（不是 `wlan.*`, `rmnet.*`, `eth.*`, `lo`）的 MTU 位于 `1..1499` | `detected = true` |

#### 4.4 路由 (`checkRoutingTable`)

数据来源：

- 优先使用 Android API 中的 `LinkProperties.routes`；
- fallback：若无法通过 API 获取默认路由，则读取 `/proc/net/route`。

检测条件：

- 默认路由经过非标准接口；
- 专用的非默认路由经过 VPN/非标准接口；
- split tunneling 模式：同时可见 tunnel 路由与经过标准网络的正常默认路由。

如果默认路由经过 `wlan.*`, `rmnet.*`, `eth.*`, `lo`，且该网络本身没有被标记为 VPN，则视为正常。

#### 4.5 DNS (`checkDns`)

API：`ConnectivityManager.getLinkProperties(activeNetwork).dnsServers`

若 underlying 网络快照可用，DNS 会结合这些快照一起评估。

| 信号 | 结果 |
|------|------|
| loopback DNS (`127.x.x.x`, `::1`) | `detected = true` |
| 继承自主 non-VPN 网络相同私有/ULA 子网的 private DNS | 正常 |
| VPN 活跃且 private DNS 与 underlying 网络不同 | `detected = true` |
| 在缺少足够上下文时出现 private DNS | `needsReview = true` |
| VPN 活跃时 public DNS 被替换 | `needsReview = true` |
| link-local (`169.254.x.x`, `fe80::/10`) | 仅信息 |

#### 4.6 额外代理技术信号 (`checkProxyTechnicalSignals`)

检查内容：

- `VpnAppCatalog` 中不带 `VPN_SERVICE`、但带有 `LOCAL_PROXY` 信号的 proxy-only 工具；
- `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` 中已知代理端口上的本地 listener；
- 高位端口上大量的 localhost listener。

逻辑：

- 已知 localhost 代理端口上的 listener 会产生 `detected = true`；
- proxy-only 工具或大量 localhost listener 会产生 `needsReview = true`。

同时还会单独记录一个限制：在没有 root/privileged access 的情况下，进程、`iptables`/`pf` 和系统证书的检查并不完整。

#### 4.7 `dumpsys vpn_management` (`checkDumpsysVpn`)

仅限 Android 12+（API 31+）。执行 `dumpsys vpn_management`。

如果解析器（`VpnDumpsysParser`）发现活动 VPN 记录，就会产生 `detected = true`。同时会从记录中提取包名，再与 `VpnAppCatalog` 匹配：

- 已知包名：高置信度；
- 未知包名：`detected = true`，同时 `needsReview = true`。

空输出、`Permission Denial` 或服务不可用都视为未检测到。

#### 4.8 `dumpsys activity services android.net.VpnService` (`checkDumpsysVpnService`)

执行 `dumpsys activity services android.net.VpnService`。

如果发现活动的 `VpnService`，会生成 `activeApps` 和 evidence：

- 目录中的已知包名：高置信度；
- 未知包名：`detected = true` 且 `needsReview = true`。

空输出或不存在 `VpnService` 记录都不会触发检测。

---

### 5. 位置迹象 (`LocationSignalsChecker`)

该模块收集能够证明设备物理上位于俄罗斯，或相反地表明移动网络信号异常的迹象。

来源：

- `TelephonyManager.networkOperator`, `networkCountryIso`, `networkOperatorName`
- `TelephonyManager.simOperator`, `simCountryIso`, `isNetworkRoaming`
- `requestCellInfoUpdate` / `allCellInfo`
- `WifiManager.scanResults` 与当前 `BSSID`
- `BeaconDB`（`https://api.beacondb.net/v1/geolocate`）用于 cell/Wi-Fi geolocation
- `countryCode` 的 reverse geocoding

权限：

- `ACCESS_FINE_LOCATION` 用于 cell lookup；
- 在 Android 13+ 上，`NEARBY_WIFI_DEVICES` 用于 Wi-Fi lookup。

逻辑：

| 信号 | 结果 |
|------|------|
| `networkMcc == 250` | 添加内部 finding `network_mcc_ru:true` |
| `BeaconDB`/reverse geocode 返回 `RU` | 添加 `cell_country_ru:true` 与 `location_country_ru:true` |
| `networkMcc != 250` | `needsReview = true` |
| 缺少权限或 radio data | 仅信息 |

在当前实现中，`LocationSignalsChecker.detected` 永远为 `false`。它在 `VerdictEngine` 中的主要作用是确认“设备在俄罗斯”并加强境外 GeoIP 信号。

---

### 6. Bypass 检查 (`BypassChecker`)

以下三项检查并行执行：

- `ProxyScanner`
- `XrayApiScanner`
- `UnderlyingNetworkProber`

#### 6.1 代理扫描器 (`ProxyScanner` + `ProxyProber`)

扫描 `127.0.0.1` 与 `::1`。

模式：

| 模式 | 说明 |
|------|------|
| `AUTO` | 先扫常用端口，再扫完整范围 |
| `MANUAL` | 检查单个指定端口 |

`AUTO` 模式下的常用端口由 `VpnAppCatalog.localhostProxyPorts` 构造，并额外包含 `1081`, `7890`, `7891`。

完整扫描参数：

- 范围 `1024..65535`
- 并发度 `200`
- 连接超时 `80 ms`
- 读取超时 `120 ms`

只识别无认证的代理：

| 类型 | 识别方式 |
|------|----------|
| `SOCKS5` | greeting `0x05 0x01 0x00` 与响应 `0x05 0x00` |
| `HTTP CONNECT` | `CONNECT ifconfig.me:443 HTTP/1.1` 与响应 `HTTP/1.x 200` |

开放的 localhost 代理本身并不会被视为“确认存在绕过”：它只会被记录为 `needsReview`。只有在能够同时拿到直连 IP 与代理 IP，且二者不同的情况下，才会确认绕过。

此外：

- 如果找到了 `SOCKS5`，但无法通过它获取 HTTP IP，且该端口又不像 Xray，则会启动 `MtProtoProber`；
- MTProto probe 成功只会增加一条说明性 finding，不影响最终 verdict。

#### 6.2 Xray gRPC API 扫描器 (`XrayApiScanner` + `XrayApiClient`)

扫描 `127.0.0.1` 与 `::1`。

参数：

- 范围 `1024..65535`
- 并发度 `100`
- TCP 连接超时 `200 ms`
- gRPC deadline `2000 ms`，超时后会以更大 deadline 重试

该检查不是通过原始 HTTP/2 preface，而是通过真实的 gRPC 调用 `HandlerServiceGrpc.listOutbounds(...)` 完成的。

成功时：

- endpoint 会产生 `detected = true`；
- findings 中会加入最多 10 条 outbound 摘要（`tag`, `protocol`, `address`, `port`, `sni`）以及剩余数量计数。

#### 6.3 Underlying network leak / VPN network binding (`UnderlyingNetworkProber`)

如果设备上 VPN 处于活动状态，该模块会：

- 枚举所有 `ConnectivityManager.allNetworks`；
- 查找一个具备互联网能力、但没有 `TRANSPORT_VPN` 的网络；
- 将 HTTP(S) 请求绑定到该网络；
- 通过 `ifconfig.me`, `checkip.amazonaws.com`, `ipv4-internet.yandex.net`, `ipv6-internet.yandex.net` 请求公网 IP。

如果在 VPN 激活时 underlying 网络仍可访问，则会被视为 `VPN gateway leak`，并产生 `detected = true`。

类别最终结果：

- `detected = confirmed split tunnel || xrayApiFound || vpnGatewayLeak || vpnNetworkBinding`
- 如果发现开放代理但无法确认绕过，则 `needsReview = true`

---

### 7. CDN Pulling (`CdnPullingChecker`)

向已知的 redirector 和 trace 端点（例如 Google Video、Cloudflare trace、Meduza）发送 HTTPS 请求，以查看暴露了什么公网 IP 或网络元数据。响应内容的不同往往能指示代理或隧道的存在。

### 8. Call Transport (`CallTransportChecker`)

检查全球与区域端点的 UDP/STUN 可达性，并通过本地代理测试 TCP MTProto 的连通性。该项检查能够揭示重定向的公网 IP 或是绕过常规隧道的底层网络泄漏。

### 9. SNITCH — RTT 三角测量 (`RttTriangulationChecker`) β

向一组俄罗斯和境外主机发送 ICMP ping，并比较各自的中位往返时延。

俄罗斯目标：`yandex.ru`、`mail.ru`、`vk.com`、`sberbank.ru`、`gosuslugi.ru`。

境外目标：`facebook.com`、`github.com`、`twitter.com`、`reddit.com`、`instagram.com`。

逻辑：

- 若到俄罗斯主机的中位 RTT 超过阈值（`80 ms`），则设备很可能不在俄罗斯境内；
- 高抖动（> 60 ms）会降低结论的置信度；
- 检测结果会将判定升级为 `NEEDS_REVIEW`，但本身不会产生 `DETECTED`。

该检查为可选项，默认关闭。

---

### 10. ICMP 欺骗检测 (`IcmpSpoofingChecker`)

检测运营商是否伪造被封锁主机的 ICMP 回复。

默认目标：

- `instagram.com` — 被封锁主机（`BLOCKED`）；
- `google.com` — 控制主机（`CONTROL`）。

目标可通过自定义检查进行配置，至少需要一对 BLOCKED + CONTROL 目标。

逻辑：

| 条件 | 结果 |
|------|------|
| BLOCKED 主机回复了 ping | `needsReview = true` — 可能存在运营商 ICMP 欺骗 |
| CONTROL 主机以 RTT < 10 ms 回复 | `needsReview = true` — 延迟异常低（可能存在本地拦截） |
| 两个条件同时满足 | `needsReview = true`，信号更强 |
| CONTROL 主机未回复 | 结果不确定（inconclusive） |
| 以上均不满足 | 正常 |

`IcmpSpoofingChecker.detected` 始终为 `false`。结果可通过 `VerdictEngine` 中的 R6 将判定从 `NOT_DETECTED` 升级为 `NEEDS_REVIEW`。默认启用。检测到 home-routed 漫游时，相关信号会被自动抑制。

---

### 11. 域名可达性检测 (`DomainReachabilityChecker`)

通过 DNS → TCP → TLS 流水线检查用户配置列表中的每个域名：

| 步骤 | 可检测的封锁类型 | 超时 |
|------|-----------------|------|
| DNS | NXDOMAIN、超时 | 8 秒 |
| TCP :443 | 连接拒绝、超时 | 8 秒 |
| TLS (SNI) | 连接重置——DPI 封锁标志 | 10 秒 |

TLS 步骤使用信任所有证书的 X.509 manager，因为目标是检测 DPI 的连接重置，而非验证证书有效性。由无效证书引发的 `SSLHandshakeException` 被视为 TLS 握手成功。

结果不影响最终判定。该模块默认禁用（`domainReachabilityEnabled = false`），仅在自定义检查设置中提供了非空域名列表时才会激活。

---

### 12. 原生迹象 (`NativeSignsChecker`)

直接在 C++ 层执行底层 JNI 检查：
- 枚举原生接口并检查 `getifaddrs()`
- 直接解析 `/proc/net/route`
- 扫描 `/proc/self/maps` 寻找已知的 hook 标记
- 检查 `libc` 符号解析 (dlsym) 的完整性
- 检查 Root（su 二进制文件、magisk 属性、selinux 状态、/system rw 挂载等）

原生发现可被解释为 `needsReview` 或一般的间接路由迹象。

---

## 结论 (`VerdictEngine`)

`VerdictEngine` 并不会同等使用所有收集到的模块结果。

**R1 — 通过 bypass evidence 的无条件检测：**

若任何 detected evidence 的来源为 `SPLIT_TUNNEL_BYPASS`、`XRAY_API`、`VPN_GATEWAY_LEAK` 或 `VPN_NETWORK_BINDING` → `DETECTED`。

**R3 — IP 共识：**

`IpConsensusBuilder` 整合来自 GeoIP、IpComparison、CDN Pulling、TUN 探测、bypass 和 callTransportLeaks 的信号。若确定了 `geoAxis`（境外 IP、地理国家不匹配或 Warp 指标），且同时存在 `probeTargetDivergence`、`probeTargetDirectDivergence` 或 `crossChannelMismatch` → `DETECTED`。

**R4 — 位置与 GeoIP 对比：**

- 若位置信号确认设备在俄罗斯（`network_mcc_ru:true`、`cell_country_ru:true` 或 `location_country_ru:true`），而 GeoIP 同时显示境外 IP（`outsideRu = true`）→ `DETECTED`，home-routed 漫游除外。
- 若位置确认在俄罗斯，但 GeoIP 显示 hosting/proxy 且无境外 IP，且无其他信号 → `NEEDS_REVIEW`。

`expectedRoamingExit` 标志（由 `HomeNetworkCatalog` 根据 SIM 卡的 MCC/MNC 和 ASN 确定）用于防止使用外国 SIM 卡并通过归属运营商路由时产生误报。

**R5 — 三轴矩阵（geo × direct × indirect）：**

- `geoHit` = `GeoIP.outsideRu == true`（漫游除外）
- `directHit` = 来自 `DIRECT_NETWORK_CAPABILITIES` 或 `SYSTEM_PROXY` 的 detected evidence
- `indirectHit` = 来自 `INDIRECT_NETWORK_CAPABILITIES`、`ACTIVE_VPN`、`NETWORK_INTERFACE`、`ROUTING`、`DNS`、`PROXY_TECHNICAL_SIGNAL`、`NATIVE_INTERFACE`、`NATIVE_ROUTE`、`NATIVE_JVM_MISMATCH` 的 detected evidence

| Geo | Direct | Indirect | Verdict |
|-----|--------|----------|---------|
| 否 | 否 | 否 | `NOT_DETECTED` |
| 否 | 是 | 否 | `NOT_DETECTED` |
| 否 | 否 | 是 | `NOT_DETECTED` |
| 是 | 否 | 否 | `NEEDS_REVIEW` |
| 否 | 是 | 是 | `NEEDS_REVIEW`（若 geo 可用），否则 `DETECTED` |
| 是 | 是 | 否 | `DETECTED` |
| 是 | 否 | 是 | `DETECTED` |
| 是 | 是 | 是 | `DETECTED` |

**R6 — 回退至 `NEEDS_REVIEW`：**

若矩阵返回 `NOT_DETECTED`，但满足以下至少一个条件，则结果升级为 `NEEDS_REVIEW`：
- `bypassResult.needsReview`（发现开放代理但未确认绕过）
- `directSigns.needsReview` 或 `indirectSigns.needsReview`
- `locationSignalHit`（location.detected && !expectedRoamingExit）
- 来自 `CallTransportChecker` 的可操作泄漏（状态为 `NEEDS_REVIEW`，且非通过本地代理）
- `icmpSpoofing.needsReview`
- `NativeSignsChecker` 发现了 hook 标记（`NATIVE_HOOK_MARKERS`）或完整性违规（`NATIVE_LIBRARY_INTEGRITY`）
- `ipConsensus.needsReview`、`ipConsensus.channelConflict` 非空，或 `ipConsensus.probeTargetDivergence`
- `TUN_ACTIVE_PROBE` evidence 的 `detected = false`（tun 存在但该应用的 VPN 未激活）

说明：

- `IpComparisonChecker` 现在通过 `IpConsensusBuilder` 间接参与 R3；
- `INSTALLED_APP` 与 `VPN_SERVICE_DECLARATION` 信号不属于该矩阵，仅用于诊断；
- `DomainReachabilityChecker` 不影响最终判定。

---

## 构建

要求：JDK 17+，以及包含 API 36 Build Tools 的 Android SDK。

```bash
./gradlew assembleDebug
```

---

## 致谢

[runetfreedom](https://github.com/runetfreedom) — 感谢他们提供 [per-app-split-bypass-poc](https://github.com/runetfreedom/per-app-split-bypass-poc)，本项目中的 per-app split bypass 检测正是基于此实现的。
