---
title: 检查与应对措施完整矩阵
permalink: /help/zh-CN/anti-detection/matrix/
---

# 检查与应对措施完整矩阵

本页用于核对当前 RKNHardering 2.10.0 源码树的覆盖完整性，不能替代各专题页面。表格中的“无 root”与“有 root”描述的是如何改变可观察状态，而不是保证一定通过检查。外部项目在某个特定内核或 ROM 上可能只覆盖一行中的部分通道。具体下载与分步安装集中在 [VPNHide、VPNHide Next 与 root 技术栈](../root-vpnhide/)页面，第一方参考资料见[来源](../sources/)。

## 1. 全部 `EvidenceSource` 值 — 65

| ID | 区域 | 该来源报告什么 | 无 root | 有 root | 限制 |
|---|---|---|---|---|---|
| `GEO_IP` | 服务端路径 | 公网 IP 的国家、ASN/ISP、托管/数据中心以及代理/VPN 指标。 | 选择与目标国家和网络类型一致的出口；外部路由器本身不会改变 GeoIP。 | Root 无法修正远端数据库；必须改变路由或出口。 | 不同 GeoIP 数据库会冲突且更新滞后；一个提供商显示干净不保证最终判定。 |
| `DIRECT_NETWORK_CAPABILITIES` | 框架层 | 活动网络上的 `TRANSPORT_VPN`、`IS_VPN` 与 `VpnTransportInfo`。 | 通常无法在本机无痕隐藏；应使用外部网关，把 `VpnService` 移出手机。 | 在 `system_server` 中运行 VPNHide 或 VPNHide Next，并且作用域只包含 `System Framework`。 | 缺少框架层时，原生后端不会改变 Binder 网络模型。 |
| `INDIRECT_NETWORK_CAPABILITIES` | 框架层 | 缺少 `NOT_VPN`、能力不一致以及间接 VPN 模型。 | 使用外部网关；按应用绕过可能留下自相矛盾的状态。 | 在系统层过滤 `NetworkCapabilities` 及相关 Parcel 数据。 | 活动网络、能力、回调与 `LinkProperties` 必须彼此一致。 |
| `ICMP_SPOOFING` | 服务端路径 | 来自运营商理论上应阻断的地址或域名的 ICMP 响应，包括可能的替换响应。 | 不要在本地伪造；应在真实运营商网络上测试并重复运行。 | 通常不需要 root；防火墙反而可能扭曲结果并制造假信号。 | ICMP 行为取决于运营商、NAT 与速率限制，因此更常属于待复核信号。 |
| `RTT_TRIANGULATION` | 服务端路径 | 俄罗斯与境外主机之间的延迟对比（SNITCH β 或诊断）。 | 使用真实且一致的路由，不要把一次 RTT 样本当作证据。 | Root 无法消除物理延迟；本地注入延迟并不可靠。 | 移动网络、拥塞与 Wi-Fi 会引入大量噪声。 |
| `SYSTEM_PROXY` | 代理 | Java 属性、`Proxy`、默认及按网络代理状态、PAC、排除项与有效性。 | 关闭系统代理或 PAC，改用 TUN 或外部网关。 | 可以使用系统 Hook，但更推荐直接移除代理；VPNHide Zygisk 可过滤部分属性。 | 应用可能忽略代理，但代理存在本身仍是独立信号。 |
| `INSTALLED_APP` | 软件包 | 已知 VPN/代理软件包及名称启发式。 | 不要把客户端安装在同一用户资料中；使用外部路由器或独立资料。 | 针对观察者 UID 使用 VPNHide Apps 或 PackageManager 过滤。 | 软件包可见性取决于 Android、OEM 与权限；安装不等于正在使用。 |
| `VPN_SERVICE_DECLARATION` | 软件包 | 声明 `android.net.VpnService` intent 的服务。 | 把 VPN 客户端放到目标资料之外，或移到另一台设备。 | 过滤 PackageManager 的 query、resolve 与直接查找路径。 | 系统/特权调用方以及应用自身查询仍必须正常工作。 |
| `ACTIVE_VPN` | 框架层 | Android 连接 API 报告的活动 VPN 网络。 | 移除本地 `VpnService`，否则必须接受其可见性。 | 在 `system_server` 中过滤活动网络与网络列表。 | 必须同时处理原生 TUN 与路由指标。 |
| `LOCAL_PROXY` | 本地回环 | 回环地址上的 SOCKS5 或 HTTP CONNECT，以及代理与直连 IP 的比较。 | 关闭监听器或 API；不要只依赖更换端口。 | 使用按 UID 防火墙、portshide 或内核 `security_socket_connect` 过滤。 | 超时与连接被拒绝含义不同；shell UID 不等于应用 UID。 |
| `XRAY_API` | 本地回环 | Xray gRPC 控制 API 及其出站列表。 | 关闭 API/监听器，或把控制面移出手机。 | 阻止目标 UID 访问回环；密钥不能隐藏端口本身。 | 完整扫描仍可能在其他端口发现服务。 |
| `CLASH_API` | 本地回环 | Clash、Mihomo 或 sing-box 的 REST 端点，例如 `/configs`、`/connections` 和 `/proxies`。 | 关闭控制器、改用 Unix 套接字，或放入目标无法访问的命名空间。 | 使用按 UID 防火墙、portshide 或内核阻断。 | 强密钥只保护控制操作，不能隐藏监听器或协议的存在。 |
| `SPLIT_TUNNEL_BYPASS` | 绕过路径 | 存在 VPN/TUN 时，应用仍拥有明确的直连路径。 | 按应用直连可修正出口但仍可检测；最佳无 root 方案是外部网关。 | 同时隐藏本地 TUN 与 Binder 模型，并让直连出口保持一致。 | 当服务端 IP 与本地模型矛盾时，绕过路径仍是强证据。 |
| `PROXY_AUTH_BYPASS` | 本地回环 | 本地 SOCKS 或 HTTP 代理认证薄弱或缺失。 | 使用强认证，并关闭所有非必要监听器。 | 即使启用认证，也应阻止目标 UID 访问。 | 扫描器可能在检查凭据前就识别出代理。 |
| `NETWORK_INTERFACE` | 网络接口 | Java `NetworkInterface`、tun/wg/ppp/ipsec 名称以及 MTU。 | 使用外部网关；重命名接口或更改 MTU 无法关闭其他通道。 | 使用内核后端；仅有框架层不够。 | 原始 netlink、ioctl 与接口类型必须一致。 |
| `ROUTING` | 路由 | `LinkProperties`、`/proc/net/route`、默认/分流路由及策略路由。 | 使用外部网关；本地分流路由仍然可见。 | 组合内核路由/netlink 过滤与 `system_server` 中的 `LinkProperties` 过滤。 | 单次 lookup、主机路由和后端一致性的覆盖程度因后端而异。 |
| `DNS` | DNS | 回环、私有或被替换的 DNS，以及 VPN 与直连解析之间的差异。 | 让 DNS 跟随 HTTP/UDP 出站路径，并移除系统代理。 | Root 不能替代正确路由；框架可隐藏 `LinkProperties` 中的 DNS，但服务端 DNS 仍存在。 | DoH、DoT 与 IPv6 可能走不同路径。 |
| `PROXY_TECHNICAL_SIGNAL` | 代理 | 已知端口、多个高位端口以及 proc 套接字痕迹。 | 关闭守护进程与监听器，或使用外部网关。 | 阻止该 UID 访问回环，并在必要时过滤 proc 或套接字视图。 | 关闭控制端口不会移除 VPN 接口本身。 |
| `DUMPSYS` | 框架层 | 在可访问时读取 `dumpsys vpn_management` 与活动 `VpnService` 实例。 | 原厂系统通常限制访问；本地应用无法隐藏系统服务。 | 加固系统/框架，不要向目标授予 shell、Shizuku 或特权访问。 | 可访问性由 ROM 与权限级别决定；被拒绝不证明没有 VPN。 |
| `LOCATION_SIGNALS` | 位置 | MCC/MNC、SIM、基站、Wi-Fi/BeaconDB，以及俄罗斯/非俄罗斯位置上下文。 | 使用真实且一致的位置与出口，不要把策略建立在伪造 GPS 上。 | Root 级替换风险高且会制造不一致；正确出口更可靠。 | 缺少权限或数据通常只会降低置信度，不会清除其他通道。 |
| `HOME_ROUTED_ROAMING` | 位置 | 合法漫游场景：访问网流量经归属国出口。 | 保留该上下文，并确保 SIM 与漫游状态能够解释境外出口。 | 无需 root。 | 该上下文能减少误判，但不会自动隐藏 VPN。 |
| `VPN_GATEWAY_LEAK` | 绕过路径 | 发现 VPN 网关或底层路径，从而暴露另一张网络。 | 消除含糊的多路径行为，或使用外部网关。 | 隐藏本地路由与套接字身份，并使路由模型一致。 | 真实网关仍可能从服务端被观察到。 |
| `VPN_NETWORK_BINDING` | 绕过路径 | 把套接字绑定到 VPN 或底层 `Network` 后，产生不同路径或 IP。 | 不要保留可用绕过路径，或让两条路径保持一致。 | 框架或原生隐藏不会改变真实 bind；应修正策略或路由。 | 内部观察与外部观察必须一致。 |
| `TUN_ACTIVE_PROBE` | 绕过路径 | TUN 存在，但应用不认为活动网络是 VPN，同时还出现 DNS 或路径不一致。 | 不要只依赖本地按应用绕过；应使用外部路由器。 | 组合内核与框架隐藏，并选择一致的直连路径或隧道内路径。 | 该探针专门用于发现“本地 TUN + 分流隧道”组合。 |
| `TELEGRAM_CALL_TRANSPORT` | UDP 与通话 | Telegram、MTProto 或 UDP 传输探针以及可能的泄漏。 | 让 UDP 跟随预期路由；不了解对通话的影响前不要直接阻断。 | Root 防火墙可以路由或阻断，但可能破坏服务。 | 通常属于实验性或待复核结果；必须重复测试。 |
| `WHATSAPP_CALL_TRANSPORT` | UDP 与通话 | WhatsApp STUN/UDP 路径以及可能的独立出口。 | 让 UDP 保持一致，并验证回退行为。 | 仅在明确理解后果时使用 root 防火墙或改路由。 | 阻断响应并不一定等于干净结果。 |
| `STUN_PROBE` | UDP 与通话 | 俄罗斯与全球 STUN 服务器报告的映射地址。 | UDP 必须跟随选定出口；适用时使用外部网关。 | Root 无法改变服务端报告的映射 IP；必须调整路由或 NAT。 | NAT、IPv6 与阻断会产生不同状态。 |
| `NATIVE_INTERFACE` | 原生层 | 原生接口名称、类型与地址。 | 使用外部网关。 | 优先使用内核后端；Zygisk 仅作为回退。 | 原始系统调用可以绕过用户态 Hook。 |
| `NATIVE_ROUTE` | 原生层 | 原生路由转储、策略状态与 proc 路由。 | 使用外部网关。 | 使用内核后端。 | 必须验证 IPv4/IPv6、完整转储与单次 lookup 行为以及接口索引。 |
| `NATIVE_HOST_ROUTE` | 原生层 | 经物理接口指向 VPN 服务器的公网 `/32` 或 `/128` 主机路由。 | `VpnService` 通常不会产生该路由；若存在，应修改 VPN 路由设计。 | 上游内核后端声称可过滤路由形态。 | 仅过滤接口名称无法隐藏经物理接口的服务器路由。 |
| `NATIVE_SOCKET` | 原生层 | 套接字地址、bind-to-device 状态、UDP 端口冲突、MSS、PMTU 及相关套接字指标。 | 使用外部网关，或在可行时规范化客户端参数。 | 针对具体信号使用内核后端，或 VPNHide Next Medium/Max。 | 部分信号属于启发式，并依赖具体内核。 |
| `NATIVE_HOOK_MARKERS` | 完整性 | `maps`、Hook 库、RWX 内存与已知标记。 | 不要重新打包或向目标进程注入。 | 采用“内核 + `system_server`”架构，并把目标排除在 Xposed/Zygisk 作用域之外。 | 重命名模块不会消除结构性痕迹。 |
| `NATIVE_JVM_MISMATCH` | 完整性 | Java 与原生 API 报告的接口或路由不一致。 | 避免局部 Hook；使用外部网关。 | 启用同一版本中相互匹配的框架层与内核层，并验证目标 UID。 | 局部隐藏往往比完全不隐藏更容易被发现。 |
| `NATIVE_LIBRARY_INTEGRITY` | 完整性 | `dlsym`、ELF、linker 与库完整性。 | 不要重新打包，也不要使用无 root 注入。 | 不要向目标进程注入；使用内核后端。 | Zygisk 或 inline Hook 仍可能可见。 |
| `NATIVE_ROOT_DETECTION` | Root | `su`、`/data/adb`、属性、挂载、SELinux 与 UID 0。 | 使用无 root 的原厂设备。 | 不要向目标授予 root；使用卸载/拒绝机制，保持 SELinux enforcing、系统分区只读，并尽量缩小管理器与模块栈。 | 无法保证 root 完全不可检测。 |
| `NATIVE_EMULATOR` | 设备 | QEMU、Goldfish、BlueStacks 与构建指标。 | 使用物理设备。 | 基于 root 的伪装不能把模拟器变成物理设备，因此不推荐。 | 硬件与驱动层不一致仍会保留。 |
| `SANDBOX_ISOLATION` | 用户资料 | 次要用户、工作资料、克隆和用户资料身份。 | 在所有者用户下运行；用户资料不是隐藏手段。 | 不要破坏 `UserManager`；只针对正确的完整 UID。 | 真实的隔离事实仍然存在。 |
| `BETA_VPN_BINDER` | β 框架层 | 对 VPN 服务或状态执行的隐藏 Binder 探针。 | 使用外部网关。 | 在 `system_server` 中过滤，并通过重复运行验证。 | 当重复结果稳定时，这是两条 β 硬权威路径之一。 |
| `BETA_USER_PROFILE` | β 用户资料 | 用户、用户资料与前台用户上下文。 | 使用所有者用户。 | 不要全局隐藏；只针对正确 UID。 | 用户资料与网络不一致结合时可能形成 quorum。 |
| `BETA_CONNECTIVITY_BINDER` | β 框架层 | Binder 连接状态与公共 API 的对比。 | 使用外部网关。 | `system_server` Hook 必须保持内部一致。 | 局部 Java Hook 会表现为不一致。 |
| `BETA_NETD_NETID` | β 内核 | netd、网络 ID 与扩展 rtnetlink 上下文。 | 使用外部网关。 | 同时进行内核与系统过滤；VPNHide Next 声称覆盖更广。 | 后端一致性取决于 ROM 与内核。 |
| `BETA_SOCKET_MARK` | β 套接字 | 套接字 mark、网络 ID 与身份。 | 使用外部网关，或只保留一条一致路径。 | 应用内核级套接字过滤，或修正路由策略。 | 用户态 Hook 可能看不到原始套接字元数据。 |
| `BETA_SOCKET_DIAG` | β 套接字 | INET_DIAG cookie 与套接字身份。 | 使用外部网关。 | 在内核中过滤；不要仅为隐藏结果而削弱 SELinux。 | 拒绝访问属于中性结果；可访问性取决于内核。 |
| `BETA_WIREGUARD_GENL` | β 内核 VPN | WireGuard generic-netlink 控制面。 | 不要在手机上运行内核 WireGuard；改用外部网关。 | 使用兼容内核后端过滤或隐藏。 | 该特权探针为可选启用；拒绝访问属于中性结果。 |
| `BETA_OVPN_GENL` | β 内核 VPN | OpenVPN DCO 或 generic-netlink 状态。 | 使用外部网关，或避免在本机使用 DCO。 | 在内核中过滤。 | 该特权探针为可选启用。 |
| `BETA_XFRM` | β IPsec | XFRM 状态与策略。 | 使用外部网关，或避免本地 IPsec。 | 在内核中过滤。 | 企业环境中的 IPsec 可能完全合法。 |
| `BETA_UNIX_DIAG` | β 本地回环 | 本地控制面的 Unix 套接字与对端身份。 | 关闭守护进程，或把它移出设备。 | 按命名空间或 UID 过滤。 | 隐藏 TCP 端口不会关闭 Unix 套接字。 |
| `BETA_BPF_NETFILTER` | β 策略 | BPF、netd、cgroup、netfilter 与原始目标状态。 | 使用外部网关，并尽量减少本地重定向。 | 应用内核级策略隐藏；Next Max 声称覆盖 BPF。 | 跨内核可移植性很困难，因此通常属于待复核信号。 |
| `BETA_NAMESPACE` | β 完整性 | 挂载与网络命名空间身份。 | 不要使用虚拟化或用户资料包装器。 | 使用正确的卸载命名空间，并避免破坏系统命名空间。 | Root 管理器本身也可能制造命名空间差异。 |
| `BETA_SANDBOX_IDENTITY` | β 完整性 | 虚拟化环境中的进程、文件系统与 fscrypt 身份。 | 在普通所有者用户沙箱中使用原始 APK。 | 不要重新打包，也不要通过虚拟容器运行。 | Root 无法把虚拟化 APK 变成普通 APK。 |
| `BETA_HOOK_CONSISTENCY` | β 完整性 | 直接系统调用、io_uring、文件描述符与 linker 一致性。 | 不要注入或重新打包进程。 | 使用内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 替代路径会暴露局部 Hook。 |
| `BETA_TUN_FD` | β 内核 VPN | 对 TUN 文件描述符执行内核查询。 | 移除本地 `VpnService`，或使用外部网关。 | 在内核中过滤，并验证精确后端。 | 当重复结果稳定时，这是第二条 β 硬权威路径。 |
| `BETA_DNS_NETID` | β DNS | DNS 网络 ID 与原生解析器路径。 | 让 DNS 与出口保持一致。 | 框架或内核隐藏不能替代正确的 DNS 路由。 | DoH 与原生解析器可能分流。 |
| `BETA_ROUTE_LOOKUP` | β 路由 | 对选定目标执行一次路由查询。 | 使用外部网关。 | 使用内核后端，并考虑上游单次 lookup 的覆盖缺口。 | 干净的路由转储不能保证单次 lookup 也干净。 |
| `BETA_POLICY_RULE` | β 路由 | 按 UID 与网络 ID 观察策略规则。 | 使用外部网关。 | 使用覆盖 `RTM_GETRULE` 的内核后端。 | ROM 与 netd 可能创建复杂但合法的规则。 |
| `BETA_RTNL_ADDRESS` | β 接口 | RTNL 地址转储。 | 使用外部网关。 | 应用内核 netlink 过滤。 | 必须同时覆盖 IPv4 与 IPv6。 |
| `BETA_LINK_DRIVER` | β 接口 | 接口驱动、kind 与详细属性。 | 使用外部网关。 | 在内核中过滤；Next 声称覆盖 sysfs 与驱动。 | 重命名接口不会改变其驱动或 kind。 |
| `BETA_INTERFACE_TRAFFIC` | β 路径 | 用于指示活动出口的流量计数器。 | 使用外部网关，或只保留一条一致路由。 | Next Max 声称可隐藏 BPF 与统计信息。 | 计数器与时序仍必须保持一致。 |
| `BETA_PROXY_SELECTOR` | β 代理 | Java `ProxySelector` 与系统代理模型。 | 关闭代理或 PAC。 | 仅在确有必要时使用系统 Hook；直接移除设置更好。 | 应用层与原生路径可能不一致。 |
| `BETA_TRANSPORT_MATRIX` | β 服务端 | 针对 canary 端点的 HTTP、DNS 与 UDP 传输矩阵。 | 让所有协议都走预期路径。 | Root 无法改变服务端观察；必须修改路由。 | 网络与 epoch 必须保持稳定。 |
| `BETA_TLS_INTERCEPTION` | β TLS | TLS 拦截的证书与握手指标。 | 不要为目标安装 MITM CA 或代理；使用直接 TLS。 | 把目标排除在 MITM 之外，并移除注入的信任或 Hook。 | 企业 CA 可能合法，因此通常属于待复核信号。 |
| `BETA_PKTINFO` | β 套接字 | `IP_PKTINFO`、IPv6 packet info 与入站接口身份。 | 使用外部网关。 | 应用内核级套接字过滤。 | 结果必须与路由和接口模型一致。 |
| `BETA_NETWORK_TRANSITION` | β 时间线 | netlink 网络转换及网络事件的时间顺序。 | 不要在网络切换时测试；使用外部网关。 | 系统与内核过滤必须原子化。 | 策略可抑制竞态，但重复验证仍然重要。 |
| `BETA_TRACEROUTE` | β 路径 | Traceroute 与路径观察。 | 使用真实且一致的路由。 | Root 防火墙只能限制探针；服务端路径仍然存在。 | 通常属于系统网络上下文，而不是硬 VPN 证据。 |
| `BETA_SERVER_FINGERPRINT` | β 服务端 | 活动路径的 canary 或服务端指纹。 | 选择预期出口。 | Root 无法修正服务端指纹。 | 仅有系统网络上下文不会进入 β 硬 quorum。 |

## 2. 全部 `NativeSignalId` 值 — 85

| ID | 检查读取什么 | 无 root | 有 root | 限制 |
|---|---|---|---|---|
| [`NATIVE_LIBRARY`](../../native/native-library/) | 加载原生检查库。 | 不要“修复”被拒绝或不可用的结果；应在对照设备上重复检查。 | Root 只用于诊断；不要削弱 SELinux。 | 通常属于信息或可用性结果，必须与其他行一起解释。 |
| [`INTERFACE_ENUMERATION`](../../native/interface-enumeration/) | 主要网络接口枚举。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`TUNTAP_TYPE`](../../native/tuntap-type/) | 不依赖名称的 ARPHRD_TUNNEL/TUN-TAP 接口类型检查。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`IPSEC_INTERFACE`](../../native/ipsec-interface/) | IPsec/XFRM 接口。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`JVM_NATIVE_MISMATCH`](../../native/jvm-native-mismatch/) | Java `NetworkInterface` 与原生 `getifaddrs` 结果不一致。 | 使用外部网关，或避免局部 Hook。 | 启用同一版本中匹配的框架层与内核层，并把目标排除在注入作用域之外。 | 任何未覆盖通道都会重新制造不一致。 |
| [`ROUTE_TABLE`](../../native/route-table/) | 主路由表与默认路由。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`HOST_ROUTE`](../../native/host-route/) | 经物理接口的公网 /32 或 /128 主机路由。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`HOOK_MARKERS`](../../native/hook-markers/) | proc/self/maps 中具名的注入标记。 | 不要重新打包 APK，也不要注入无 root 或 Xposed Hook。 | 使用带 `system_server` 作用域的内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 进程内 Zygisk 与第三方隐藏模块仍可能可见。 |
| [`RWX_MEMORY_REGIONS`](../../native/rwx-memory-regions/) | 大型 RWX 内存区域。 | 不要重新打包 APK，也不要注入无 root 或 Xposed Hook。 | 使用带 `system_server` 作用域的内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 进程内 Zygisk 与第三方隐藏模块仍可能可见。 |
| [`LIBRARY_INTEGRITY`](../../native/library-integrity/) | 关键 libc 符号的来源完整性。 | 不要重新打包 APK，也不要注入无 root 或 Xposed Hook。 | 使用带 `system_server` 作用域的内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 进程内 Zygisk 与第三方隐藏模块仍可能可见。 |
| [`ROOT_INDICATORS`](../../native/root-indicators/) | 原生 Root 指标汇总。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`ROOT_SU_BINARY`](../../native/root-su-binary/) | 已知路径中的 su 文件。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`ROOT_PROPERTY`](../../native/root-property/) | 可疑 Root/调试系统属性。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`ROOT_MANAGEMENT`](../../native/root-management/) | Root 管理器目录与文件。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`ROOT_SYSTEM_RW`](../../native/root-system-rw/) | 对 /system 具有写权限。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`ROOT_SUSPICIOUS_MOUNT`](../../native/root-suspicious-mount/) | 包含 Magisk/core-only 与 Root 标记的挂载行。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`ROOT_OVERLAY_MOUNT`](../../native/root-overlay-mount/) | 覆盖 /system 或 /vendor 的 Overlay 挂载。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`ROOT_SELINUX`](../../native/root-selinux/) | SELinux Permissive 模式或 enforce 文件不可访问。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`ROOT_UID`](../../native/root-uid/) | 进程 UID/EUID/GID 等于 0。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`ROOT_MAGISK_PROPERTY`](../../native/root-magisk-property/) | Magisk 专用系统属性。 | 原厂无 root 系统是唯一可靠的无 root 基线。 | 不要向目标授予 root；使用卸载或拒绝机制，保持 SELinux enforcing、系统只读，并尽量缩小管理器和模块栈。 | 单独的内核、属性或挂载痕迹可能继续存在，无法保证完全隐藏。 |
| [`EMULATOR_INDICATORS`](../../native/emulator-indicators/) | 模拟器指标汇总项。 | 使用物理设备。 | 不要局部伪装模拟器；基于 root 的伪装会制造不一致。 | 硬件、驱动与构建指标仍然存在。 |
| [`EMULATOR_QEMU_PROPERTY`](../../native/emulator-qemu-property/) | QEMU 系统属性。 | 使用物理设备。 | 不要局部伪装模拟器；基于 root 的伪装会制造不一致。 | 硬件、驱动与构建指标仍然存在。 |
| [`EMULATOR_QEMU_PIPE`](../../native/emulator-qemu-pipe/) | QEMU 通信管道与套接字。 | 使用物理设备。 | 不要局部伪装模拟器；基于 root 的伪装会制造不一致。 | 硬件、驱动与构建指标仍然存在。 |
| [`EMULATOR_GOLDFISH`](../../native/emulator-goldfish/) | 硬件与主板属性中的 Goldfish/Ranchu。 | 使用物理设备。 | 不要局部伪装模拟器；基于 root 的伪装会制造不一致。 | 硬件、驱动与构建指标仍然存在。 |
| [`EMULATOR_QEMU_DRIVER`](../../native/emulator-qemu-driver/) | TTY 驱动列表中的 QEMU Goldfish。 | 使用物理设备。 | 不要局部伪装模拟器；基于 root 的伪装会制造不一致。 | 硬件、驱动与构建指标仍然存在。 |
| [`EMULATOR_BLUESTACKS`](../../native/emulator-bluestacks/) | BlueStacks 文件痕迹。 | 使用物理设备。 | 不要局部伪装模拟器；基于 root 的伪装会制造不一致。 | 硬件、驱动与构建指标仍然存在。 |
| [`EMULATOR_BUILD`](../../native/emulator-build-profile/) | Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT 启发式检查。 | 使用物理设备。 | 不要局部伪装模拟器；基于 root 的伪装会制造不一致。 | 硬件、驱动与构建指标仍然存在。 |
| [`ISOLATION_PROFILE`](../../native/isolation-profile/) | 隔离用户资料汇总项。 | 在所有者用户下运行；只有明确测试时才使用独立资料。 | 把完整 UID 正确加入隐藏配置，并且不要破坏 `UserManager`。 | 用户或用户资料事实仍然真实存在。 |
| [`ISOLATION_CLONE`](../../native/isolation-clone/) | 克隆应用/双开用户 ID。 | 在所有者用户下运行；只有明确测试时才使用独立资料。 | 把完整 UID 正确加入隐藏配置，并且不要破坏 `UserManager`。 | 用户或用户资料事实仍然真实存在。 |
| [`ISOLATION_SECONDARY_USER`](../../native/isolation-secondary-user/) | 运行在主用户之外。 | 在所有者用户下运行；只有明确测试时才使用独立资料。 | 把完整 UID 正确加入隐藏配置，并且不要破坏 `UserManager`。 | 用户或用户资料事实仍然真实存在。 |
| [`ISOLATION_WORK_PROFILE`](../../native/isolation-work-profile/) | RKNHardering 本身是 Profile Owner。 | 在所有者用户下运行；只有明确测试时才使用独立资料。 | 把完整 UID 正确加入隐藏配置，并且不要破坏 `UserManager`。 | 用户或用户资料事实仍然真实存在。 |
| [`VPN_PROPERTY`](../../native/vpn-property/) | 旧版 VPN/DNS 系统属性。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`DNS_PROPERTY`](../../native/dns-property/) | 保留的 `dns_prop` ID。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`VPN_FILE`](../../native/vpn-file/) | 保留的通用 VPN 文件 ID。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`VPNHIDE`](../../native/vpnhide/) | VPNHide 痕迹与回归 Oracle。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`LSPOSED`](../../native/lsposed/) | LSPosed/Vector 路径痕迹。 | 不要重新打包 APK，也不要注入无 root 或 Xposed Hook。 | 使用带 `system_server` 作用域的内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 进程内 Zygisk 与第三方隐藏模块仍可能可见。 |
| [`HOOK_PROPERTY`](../../native/hook-property/) | LSPosed/Magisk/Zygote Hook 系统属性。 | 不要重新打包 APK，也不要注入无 root 或 Xposed Hook。 | 使用带 `system_server` 作用域的内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 进程内 Zygisk 与第三方隐藏模块仍可能可见。 |
| [`TCP_VPN_PORT`](../../native/tcp-vpn-port/) | 保留的旧版 TCP VPN 端口 ID。 | 关闭监听器或控制 API，或把守护进程移到网关。 | 使用按 UID 防火墙、portshide 或内核回环阻断。 | shell 与目标 UID 可能看到不同规则；仅更换端口不够。 |
| [`UDP_VPN_PORT`](../../native/udp-vpn-port/) | 保留的旧版 UDP VPN 端口 ID。 | 关闭监听器或控制 API，或把守护进程移到网关。 | 使用按 UID 防火墙、portshide 或内核回环阻断。 | shell 与目标 UID 可能看到不同规则；仅更换端口不够。 |
| [`INET6_VPN_INTERFACE`](../../native/inet6-vpn-interface/) | 针对固定 VPN 接口的旧版 ioctl 检查。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`ROUTE_VPN_INTERFACE`](../../native/route-vpn-interface/) | 经固定 VPN 接口名称的旧版路由。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`ARP_VPN_INTERFACE`](../../native/arp-vpn-interface/) | VPN 接口的保留旧版 ARP ID。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`SYSCTL_FORWARDING`](../../native/sysctl-forwarding/) | 已启用 IPv4 转发。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`SYSCTL_RP_FILTER`](../../native/sysctl-rp-filter/) | 已全局禁用反向路径过滤。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`ESTABLISHED_VPN_SOCKET`](../../native/established-vpn-socket/) | 连接到常见 VPN 端口的已建立 TCP 会话。 | 关闭监听器或控制 API，或把守护进程移到网关。 | 使用按 UID 防火墙、portshide 或内核回环阻断。 | shell 与目标 UID 可能看到不同规则；仅更换端口不够。 |
| [`VPN_POLICY_RULES`](../../native/vpn-policy-rules/) | VPN 接口上的旧版非标准 IPv4 路由。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`VPN_QDISC`](../../native/vpn-qdisc/) | 历史上名为 qdisc 的 tun0/wg0 流量计数检查。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`HIDDEN_MAC_NEIGHBORS`](../../native/hidden-mac-neighbors/) | MAC 地址为全零或广播地址的 ARP 条目。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`TCP_MSS_LOW`](../../native/tcp-mss-low/) | 本地连接上的低 TCP MSS。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`SO_BINDTODEVICE`](../../native/so-bindtodevice/) | 历史 SO_BINDTODEVICE 名称下的旧版套接字身份检查。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`LOOPBACK_PORT_CONFLICT`](../../native/loopback-port-conflict/) | 127.0.0.1 上的 TCP 端口被占用。 | 关闭监听器或控制 API，或把守护进程移到网关。 | 使用按 UID 防火墙、portshide 或内核回环阻断。 | shell 与目标 UID 可能看到不同规则；仅更换端口不够。 |
| [`BPF_MAP_ACCESSIBLE`](../../native/bpf-map-accessible/) | 可访问 netd 的 BPF 接口索引映射。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`IP_RECVERR`](../../native/ip-recverr/) | 保留的阳性 `IP_RECVERR` ID。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`SYSCALL_UNAVAILABLE`](../../native/syscall-unavailable/) | 原生系统调用/套接字探针不可用。 | 不要“修复”被拒绝或不可用的结果；应在对照设备上重复检查。 | Root 只用于诊断；不要削弱 SELinux。 | 通常属于信息或可用性结果，必须与其他行一起解释。 |
| [`SYSFS_VPN_LEAK`](../../native/sysfs-vpn-leak/) | 可通过 sysfs 与 proc/sys 访问的 VPN 接口。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`GETIFADDRS_VPN`](../../native/getifaddrs-vpn/) | `getifaddrs()` 中的固定 VPN 风格接口名称。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`SYSCLASSNET_VPN`](../../native/sysclassnet-vpn/) | `/sys/class/net` 中的固定 VPN 接口。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`RTM_GETLINK_VPN`](../../native/rtm-getlink-vpn/) | Netlink `RTM_GETLINK` 中的 VPN 接口。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`PROC_IF_INET6_VPN`](../../native/proc-if-inet6-vpn/) | `/proc/net/if_inet6` 中的 VPN 接口。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`PROC_IPV6_ROUTE_VPN`](../../native/proc-ipv6-route-vpn/) | `/proc/net/ipv6_route` 中的 VPN 接口。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`PROC_NET_DEV_VPN`](../../native/proc-net-dev-vpn/) | `/proc/net/dev` 中的 VPN 接口计数器。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`IFINDEXNAME_VPN`](../../native/ifindexname-vpn/) | `if_indextoname()` 返回 VPN 风格接口名称。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`VPN_POLICY_RULES_NETLINK`](../../native/vpn-policy-rules-netlink/) | 通过 RTM_GETRULE 发现的可疑策略规则。 | 把 VPN 移出手机并放到外部网关；只重命名一个痕迹并不够。 | 优先使用内核后端，为 Binder 增加框架层，并且只启用一个原生后端。 | 必须验证 IPv4/IPv6、原始系统调用、proc/sysfs 与套接字路径。 |
| [`FIB_TRIE_DENIED`](../../native/fib-trie-denied/) | 访问 /proc/net/fib_trie 被拒绝或失败。 | 不要“修复”被拒绝或不可用的结果；应在对照设备上重复检查。 | Root 只用于诊断；不要削弱 SELinux。 | 通常属于信息或可用性结果，必须与其他行一起解释。 |
| [`INET_DIAG_DENIED`](../../native/inet-diag-denied/) | 应用无法使用 NETLINK_SOCK_DIAG。 | 不要“修复”被拒绝或不可用的结果；应在对照设备上重复检查。 | Root 只用于诊断；不要削弱 SELinux。 | 通常属于信息或可用性结果，必须与其他行一起解释。 |
| [`BINDTODEVICE_LEAK`](../../native/bindtodevice-leak/) | SO_BINDTODEVICE 确认 VPN 接口真实存在。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`GETSOCKNAME_LEAK`](../../native/getsockname-leak/) | 未绑定 UDP 套接字立即获得私有 IPv4 地址。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`UDP_PORT_CONFLICT_PHYSICAL`](../../native/udp-port-conflict-physical/) | 物理 IPv4 地址上的 VPN 相关 UDP 端口被占用。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`DEEP_VPN_QDISC`](../../native/deep-vpn-qdisc/) | 保留的深度 qdisc 检测 ID。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`DEEP_BPF_MAP_ACCESSIBLE`](../../native/deep-bpf-map-accessible/) | BPF 映射可访问性的保留深度检测 ID。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`ROUTE_COUNT`](../../native/route-count/) | 信息性的路由与接口数量。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`TRIM_ORACLE`](../../native/trim-oracle/) | if_indextoname 与 RTM_GETLINK 的接口数量不一致。 | 使用外部网关；没有 root 时通常无法在本机过滤。 | 使用内核后端；对 BPF、qdisc 或时序项，应把 Next Max 视为实验方案。 | 后端一致性与内核 ABI 会变化，必须重复验证。 |
| [`PMTU_MSS_COMBINED`](../../native/pmtu-mss-combined/) | 本地 `127.0.0.1:443` 连接的 TCP_INFO MSS。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`UDP_PMTU_OK`](../../native/udp-pmtu-ok/) | 成功通过 UDP 向 `127.0.0.1:53` 发送 1500 字节。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`UDP_PMTU_FAIL`](../../native/udp-pmtu-fail/) | 向环回地址发送 1500 字节 UDP 数据报失败。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`NORMAL_PMTU`](../../native/normal-pmtu/) | 第一个非隧道接口的 MTU。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`TIMING_ORACLE`](../../native/timing-oracle/) | 通过 CNTVCT_EL0 测量 ARM64 socket/sendto 时序。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`BACKPRESSURE`](../../native/backpressure/) | 环回 UDP 洪泛：50,000 个 1,400 字节数据报。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`GSO_FAILED`](../../native/gso-failed/) | `setsockopt()` 未接受 `UDP_SEGMENT`。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`GSO_SEND_FAILED`](../../native/gso-send-failed/) | `UDP_SEGMENT` 已接受，但发送 4,800 字节失败。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`GSO_OK`](../../native/gso-ok/) | UDP GSO 被接受且环回发送成功。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`HW_TIMESTAMP`](../../native/hardware-timestamp/) | 在环回接口上成功配置 `SIOCSHWTSTAMP`。 | 规范化真实 VPN、路由或套接字参数，或使用外部网关。 | VPNHide Next Medium/Max 声称覆盖部分路径；必须针对具体信号验证。 | 这些启发式依赖内核与网络，可能误报。 |
| [`TRACEROUTE_DENIED`](../../native/traceroute-denied/) | TTL=1 的回环 UDP 发送返回 EACCES。 | 不要“修复”被拒绝或不可用的结果；应在对照设备上重复检查。 | Root 只用于诊断；不要削弱 SELinux。 | 通常属于信息或可用性结果，必须与其他行一起解释。 |
| [`GENERAL_DIAGNOSTICS`](../../native/general-diagnostics/) | 深度原生检测器没有返回任何行。 | 不要“修复”被拒绝或不可用的结果；应在对照设备上重复检查。 | Root 只用于诊断；不要削弱 SELinux。 | 通常属于信息或可用性结果，必须与其他行一起解释。 |
| [`UNKNOWN`](../../native/unknown-signals/) | 未知或未映射的原生 Kind。 | 不要“修复”被拒绝或不可用的结果；应在对照设备上重复检查。 | Root 只用于诊断；不要削弱 SELinux。 | 通常属于信息或可用性结果，必须与其他行一起解释。 |

## 3. 全部 β 检查 ID — 41

| β ID | `EvidenceSource` | 类别/通道 | 检查内容 | 无 root | 有 root | 限制 |
|---|---|---|---|---|---|---|
| `beta.vpn_binder` | `BETA_VPN_BINDER` | `VPN_OR_PROXY` / `android_vpn_service`; hard-authority | 向 Android VPN 服务或状态发起 Binder 查询。 | 使用外部网关。 | 在 `system_server` 中应用框架过滤，并把目标排除在 Xposed 作用域之外。 | Binder 与原生模型必须一致。 |
| `beta.user_profile` | `BETA_USER_PROFILE` | `ISOLATED_PROFILE` / `android_user_manager` | 通过 Android 用户 API 获取当前用户或用户资料。 | 在所有者用户下运行。 | 只针对正确 UID；不要破坏 `UserManager`。 | 真实的用户资料信号仍会保留。 |
| `beta.foreground_user` | `BETA_USER_PROFILE` | `ISOLATED_PROFILE` / `android_user_manager` | 前台用户及其与进程上下文的一致性。 | 在所有者用户下运行。 | 只针对正确 UID；不要破坏 `UserManager`。 | 真实的用户资料信号仍会保留。 |
| `beta.connectivity_binder` | `BETA_CONNECTIVITY_BINDER` | `NETWORK_PATH_DIVERGENCE` / `android_connectivity` | 把 Connectivity Binder 响应与公共模型比较。 | 使用外部网关。 | 在 `system_server` 中应用框架过滤，并把目标排除在 Xposed 作用域之外。 | Binder 与原生模型必须一致。 |
| `beta.netd_netid` | `BETA_NETD_NETID` | `NETWORK_PATH_DIVERGENCE` / `netd` | 活动路径的 netd 或网络 ID。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.socket_identity` | `BETA_SOCKET_MARK` | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | 套接字 mark、网络 ID 与身份。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.inet_diag_cookie` | `BETA_SOCKET_DIAG` | `NETWORK_PATH_DIVERGENCE` / `socket_diag` | INET_DIAG cookie 与套接字身份。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.route_lookup` | `BETA_ROUTE_LOOKUP` | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | 对控制目标执行一次路由查询。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.policy_rules` | `BETA_POLICY_RULE` | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | 针对 UID 或网络 ID 的策略路由规则。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.rtnl_address` | `BETA_RTNL_ADDRESS` | `NETWORK_PATH_DIVERGENCE` / `kernel_link` | IPv4 与 IPv6 RTNL 地址转储。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.extended_rtnetlink` | `BETA_NETD_NETID` | `NETWORK_PATH_DIVERGENCE` / `kernel_routing` | 扩展 rtnetlink 与 netd 路由上下文。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.interface_driver` | `BETA_LINK_DRIVER` | `VPN_OR_PROXY` / `kernel_link` | 网络接口驱动、kind 与详细属性。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.interface_traffic` | `BETA_INTERFACE_TRAFFIC` | `NETWORK_PATH_DIVERGENCE` / `active_egress` | 接口计数器与真实出口。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.wireguard_genl` | `BETA_WIREGUARD_GENL` | `VPN_OR_PROXY` / `kernel_vpn` | WireGuard generic-netlink 状态。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.ovpn_genl` | `BETA_OVPN_GENL` | `VPN_OR_PROXY` / `kernel_vpn` | OpenVPN DCO 或 generic-netlink 状态。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.xfrm` | `BETA_XFRM` | `VPN_OR_PROXY` / `kernel_ipsec` | XFRM/IPsec 状态与策略。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.unix_diag` | `BETA_UNIX_DIAG` | `VPN_OR_PROXY` / `local_control_plane` | 本地控制面的 Unix 域套接字。 | 关闭代理或控制守护进程。 | 按 UID 或命名空间阻断。 | 监听器或 Unix 套接字仍可能可见。 |
| `beta.unix_peer_identity` | `BETA_UNIX_DIAG` | `VPN_OR_PROXY` / `local_control_plane` | Unix 套接字上的对端凭据与身份。 | 关闭代理或控制守护进程。 | 按 UID 或命名空间阻断。 | 监听器或 Unix 套接字仍可能可见。 |
| `beta.tun_fd` | `BETA_TUN_FD` | `VPN_OR_PROXY` / `process_fd`; hard-authority | 对 TUN 文件描述符执行内核查询。 | 使用外部网关移除本地 `VpnService`。 | 在内核中过滤；用户态 Hook 不够。 | 只有至少两次稳定且一致的样本后，才能视为硬证据。 |
| `beta.bpf_netd` | `BETA_BPF_NETFILTER` | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | BPF/netd 映射与流量策略。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.cgroup_bpf` | `BETA_BPF_NETFILTER` | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Cgroup BPF 挂载与策略。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.netfilter_path` | `BETA_BPF_NETFILTER` | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Netfilter 路径或重定向状态。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.original_destination` | `BETA_BPF_NETFILTER` | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | 透明重定向后的原始目标。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.direct_syscall_consistency` | `BETA_HOOK_CONSISTENCY` | `HOOK_OR_TAMPERING` / `hook_consistency` | 比较 libc API 与直接系统调用。 | 避免进程注入。 | 使用内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 替代路径会暴露局部 Hook。 |
| `beta.io_uring_consistency` | `BETA_HOOK_CONSISTENCY` | `HOOK_OR_TAMPERING` / `alternate_syscall_path` | 把替代 io_uring 路径与可能被 Hook 的 API 比较。 | 避免进程注入。 | 使用内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 替代路径会暴露局部 Hook。 |
| `beta.fd_identity` | `BETA_HOOK_CONSISTENCY` | `HOOK_OR_TAMPERING` / `process_fd` | 进程文件描述符的类型与身份。 | 避免进程注入。 | 使用内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 替代路径会暴露局部 Hook。 |
| `beta.sandbox_identity.process` | `BETA_SANDBOX_IDENTITY` | `APP_VIRTUALIZATION` / `process_identity` | 虚拟容器中的进程身份。 | 在普通沙箱中使用原始 APK。 | 不要使用虚拟容器或重新打包的 APK。 | Root 无法把容器变成普通用户资料。 |
| `beta.sandbox_identity.filesystem` | `BETA_SANDBOX_IDENTITY` | `APP_VIRTUALIZATION` / `filesystem_identity` | 沙箱文件系统布局与身份。 | 在普通沙箱中使用原始 APK。 | 不要使用虚拟容器或重新打包的 APK。 | Root 无法把容器变成普通用户资料。 |
| `beta.sandbox_identity.namespace` | `BETA_NAMESPACE` | `APP_VIRTUALIZATION` / `namespace_identity` | 沙箱或虚拟化命名空间身份。 | 在普通沙箱中使用原始 APK。 | 不要使用虚拟容器或重新打包的 APK。 | Root 无法把容器变成普通用户资料。 |
| `beta.fscrypt_identity` | `BETA_SANDBOX_IDENTITY` | `APP_VIRTUALIZATION` / `filesystem_identity` | fscrypt 与用户存储身份。 | 在普通沙箱中使用原始 APK。 | 不要使用虚拟容器或重新打包的 APK。 | Root 无法把容器变成普通用户资料。 |
| `beta.linker_integrity` | `BETA_HOOK_CONSISTENCY` | `HOOK_OR_TAMPERING` / `loader_integrity` | Linker/loader 完整性与 Hook。 | 避免进程注入。 | 使用内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 替代路径会暴露局部 Hook。 |
| `beta.dns_netid` | `BETA_DNS_NETID` | `NETWORK_PATH_DIVERGENCE` / `dns_path` | DNS 解析器网络 ID 与路径。 | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.native_dns_resolver` | `BETA_DNS_NETID` | `NETWORK_PATH_DIVERGENCE` / `dns_path` | 原生解析器与框架 DNS 的对比。 | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.proxy_selector` | `BETA_PROXY_SELECTOR` | `VPN_OR_PROXY` / `android_proxy` | Java `ProxySelector` 与系统代理一致性。 | 关闭代理或控制守护进程。 | 按 UID 或命名空间阻断。 | 监听器或 Unix 套接字仍可能可见。 |
| `beta.transport_matrix` | `BETA_TRANSPORT_MATRIX` | `NETWORK_PATH_DIVERGENCE` / `active_egress` | 针对 canary 端点的 HTTP、DNS 与 UDP 矩阵。 | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.tls_interception` | `BETA_TLS_INTERCEPTION` | `VPN_OR_PROXY` / `tls_path` | TLS 拦截与证书路径。 | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.pktinfo` | `BETA_PKTINFO` | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | 入站或出站路径的 `IP_PKTINFO`/IPv6 packet info。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.netlink_transitions` | `BETA_NETWORK_TRANSITION` | `NETWORK_PATH_DIVERGENCE` / `network_timeline` | netlink 网络事件的时间顺序。 | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.traceroute` | `BETA_TRACEROUTE` | `SYSTEM_NETWORK_CONTEXT` / `path_observation` | Traceroute 与路径观察。 | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.server_fingerprint` | `BETA_SERVER_FINGERPRINT` | `SYSTEM_NETWORK_CONTEXT` / `server_observation` | 远端观察路径的指纹。 | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.root_emulator` | `NATIVE_ROOT_DETECTION` | `DEVICE_INTEGRITY` / `device_integrity` | 对 root、模拟器与设备完整性的 β 聚合评估。 | 使用无 root 的原厂物理设备。 | 尽量缩小 root 表面，不要局部伪装模拟器。 | 仍可能进入待复核状态或形成 quorum。 |

## 4. 修复优先级

1. 先处理服务端观察与真实出口：`GEO_IP`、IP 共识、DNS、CDN、STUN 与通话传输，以及底层网络绑定。
2. 再处理框架层：直接/间接 capabilities、活动 VPN 状态、`LinkProperties` 与 Binder β 检查。
3. 随后处理原生内核层：接口、路由、TUN 类型、netlink、接口索引、套接字身份与 TUN 文件描述符。
4. 然后处理 localhost 与软件包可见性。
5. 最后再处理 root、Hook、隔离环境，以及启发式 PMTU、GSO 或时序行。

这个顺序可以减少错误结论。当应用仍能看到开放的 Clash API 和境外出口时，安装 root 隐藏模块没有意义；当 `TRANSPORT_VPN` 仍是直接证据时，调整 MTU 也没有意义。

## 5. 覆盖状态

只有当 `_validate.py` 确认三个章节中的行与源码精确对应，并且每一行的 root/无 root 列都非空时，矩阵才算完整。每当新增 `EvidenceSource`、`NativeSignalId` 或 `BetaCheckRegistry.definition()`，本地验证都必须先失败，直到在此处添加独立行。

[返回目录](../)
