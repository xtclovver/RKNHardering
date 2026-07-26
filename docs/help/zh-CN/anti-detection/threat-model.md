---
title: 威胁模型与应对措施顺序
permalink: /help/zh-CN/anti-detection/threat-model/
---

# 威胁模型与应对措施顺序

在选择模块之前，应先把检查划分为三个相互独立的层级。大多数失败配置只覆盖其中一层，却误以为这就是完整绕过。

## 1. 服务端与真实网络路径

这一层位于 Android 进程之外。RKNHardering 会比较外部地址、国家、ASN/ISP、俄罗斯与非俄罗斯服务的响应、DNS 路径、CDN 重定向、STUN 和传输探测。LSPosed 或内核模块都无法把外国数据中心 IP 变成俄罗斯住宅网络地址。只有路由和合适的出口能够改变这一层。

真正需要回答的问题是：**远端实际观察到的是哪个地址和哪条路由？** 这取决于分流、DNS、IPv4/IPv6、UDP 以及具体端点。详情见[网络路径](../network-path/)。

## 2. Android 的本地网络模型

这一层由 Binder/Java API 和原生内核接口组成：

- `NetworkCapabilities`、`NetworkInfo`、`LinkProperties` 及回调；
- `NetworkInterface`、`getifaddrs()`、`ioctl(SIOCGIF*)` 和 netlink `RTM_GET*`；
- `/proc/net/*`、`/sys/class/net`、策略规则、qdisc 和套接字身份；
- 系统代理、本地端口和控制 API；
- 已安装软件包以及 `VpnService` 的可见性。

无 root 的根本限制就在这里。普通 VPN 应用可以把某个软件包排除出隧道，但不能为另一个 UID 改写 `system_server` 与内核的响应。外部路由器之所以能消除本地指标，是因为受测 Android 设备上根本不会创建 VPN。Root 方案则可以在 `system_server` 和内核中筛选数据。

## 3. 设备与进程完整性

隐藏模块本身也可能成为信号。RKNHardering 会检查 root 文件和系统属性、挂载、SELinux、Hook、RWX 区域、库完整性、Java/原生层不一致、模拟器指标以及当前用户资料。直接注入 RKNHardering 进程的模块也许能移除 `TRANSPORT_VPN`，却可能留下置信度更高的 Hook 或篡改痕迹。

合理的 root 架构应将职责分离：在 `system_server` 中过滤 Java 数据，在内核层过滤原生数据，并且不向目标进程注入 Xposed 或 Zygisk。正因如此，VPNHide 推荐把系统 Java 层与一个内核后端配合使用，同时仅把 Zygisk 保留为后备方案。

## 无 root

无 root 时有四种诚实可行的操作。

第一，改变真实流量路径。例如，把 `com.notcvnt.rknhardering` 排除出 VPN，让它直连或经过预期出口。这有助于 GeoIP 和 IP 共识检查，但当前的 TUN Active Probe 能识别“TUN 存在，而此应用没有 VPN 传输”这一组合。

第二，把 VPN 移出手机。路由器、独立网关或热点能够提供最干净的本地视图：Android 看到的是普通 Wi-Fi，而不是 `VpnService`。这是唯一通用的无 root 方法，可以同时从受测设备上移除 Binder、TUN、netlink 和 VPN 客户端软件包信号。

第三，消除不必要的配置泄漏：系统代理、PAC 设置、回环监听器、Clash/sing-box/Xray API、弱认证，以及单独分流的 DNS 路径。这样做不会隐藏 TUN 接口，但能关闭彼此独立的检测来源。

第四，使用独立资料或用户。它能分离数据和已安装软件包，但并非不可见：Android 会给资料分配独立的用户 ID 和 UID 范围，而 RKNHardering 同时包含稳定版与 beta 隔离信号。在当前 `VerdictEngine` 中，单个资料信号通常只会导致待复核；但若同时出现网络不一致，beta 法定人数规则可能给出 `DETECTED`。

## 有 root

Root 扩大了可改变的范围，但不会消除网络层。可工作的方案包含四个彼此独立的要素：

1. 按应用路由和一致的出口。
2. 在 `system_server` 中进行 Java/Binder 过滤。
3. 对 `ioctl`、netlink、路由和 proc/sysfs **仅使用一个**原生/内核后端。
4. 阻止本地主机控制面，并尽量减少 root/Hook 痕迹。

对于受支持的 GKI 内核，优先选择 VPNHide 内核模块。较旧或非 GKI 内核可能可以使用 KPM/KernelPatch 后端。Zygisk 部署更容易，但原始系统调用可以绕过它的 libc Hook，而且进程完整性检查可能识别它。VPNHide Next 声称还覆盖 MTU/MSS/TCP_INFO、PMTU/GSO、eBPF、qdisc、时序和 IPv6 链路本地路径。不过，该项目本身也警告可能出现 boot loop 与 kernel panic，因此它属于实验分支，而不是安全默认的“最大模式”。

## RKNHardering 如何得出最终结论

**本项目已核验：**最终结果不是把每一行简单相加。证据来源、独立性和证据域都很重要。

- 通过分流、本地代理或 Xray/Clash API、网关泄漏，或绑定到底层网络形成的显式绕过，可以立即提供强证据。
- 外部 IP 地址或地理位置持续不一致，会进入独立的共识逻辑。
- 在没有独立网络确认时，root、Hook、隔离以及部分原生信号更常把结果推向 `NEEDS_REVIEW`。
- Beta 检查默认禁用。唯一可独立形成硬判定权的路径是 `beta.vpn_binder` 和 `beta.tun_fd`，而且仍要求多次稳定样本。其他 beta 信号需要来自独立分组的法定人数，或与稳定证据组合后，才会得到 `DETECTED`。

实际含义很重要：试图“修复”每一个信息性条目没有意义。应优先处理最强且彼此独立的来源——真实出口、Binder VPN 状态、原生接口和路由枚举、本地主机 API，以及明确的 root 或 Hook 痕迹。

## 虚假的安全感

**只做分流。** 流量会直连出去，但 TUN 接口和 VPN 网络仍然存在。当前检查会专门识别这种组合。

**只在应用进程内使用 LSPosed Hook。** Java API 看起来干净，但 `getifaddrs()`、netlink 和原始系统调用仍然可见，而且进程会新增 Hook 标记。

**只使用 Zygisk 原生隐藏。** 常见 libc 路径会被覆盖，但直接系统调用、其他接收函数和进程完整性检查仍可能暴露干预。

**只重命名 `tun0`。** RKNHardering 检查的不只是名称，还包括 TUN/TAP 类型、接口索引、netlink、路由、MTU/MSS、策略规则、qdisc 和间接套接字信号。

**只使用第二空间。** 软件包与数据会被隔离，但用户 ID 和资料状态仍然可见。OEM 分身系统经常使用可识别的用户 ID，代码也会单独检查这些 ID。

**只使用 root 隐藏模块。** 它不会改变外部 IP、DNS、STUN 或 CDN 行为。不兼容的模块还可能产生新的挂载、RWX 或链接器异常。

## 推荐的诊断顺序

在不同时改变多个变量的前提下，运行四个场景：

1. 干净手机、VPN 关闭——设备与固件基线。
2. VPN 开启，RKNHardering 位于隧道内——完整的本地和服务端信号集合。
3. VPN 开启，但排除该软件包——把服务端不一致与 TUN/按应用绕过分开。
4. 所选隐藏方法——观察哪些信号确实消失，以及出现了哪些新的 root 或 Hook 信号。

为保证可复现，应记录时间、网络、用户 ID、模块列表、VPN 客户端、资料空间，以及连续两次结果。完整模板见[实验室方法](../lab/)。

[返回反检测指南首页](../)
