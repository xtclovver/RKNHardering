---
title: VPN 与系统修改检测的实用应对措施
permalink: /help/zh-CN/anti-detection/
---

# VPN 与系统修改检测的实用应对措施

本指南说明 RKNHardering 各项检查的另一面：应用实际观察什么、哪些方法确实会改变可观察状态，以及哪些方法只是制造“已经解决”的表象。内容面向开发、兼容性测试，以及对你所控制的防御机制进行验证。下述设置并不保证能够通过第三方反欺诈系统，因为这类系统还可能使用额外的服务端信号、硬件支持的证明机制和专有规则。

本文已按照此项目副本中包含的 RKNHardering 2.10.0 源代码进行核验。完整性分别对照三个注册表跟踪：**65 个 `EvidenceSource` 条目**、**85 个 `NativeSignalId` 条目**和 **41 项 beta 检查**。[完整矩阵](./matrix/)为每个标识符分别列出“无 root”“有 root”和“仍然可见的内容”。

## 先选择正确的解决方案类别

| RKNHardering 检测的内容 | 实际需要改变的内容 | 最实用的方案 |
|---|---|---|
| GeoIP、俄罗斯与非俄罗斯检查得到的 IP 不一致、CDN、STUN 和通话测试 | 路由与真实外部地址 | 正确的按应用路由，并让 DNS/HTTP/UDP 行为保持一致；必要时使用国家和网络类型符合预期的出口 |
| `TRANSPORT_VPN`、TUN、路由、netlink、`/proc` 和网络接口 | Android 的本地网络视图 | 无 root 时，把 VPN 移到路由器或另一台设备；有 root 时，同时使用系统 Java 层和一个内核/原生后端 |
| 本地主机端口以及 Clash/sing-box/Xray API | 目标 UID 对本地控制面的访问 | 关闭监听器或 API；有 root 时，为目标 UID 阻止回环访问 |
| 已安装的 VPN 应用 | 软件包可见性 | 独立用户资料只能部分缓解；有 root 时，在 `system_server` 中过滤 `PackageManager` |
| Magisk/KernelSU/APatch、Hook、RWX 区域、`maps`、系统属性和挂载 | 进程状态与挂载命名空间 | 不要向目标进程注入 Hook；尽量缩小 root 暴露面；优先采用内核级方案而不是 Zygisk |
| 第二空间、工作资料和应用分身 | Android 用户/资料身份 | 在主用户中运行；迁移到资料空间并不是完整绕过，而且会产生新的信号 |

## 无 root 的主要限制

Android `VpnService` 会创建虚拟接口和系统 VPN 模型。通过按应用路由把某个应用排除在隧道之外，会改变该应用流量采用的路径，但不一定能隐藏 TUN 接口、VPN 网络或相关路由的存在。RKNHardering 会单独检查这一点：如果存在活动的 TUN 接口，而应用本身没有 VPN 传输，则会被视为显式按应用排除的证据。因此，把 RKNHardering 加入绕过列表可能有助于修正服务端 IP 信号，但这本身并不等同于隐藏 VPN。

最强的无 root 架构是：**让 VPN 不再作为手机上的系统对象存在**。可以把它运行在路由器、旅行路由器、作为热点的另一部手机，或其他网关上。这样，受测 Android 设备上就没有 `VpnService`、TUN 接口或 VPN 客户端软件包。不过，外部 IP 和服务端指标仍须在逻辑上保持一致。

Android 官方参考资料为 [`VpnService`](https://developer.android.com/reference/android/net/VpnService) 和 [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder)。`addAllowedApplication` 与 `addDisallowedApplication` 控制应用路由，而 `establish()` 会创建 VPN 接口本身。

## 如何阅读本指南

全文统一使用以下来源标签：

- **本项目已核验** — 结论直接来自此副本中的 RKNHardering 代码及其注册表。
- **外部项目声明** — 该能力由 VPNHide、VPNHide Next、某个 root 框架或其他工具的开发者描述；必须在具体固件上复现验证。
- **社区报告** — 社区报告过可用的场景或配置，不代表普遍保证。

不要一开始就安装模块，请先阅读[威胁模型与操作顺序](./threat-model/)。然后按需要查看对应页面：

- [网络路径：GeoIP、IP 共识、DNS、CDN、STUN、通话和 RTT](./network-path/)
- [Android 本地信号：Binder、TUN、路由、软件包、代理和本地主机](./local-signals/)
- [Root 技术栈：VPNHide、VPNHide Next、Vector/LSPosed、Magisk、KernelSU 和 APatch](./root-vpnhide/)
- [第二空间、工作资料、私密空间和应用分身](./profiles/)
- [Root、Hook、模拟器和进程完整性](./root-integrity/)
- [Beta 检查及其法定人数规则](./beta/)
- [包含每个标识符的完整矩阵](./matrix/)
- [实验室方法、验证命令和回滚](./lab/)
- [来源、下载地址和核验日期](./sources/)

## 最低限度的安全操作顺序

1. 保存一个干净的恢复点：固件版本、适用于当前 root 方案的 `boot.img` 或 `init_boot.img`、模块列表、VPN 配置，以及资料空间数据的备份。
2. 在添加 Hook 之前先修正真实网络路径：外部 IP、DNS、按应用路由和本地主机 API。
3. 单独测试 Android 本地信号。不要把出口变更和 TUN 隐藏混在一起，并据此得出单一结论。
4. 有 root 时，**只能启用一个** VPNHide 原生后端。多个内核后端同时运行可能让设备卡死或触发内核崩溃。
5. 每次更改后都要重启目标应用，并在同一个稳定网络状态下至少重复测试两次。
6. 如果结果变差，应禁用最近一次更改，而不是继续叠加另一个模块。

## 什么才算成功

成功不是看到一张绿色卡片。以下条件必须同时成立：

- 在适用情况下，预期的外部 IP 在 HTTP、DNS 和 UDP 之间保持一致；
- 不再存在高置信度的本地 VPN 信号；
- 不再存在明显的本地主机或控制面泄漏；
- 绕过方法没有引入新的 root、Hook 或隔离信号；
- 强制停止应用、更换网络和重启设备后，结果仍可复现。

[返回简体中文帮助首页](../)
