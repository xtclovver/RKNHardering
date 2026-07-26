---
title: 来源、下载地址与声明状态
permalink: /help/zh-CN/anti-detection/sources/
---

# 来源、下载地址与声明状态

以下关键链接和项目状态最后一次人工核验于 **2026 年 7 月 19 日**。始终通过官方仓库中的 `releases/latest` 下载，不要使用聊天群中重新打包的 APK 或 ZIP。项目发布 SHA-256 校验和或签名时，应在安装前完成验证。

## RKNHardering——本项目已核验

- [RKNHardering 原始项目](https://github.com/xtclovver/RKNHardering)
- [README 中的架构与当前检查](https://github.com/xtclovver/RKNHardering/blob/main/README.md)
- 此副本中的本地源码：`DirectSignsChecker`、`IndirectSignsChecker`、`BypassChecker`、`NativeSignsChecker`、`VpnNativeDetectorChecker`、`BetaCheckRegistry`、`BetaEvidencePolicy`、`VerdictEngine`、`NativeSignalId` 和 `EvidenceSource`。
- [β 检查研究说明](https://github.com/xtclovver/RKNHardering/blob/main/docs/beta-checks-research.md)

本指南中的每个精确数量和 ID 都来自本地代码，而不是第三方列表。

## Android 与 AOSP——架构限制

- [`VpnService`](https://developer.android.com/reference/android/net/VpnService) — 创建虚拟接口、`protect()` 和底层网络。
- [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder) — 允许/排除应用、路由、DNS、MTU 与代理配置。
- [软件包可见性过滤](https://developer.android.com/training/package-visibility) — Android 11+ 对软件包可见性的限制。
- [AOSP 工作资料](https://source.android.com/docs/devices/admin/managed-profiles) — 独立用户 ID、UID 和资料数据。
- [AOSP 私密空间](https://source.android.com/docs/security/features/private-space) — 私密资料以及锁定或停止状态。
- [AOSP 应用沙箱](https://source.android.com/docs/security/app-sandbox) — 基于 UID 的隔离。

## 上游 VPNHide——外部声明；必须在设备上验证

- [仓库](https://github.com/okhsunrog/vpnhide)
- [最新发布](https://github.com/okhsunrog/vpnhide/releases/latest)
- [完整检测向量图](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)
- [kmod README](https://github.com/okhsunrog/vpnhide/blob/main/kmod/README.md)
- [KPM README](https://github.com/okhsunrog/vpnhide/blob/main/kmod/kpm/README.md)
- [Zygisk README](https://github.com/okhsunrog/vpnhide/blob/main/zygisk/README.md)
- [LSPosed/应用 README](https://github.com/okhsunrog/vpnhide/blob/main/lsposed/README.md)
- [portshide README](https://github.com/okhsunrog/vpnhide/blob/main/portshide/README.md)

该项目记录的重要限制包括：服务端信号不在其覆盖范围内；原始系统调用可以绕过 Zygisk；内核后端与 Zygisk 不应叠加；部分 procfs 与 KPM 功能对等场景仍有条件限制。

## VPNHide Next——覆盖更广的实验分支

- [仓库](https://github.com/soranerai/vpnhide_next)
- [最新发布](https://github.com/soranerai/vpnhide_next/releases/latest)
- [LSPosed/system_server README](https://github.com/soranerai/vpnhide_next/blob/main/lsposed/README.md)
- [内核模块 README](https://github.com/soranerai/vpnhide_next/blob/main/kmod/README.md)

该项目声称额外覆盖 MTU、MSS、`TCP_INFO`、PMTU、GSO、BPF、qdisc、时序、sysfs、procfs 和资料空间向量。其 README 也单独警告可能出现不稳定、boot loop 和 kernel panic。本指南把这些能力标注为外部项目声明。

## Root 与框架

- [Magisk](https://github.com/topjohnwu/Magisk)、[releases](https://github.com/topjohnwu/Magisk/releases/latest)、[install.md](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md)
- [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next)、[releases](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest)、[文档](https://kernelsu-next.github.io/webpage/)
- [APatch](https://github.com/bmax121/APatch)、[releases](https://github.com/bmax121/APatch/releases/latest)、[俄文安装指南](https://apatch.dev/ru/install.html)
- [Vector](https://github.com/JingMatrix/Vector)、[releases](https://github.com/JingMatrix/Vector/releases/latest)
- [已归档的 LSPosed](https://github.com/LSPosed/LSPosed)
- [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext)、[releases](https://github.com/Dr-TSNG/ZygiskNext/releases/latest)
- [NoHello](https://github.com/MhmRdd/NoHello)、[releases](https://github.com/MhmRdd/NoHello/releases/latest)
- [SUSFS core](https://gitlab.com/simonpunk/susfs4ksu)、[SUSFS 用户空间模块](https://github.com/sidex15/susfs4ksu-module)、[releases](https://github.com/sidex15/susfs4ksu-module/releases/latest)
- [Hide My Applist](https://github.com/Dr-TSNG/Hide-My-Applist)、[releases](https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest)

NoHello、Zygisk Next、SUSFS 和 HMA 都不是必需项，也不保证能够应对 RKNHardering。列出它们是为了研究 root 暴露面。尤其不要把 HMA 与 VPNHide Apps 混为一谈：HMA 通常在所选应用的上下文内运行，而 VPNHide 通过 `system_server` 过滤 PackageManager。

## 资料空间与应用分身

- [Shelter](https://gitea.angry.im/PeterCxy/Shelter)
- [Insular](https://gitlab.com/secure-system/Insular)
- [AOSP 托管资料](https://source.android.com/docs/devices/admin/managed-profiles)
- [AOSP 私密空间](https://source.android.com/docs/security/features/private-space)

删除资料空间会清除其中数据。实验前请单独备份。

## VPN 客户端与路由

- [sing-box Android](https://sing-box.sagernet.org/clients/android/)
- [sing-box 路由规则](https://sing-box.sagernet.org/configuration/route/rule/)
- [sing-box DNS](https://sing-box.sagernet.org/configuration/dns/)
- [Mihomo 通用配置](https://wiki.metacubex.one/en/config/general/)
- [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense)
- [社区 Sub-Store 指南](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md)
- [社区 S-UI 指南](https://github.com/jinndi/RKNHardering-defense/blob/main/S-UI.md)

`RKNHardering-defense` 资料被标注为社区报告。它们是分流和外部网关的实用示例，但不能证明已隐藏 2.10.0 版本中的每一个本地与 β 向量。

## 为什么本指南不提供随机的“通用绕过 APK”

如果某个应用要求在没有明确理由的情况下关闭 Play Protect、授予无障碍或设备管理员权限、上传 SuperKey、导入私有订阅，或安装未签名的内核 ZIP，那么风险远高于收益。应核验来源、仓库历史、发布签名或哈希，以及它请求的权限。绝不能把 root 密钥、VPN 秘密或包含令牌的日志交给未验证构建的作者。

[返回反检测指南首页](../)
