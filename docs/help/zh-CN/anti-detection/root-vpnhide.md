---
title: Root 技术栈——VPNHide、VPNHide Next、Vector、Magisk、KernelSU 与 APatch
permalink: /help/zh-CN/anti-detection/root-vpnhide/
---

# Root 技术栈——VPNHide、VPNHide Next、Vector、Magisk、KernelSU 与 APatch

本页描述的是安装架构，而不是“一键解决方案”。任何内核模块或启动模块都可能造成 boot loop、kernel panic、网络丢失，或在 OTA 更新后失去兼容性。开始前，应保存相关分区的原厂镜像，并确认自己知道如何进入 bootloader 或 recovery 环境以及如何禁用模块。大多数设备解锁 bootloader 时会清除用户数据。

## 无 root

VPNHide 与 VPNHide Next 没有完整的无 root 模式：其目标要求介入 `system_server`、内核或 Zygote 进程。无 root 时，APK 只能充当用户界面、诊断工具或配置器，无法获得为另一个 UID 过滤 Binder 或 netlink 响应所需的权限。

从最终效果看，最接近的无 root 替代方案是外部路由器或网关。它不会伪造本地响应，而是彻底从手机上移除本地 VPN。次级用户、重新打包或免 root Xposed 都无法提供相同覆盖范围，反而会增加隔离或完整性信号。

## 有 root：选择基础方案

| 基础方案 | 主要优点 | 主要风险或限制 | 官方下载 |
|---|---|---|---|
| Magisk | 广泛使用的 root 方案、成熟模块生态、内置 Zygisk | Root 与用户空间痕迹；启动镜像处理因设备而异 | [Magisk releases](https://github.com/topjohnwu/Magisk/releases/latest)、[官方安装指南](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md) |
| KernelSU Next | 内核级 `su`、App Profile、模块挂载 | 需要兼容内核或 LKM；管理器与内核版本必须匹配 | [KernelSU Next releases](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest)、[文档](https://kernelsu-next.github.io/webpage/) |
| APatch | 适用于 KPM 场景的 KernelPatch 运行时 | 修补 `boot.img`，仅支持 ARM64；错误镜像或密钥会带来危险 | [APatch releases](https://github.com/bmax121/APatch/releases/latest)、[俄文安装指南](https://apatch.dev/ru/install.html) |

不要在不同设备之间照搬刷写命令。Magisk 可能使用 `boot` 或 `init_boot` 分区，而 APatch 文档明确要求 `boot.img`。应遵循所选项目的说明，并使用与设备当前构建版本完全一致的原厂镜像。

### 安装前检查 APK 或 ZIP

下载的内核或 root 模块不能仅凭文件名像官方发布就被视为可信。先保存发布页地址，再计算本地哈希：

```bash
sha256sum vpnhide*.zip *.apk
unzip -l vpnhide*.zip | sed -n '1,120p'
unzip -p vpnhide*.zip module.prop 2>/dev/null
```

对于 APK，使用 Android SDK Build-Tools 中的 `apksigner`：

```bash
apksigner verify --verbose --print-certs vpnhide.apk
```

SHA-256 只能与项目自身发布的校验和比较。某条随文件一起转发的任意消息中所写的哈希，不构成独立验证。不要安装通过第三方网站或机器人索要 SuperKey、VPN 订阅或其他秘密的 ZIP。查看 `unzip -l` 并不能证明脚本安全，但可以在安装前发现意外的 boot 镜像、二进制文件或无关安装器。

## 选择框架：Vector 或旧版 LSPosed

原始 [LSPosed/LSPosed](https://github.com/LSPosed/LSPosed) 仓库已于 2026 年 5 月 2 日归档，并标称支持 Android 8.1–14。对当前设备，更合理的起点是 [JingMatrix/Vector](https://github.com/JingMatrix/Vector/releases/latest)，其标称支持 Android 8.1–17 Beta，并兼容 Xposed API。

VPNHide 只需要框架的系统作用域。安装后：

1. 启用 VPNHide 或 VPNHide Next 模块。
2. **只选择 `System Framework`**。
3. 不要把 `com.notcvnt.rknhardering` 加入作用域。
4. 重启设备，因为 `system_server` 必须在模块已经启用的状态下启动。

如果某个特定 VPNHide 版本明确要求 LSPosed 而不是 Vector，请采用该版本发布说明中记录的兼容组合。不要同时运行两个 Xposed 框架。

## 上游 VPNHide：推荐的稳定布局

源码与下载：[okhsunrog/vpnhide](https://github.com/okhsunrog/vpnhide)、[最新发布](https://github.com/okhsunrog/vpnhide/releases/latest)和[检测向量图](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)。

架构：

- VPNHide APK 用于配置目标；
- `System Framework` 中的 Vector 或 LSPosed 负责 Java/Binder 与 PackageManager 过滤；
- 原生后端 **只能启用一个**：kmod、KPM 或 Zygisk；
- 可选的 `portshide` 负责回环访问。

### 选择原生后端

在受支持的 GKI 设备上，优先选择 **kmod**。它运行于内核，不会修改 RKNHardering 的进程内存，也无法被原始系统调用绕过。VPNHide 会按 KMI 世代发布构建，例如 `android14-6.1`；这表示内核世代，不一定等于 Android 系统版本。

较旧或非 GKI 内核，或无法加载 `.ko` 时，可以使用 **KPM**。它要求通过 APatch 或 KPatch-Next-Module 提供 KernelPatch 运行时。这是一条现场测试较少的 beta 路径。

只把 **Zygisk** 作为后备方案。它在目标进程内的 libc 层进行过滤，因此 RKNHardering 可能观察到 `maps`、RWX 内存、链接器或 Hook 差异，而且原始系统调用可以绕过过滤。不要把它描述为等同于内核后端。

**绝不能同时安装 kmod 和 KPM。** 两者可能 Hook 同一批内核函数，结果可能是卡死、kernel panic 或 boot loop。如果系统中仍安装着多个后端 ZIP，应移除多余项，并确认只有一个处于活动状态。

### 安装上游 VPNHide

1. 只从[官方发布](https://github.com/okhsunrog/vpnhide/releases/latest)下载 APK 和推荐模块 ZIP。作者提供校验和时，应核对文件名与 SHA-256。
2. 正常安装 APK。
3. 在 Vector 或 LSPosed 中启用模块，把作用域设为 `System Framework`，然后重启。
4. Root 权限只授予 VPNHide 配置器应用，绝不能授予 RKNHardering。
5. 在概览页选择推荐的原生后端，并通过 root 管理器安装**一个** ZIP。
6. 只有需要时才安装独立 Ports 模块。
7. 重启后，把 `com.notcvnt.rknhardering` 设为 Java、Native 与 Ports 的目标，并设为 Apps 的观察者，然后保存。
8. 强制停止 RKNHardering，并运行两次检查。

在当前上游版本中，用户配置保存在 `/data/system/vpnhide_config.json`。只有先做备份并验证 JSON 后，才应手动编辑；`invalid config` 表示语法或 schema 错误。通常使用界面更安全。

只读检查：

```bash
adb shell uname -r
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell su -c 'ls -la /data/adb/modules | grep -i vpnhide'
adb shell su -c 'cat /data/system/vpnhide_config.json'
adb logcat -d | grep -iE 'VpnHide|Vector|LSPosed'
```

## VPNHide Next：覆盖更广的实验方案

源码与下载：[soranerai/vpnhide_next](https://github.com/soranerai/vpnhide_next)、[最新发布](https://github.com/soranerai/vpnhide_next/releases/latest)。

**外部项目声明：**该分支增加了内核级端口阻断、MTU、MSS 与 `TCP_INFO` 过滤、GSO 和 PMTU 处理、eBPF 流量统计、qdisc、UDP 时序、IPv6 链路本地处理，以及更广的 proc/sysfs 隐藏。`Min`、`Medium` 和 `Max` 模式控制启用多少 Hook。项目 README 明确警告，并非每个内核都能保证稳定，可能发生 boot loop 或 kernel panic。

实际选择建议：

- 从 `Min` 开始，验证基础 `ioctl`、`getifaddrs`、netlink 和路由过滤；
- 当 RKNHardering 仍观察到套接字、MTU、MSS 或 PMTU 指标时，再切换到 `Medium`；
- 只有在具备有效恢复路径的实验设备上，并已确认仍存在特定 proc、sysfs、BPF、qdisc 或时序发现时，才使用 `Max`。

不要因为“以防万一”就启用 `Max`。更多内核 Hook 会增加兼容性风险，也会让回归来源更难定位。

VPNHide Next 的 LSPosed 模块同样应通过 `System Framework` 工作，而不进入目标进程。其 kmod README 把 `dev_ioctl`、`sock_ioctl`、`rtnl_fill_ifinfo`、IPv4/IPv6 地址 netlink 与 `/proc/net/route` 列为基础 Hook 点。APK 和 ZIP 必须使用完全相同的发布版本：控制协议不匹配可能导致功能只部分生效。

### 分步骤启动 VPNHide Next

1. 只从[官方发布](https://github.com/soranerai/vpnhide_next/releases/latest)下载 APK 和内核模块。不要使用上游 VPNHide 的 kmod：这是不同项目，控制协议也不同。
2. 记录 `uname -r`、Android 构建版本和下载资源名称。如果发布说明没有声明兼容已安装内核，不要在主力设备上刷入并“看看会怎样”。
3. 安装 APK，在 Vector 或 LSPosed 中启用，只把 `System Framework` 留在作用域中，然后重启。
4. 通过受支持的 root 管理器安装且仅安装一个 VPNHide Next 内核 ZIP，再次重启。
5. 在应用中选择 `com.notcvnt.rknhardering` 的 UID 或具体副本，从 `Min` 开始并保存配置。
6. 运行两次完全相同的检查。只有确认仍有某个具体 MTU、MSS、PMTU、BPF、qdisc、proc 或 sysfs 项为阳性时，才依次切换到 `Medium`、`Max`。

顶层 README 描述了较新的控制设备 `/dev/vpnhide_ctrl`，而独立 README 或旧构建仍可能提到 `/proc/vpnhide_targets` 和 `targets.txt`。这说明不同修订之间的文档存在差异，不是手动创建缺失文件的理由。应使用准确版本的界面，并且只做只读检查：

```bash
adb shell su -c 'cat /proc/modules | grep -i vpnhide'
adb shell su -c 'ls -l /dev/vpnhide_ctrl /proc/vpnhide_targets 2>/dev/null'
adb logcat -d | grep -iE 'VPNHide Next|VpnHide|Vector|LSPosed'
```

`no such file or directory` 表示路径不存在，或该修订使用其他接口。如果模块没有出现在 `/proc/modules`，但界面报告原生层正常，首先检查准确发布版本的架构：KPM 或集成式内核补丁不一定表现为常规 LKM。

## Zygisk Next 与 root 隐藏是不同问题

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) 为 KernelSU 或 APatch 提供 Zygisk API，也可以替换 Magisk 内置的 Zygisk。其现代链接器与匿名内存模式旨在减少痕迹，但不保证模块兼容性。它不会把进程内 VPNHide 后端变成内核级过滤器。

Root 隐藏在[完整性章节](../root-integrity/)单独说明。应先确认 VPNHide 正常工作，再缩小 root 暴露面。一次安装多个隐藏模块会增加诊断难度，也可能引入新的挂载或链接器信号。

## 验证每一层

安装后，不要只依赖 VPNHide 的绿色状态指示。

**框架层：**RKNHardering 中的 `DIRECT_NETWORK_CAPABILITIES`、`INDIRECT_NETWORK_CAPABILITIES`，以及来自 `LinkProperties` 的 VPN 接口名或路由应当消失。

**原生层：**`INTERFACE_ENUMERATION`、`TUNTAP_TYPE`、`GETIFADDRS_VPN`、`RTM_GETLINK_VPN` 和路由或接口索引指标应当消失。如果 Java 结果干净但仍有原生发现，问题在原生后端，而不是 LSPosed。

**端口层：**回环扫描不应再确认 SOCKS、HTTP、Xray 或 Clash API。端口对 shell 开放、但目标 UID 无法访问，是符合预期的状态。

**完整性层：**不应出现新的 `HOOK_MARKERS`、`RWX_MEMORY_REGIONS`、`LIBRARY_INTEGRITY`、`LSPOSED` 或 β Hook 一致性信号。若出现，应检查框架作用域并放弃进程内后端。

## 风险与回滚

每次改变内核或模块之前，都要保留：

- 按 root 方案官方指南保存的原厂 `boot` 或 `init_boot` 镜像；
- 当前正常工作的修补镜像；
- `/data/adb/modules` 列表以及准确的 APK、ZIP 版本；
- VPNHide 配置；
- 无需启动 Android 即可进入 recovery 或 bootloader 的方法。

回滚应一次退一步：通过管理器或安全模式禁用最近添加的模块，重启，核验网络，再卸载它。不要同时移除多个组件，否则原因仍然无法确定。发生 boot loop 时，应使用 root 管理器的官方救援机制，或按照设备说明恢复已保存的原厂镜像。不要凭感觉操作分区。

[返回反检测指南首页](../)
