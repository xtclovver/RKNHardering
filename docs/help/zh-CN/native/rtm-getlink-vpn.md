---
title: "Netlink `RTM_GETLINK` 中的 VPN 接口"
permalink: /help/zh-CN/native/rtm-getlink-vpn/
---

# Netlink `RTM_GETLINK` 中的 VPN 接口

> **ID：** `RTM_GETLINK_VPN`
> **类别：** 网络接口
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针打开 `AF_NETLINK/NETLINK_ROUTE`，发送带 `NLM_F_DUMP` 的 `RTM_GETLINK`，随后解析 `RTM_NEWLINK` 消息及 `IFLA_IFNAME` 属性。它搜索精确名称 `tun0`、`tun1`、`utun0`、`wg0`、`ppp0` 和 `xfrm0`；接收循环使用 `poll(..., 2000)` 与 `recv()`。

### 精确触发条件

完整链路转储中至少包含一条使用固定 VPN 接口名称的 `RTM_NEWLINK` 消息。

## 结果含义

这是最重要的路径之一：即使 `/proc` 或 `/sys` 不可访问，普通应用仍可直接从内核获得网络设备列表。匹配结果属于强本地指标。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

只检查六个精确名称。探针不会严格校验多段响应是否被截断，也不会完整验证 sequence/PID；发送、poll 或接收失败时会静默不产生结果。只覆盖 `getifaddrs()` 的用户态 Hook 无法关闭这一路径。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

最可靠的无 root 方案，是不要在被测试的手机上创建 VPN 接口：把隧道移到路由器、旅行路由器、单独的网关手机或其他网络节点。`VpnService` 的按应用绕过只会改变所选应用使用的路由，但 `establish()` 仍会创建系统 VPN 接口，因此本地接口检查仍可能触发。不使用 TUN 的本地 HTTP/SOCKS 代理模式有时能消除这一特定向量，但会留下监听端口和代理设置，而且无法覆盖忽略代理的应用。 Android 的次级用户不会获得独立网络命名空间，因此工作资料与个人资料通常看到相同的 `RTM_GETLINK` 转储。

### 有 root 权限

实验室级隐藏通常需要系统 Java 层和一个原生后端。使用 VPNHide 时，应安装 APK，让 Vector/LSPosed 只作用于 `System Framework`，并在 kmod、KPM、Zygisk 中只选一个。对于可能直接使用系统调用或 netlink 的检查，优先选择 kmod 或 KPM：用户态 Zygisk Hook 可以被绕过，也会在目标进程中留下痕迹。请先阅读 [VPNHide 覆盖范围表](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)，并只从[官方发布页](https://github.com/okhsunrog/vpnhide/releases/latest)下载构建。VPNHide Next 声称覆盖更广，但也警告可能发生启动循环和内核崩溃，只能在专用测试设备上验证。 原始 netlink 需要内核级过滤或等价的系统隔离。Zygisk 必须拦截特定接收调用族，但仍可被绕过；上游 VPNHide 也明确记录了这一限制。

### 如何验证结果

```bash
adb shell ip -details link show
adb shell 'ip -o link | grep -E "tun0|tun1|utun0|wg0|ppp0|xfrm0"'
```
`ip` 同样使用 rtnetlink，但 shell UID 看到的视图可能经过不同过滤。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

有缺陷的 skb/netlink 过滤器可能让转储挂起、破坏多段响应，或导致系统 UID 的网络功能异常。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**高。**已根据 `RTM_GETLINK`、`RTM_NEWLINK`、`IFLA_IFNAME`、六个固定名称及 `HIGH_CONFIDENCE` 集合核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- 外部第一方文档或官方项目：[netlink(7)](https://man7.org/linux/man-pages/man7/netlink.7.html).
- 外部第一方文档或官方项目：[VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `getifaddrs-vpn`, `trim-oracle`, `ifindexname-vpn`, `interface-enumeration`.

[返回原生检查参考](../)
