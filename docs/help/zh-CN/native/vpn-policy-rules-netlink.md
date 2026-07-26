---
title: "通过 RTM_GETRULE 发现的可疑策略规则"
permalink: /help/zh-CN/native/vpn-policy-rules-netlink/
---

# 通过 RTM_GETRULE 发现的可疑策略规则

> **ID：** `VPN_POLICY_RULES_NETLINK`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针请求 IPv4 `RTM_GETRULE` 转储并解析 `RTM_NEWRULE`。路由表取自 `rtm_table` 或 `RTA_TABLE`，输出接口取自 `RTA_OIF`，临时 mark 取自 `RTA_FLOW`。只考虑表 100 到 200；当接口是固定隧道名称，或表号位于 100 到 110 时，规则被视为 VPN 风格。

### 精确触发条件

任意规则使用表 100 到 110 时，无论接口都会触发；或者规则使用表 100 到 200，且 OIF 为 `tun0`、`tun1`、`utun0`、`wg0`、`ppp0` 或 `xfrm0`。

## 结果含义

路由策略数据库中存在一条启发式规则认为与 VPN 有关的记录。检查器把该行视为高置信度。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

表号范围属于启发式，可能与 OEM、企业、网络共享或自定义路由配置重叠。这里把 `RTA_FLOW` 标记为 fwmark，但 Linux 策略规则通常使用 `FRA_FWMARK`，所以详情可能不完整。只检查 `AF_INET`，不覆盖 IPv6。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无 root 权限时，应调整路由设计，而不是试图改变路由表的显示方式。若需要一台本地状态干净的手机，请使用外部网关。若 VPN 仍通过 `VpnService` 运行，可配置分流，让被测试应用实际经由预期的物理网络出口；但这不能视为隐藏本地路由，因为接口和策略规则仍可能可见。不要在运行中的设备上用 `ip route` 删除路由；Android 与 VPN 服务会重新创建它们，并可能造成连接中断。 若规则由 VPN 客户端创建，禁用 TUN/VpnService 模式会将其移除；按应用排除不一定会删除共享规则。

### 有 root 权限

在已 root 设备上，后端必须过滤真实数据源，而不能只处理 libc。上游 VPNHide 的内核后端用于覆盖 `ioctl`、netlink 及部分路由/procfs 向量；Zygisk 仍只是有条件的回退方案。不要同时安装 kmod 与 KPM，因为它们可能拦截同一批内核函数。VPNHide Next 声称还覆盖更广的 PMTU/MSS/qdisc/BPF，但这是外部声明，必须在具体内核上重新验证。 上游 VPNHide 内核后端声称支持 `RTM_GETRULE` 过滤。安装后应比较目标 UID 与 shell 快照，因为规则过滤必须按 UID 生效。

### 如何验证结果

```bash
adb shell ip rule show
adb shell ip -details rule show
adb shell ip route show table all
```
关联分析表 100 到 200、OIF 和实际目标。未理解生成来源前，不要删除任何规则。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

删除策略规则可能切断 VPN、系统 UID、IMS、网络共享或工作资料的网络。错误 netlink 过滤还可能改变真实路由，而不只是显示视图。

### 回滚

修改前保存 `ip rule show` 与 `ip route show table all` 输出。恢复正常 VPN 或 NetworkStack，禁用模块并重启；Android 通常会重建系统规则。

## 证据等级

**高。**已根据 `RTM_GETRULE` 解析器、表号范围与 `HIGH_CONFIDENCE` 映射核验；文档也明确记录了 `RTA_FLOW`/fwmark 的不准确之处。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[rtnetlink rules](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- 外部第一方文档或官方项目：[ip-rule manual](https://man7.org/linux/man-pages/man8/ip-rule.8.html).
- 外部第一方文档或官方项目：[VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `vpn-policy-rules`, `route-table`, `route-count`.

[返回原生检查参考](../)
