---
title: "TTL=1 的回环 UDP 发送返回 EACCES"
permalink: /help/zh-CN/native/traceroute-denied/
---

# TTL=1 的回环 UDP 发送返回 EACCES

> **ID：** `TRACEROUTE_DENIED`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针创建普通 UDP 套接字，设置 `IP_TTL=1` 和 100 ms 发送超时，然后向 `127.0.0.1:33434` 发送 64 字节。只有当 `sendto()` 返回 -1 且 errno 精确为 `EACCES` 时才生成该行。它不会测量 ICMP 响应、网络跳数或外部 traceroute。

### 精确触发条件

设置 TTL 为 1 后，本地 UDP `sendto()` 返回 `EACCES`。

## 结果含义

这表示该特定套接字路径受到策略或防火墙拒绝，但不能证明存在 VPN 封装。检查器会设置中等置信度待复核项。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

名称中的“traceroute”只是近似描述：目标是回环地址，不使用原始套接字，也不发现网络跳数。`EPERM`、`ENETUNREACH` 等其他 errno 完全不会被报告。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

为对照测试禁用第三方本地防火墙、DNS 和 VPN 组件，并记录 `EACCES` 是否消失。无需尝试启用外部 traceroute，因为这项检查完全在本地执行。

### 有 root 权限

检查针对该 UID 的 iptables/nftables 规则与 AVC 日志。不要清空整个规则集；应定位精确作用于回环 UDP/33434 或带 TTL 标记流量的规则。

### 如何验证结果

```bash
adb logcat -d | grep -E 'avc: denied|33434|traceroute' | tail -80
adb shell su -c 'iptables-save | grep -E "33434|owner|uid|lo"; ip6tables-save | grep -E "33434|owner|uid|lo"'
```
shell 发出的数据包可能通过，而应用 UID 仍被阻止。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

全局清空防火墙可能暴露流量、禁用 kill switch 并削弱安全性。只修改已经确认的 UID 专用规则。

### 回滚

恢复保存的规则集或模块，并重新启动防火墙与 VPN。随后验证 DNS 和 kill switch。

## 证据等级

**中。**已根据回环目标、TTL=1 和唯一的 `EACCES` 分支核验；默认属于中等置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[ip(7) IP_TTL](https://man7.org/linux/man-pages/man7/ip.7.html).
- 外部第一方文档或官方项目：[sendto(2)](https://man7.org/linux/man-pages/man2/sendto.2.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `udp-pmtu-fail`, `syscall-unavailable`, `inet-diag-denied`.

[返回原生检查参考](../)
