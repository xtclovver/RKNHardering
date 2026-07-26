---
title: "127.0.0.1 上的 TCP 端口被占用"
permalink: /help/zh-CN/native/loopback-port-conflict/
---

# 127.0.0.1 上的 TCP 端口被占用

> **ID：** `LOOPBACK_PORT_CONFLICT`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

对于端口 51820、1194、443 和 8443，探针创建启用 `SO_REUSEADDR` 的 TCP 套接字，并尝试绑定到 `127.0.0.1`。只有 `EADDRINUSE` 会生成 `loopback_port_conflict`；旧版策略将其归为高置信度。

### 精确触发条件

选定的 localhost TCP 端口因地址已被占用而无法绑定。

## 结果含义

这会暴露监听器或冲突绑定，但不能识别所有者。443 和 8443 也可能被本地 Web UI、开发服务器或安全应用使用，并不一定属于 VPN。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

`SO_REUSEADDR` 与 Android 套接字语义会影响结果。探针不扫描其他端口、IPv6 `::1` 或 UDP。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

先处理真实痕迹：停止不需要的监听器、API 端口、本地守护进程或 VPN 客户端；随后对应用执行 `force-stop` 并重新测试。若必须使用 VPN，外部网关通常比任何本地绕过都更干净。第二用户资料可能限制软件包可见性，但不能保证隐藏内核网络对象，而且会产生自己的用户/资料信号。 先识别进程并禁用不需要的本地 API。仅改变端口只能避开固定列表，不能视为完整解决方案。

### 有 root 权限

Root 权限可以针对特定 UID 过滤数据，但也会增加新的检测面。VPNHide 中的 Apps 与 Ports 角色分别用于 PackageManager 与 localhost，而原生后端处理其支持的接口和路由路径。对于非标准端口，应先禁用控制 API，再考虑屏蔽。任何 iptables/nftables 规则都应通过具有清晰回滚路径的模块应用，并分别测试 IPv4 与 IPv6 回环。 VPNHide Ports 旨在限制目标 UID 访问回环地址，但根据实现方式，真实的绑定冲突仍可能可见。最稳妥的做法是不运行该监听器。

### 如何验证结果

```bash
adb shell ss -ltn 2>/dev/null | grep -E '127\.0\.0\.1:(51820|1194|443|8443)'
adb shell lsof -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ':(51820|1194|443|8443)'
```
`address already in use` 表示该端口已被占用。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

停止未知系统监听器可能破坏应用。全局回环防火墙会破坏 IPC 和本地 API。

### 回滚

恢复服务，或仅删除新增的 UID 专用规则。不要通过把端口暴露到外部来代替绑定 localhost。

## 证据等级

**高。**已根据四个端口、`AF_INET` 回环地址与 `EADDRINUSE` 核验；该 `kind` 为高置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[bind(2)](https://man7.org/linux/man-pages/man2/bind.2.html).
- 外部第一方文档或官方项目：[VPNHide Ports](https://github.com/okhsunrog/vpnhide).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `tcp-vpn-port`, `udp-port-conflict-physical`, `tcp-mss-low`.

[返回原生检查参考](../)
