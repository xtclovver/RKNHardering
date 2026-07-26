---
title: "物理 IPv4 地址上的 VPN 相关 UDP 端口被占用"
permalink: /help/zh-CN/native/udp-port-conflict-physical/
---

# 物理 IPv4 地址上的 VPN 相关 UDP 端口被占用

> **ID：** `UDP_PORT_CONFLICT_PHYSICAL`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针从 `getifaddrs()` 中取第一个 IPv4 地址，并排除名称包含 `tun`、`wg`、`ppp`、`xfrm`、`utun` 或 `lo` 的接口。随后启用 `SO_REUSEADDR`，尝试在该 IP 的 500、4500、1194、1701 和 51820 端口绑定 UDP 套接字。只有 `EADDRINUSE` 才会把端口加入结果。

### 精确触发条件

上述五个 UDP 端口中至少一个已在选定的“物理”IPv4 地址上被占用。

## 结果含义

本地地址上存在冲突绑定，可能对应 IKE/IPsec、OpenVPN、L2TP 或 WireGuard。检查器把该信号视为高置信度，但无法识别端口所有者。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

`getifaddrs()` 中的第一条记录不保证是主要物理路径；容器或 OEM 接口可能被错误选中。这些端口也有合法用途。`SO_REUSEADDR`/`SO_REUSEPORT` 和绑定语义会造成不同结果。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

先处理真实痕迹：停止不需要的监听器、API 端口、本地守护进程或 VPN 客户端；随后对应用执行 `force-stop` 并重新测试。若必须使用 VPN，外部网关通常比任何本地绕过都更干净。第二用户资料可能限制软件包可见性，但不能保证隐藏内核网络对象，而且会产生自己的用户/资料信号。 只停止你能确认的 VPN 或服务器监听器。Android 客户端侧 `VpnService` 通常不需要在物理 IP 上监听这些端口，因此必须先找出所有者。

### 有 root 权限

Root 权限可以针对特定 UID 过滤数据，但也会增加新的检测面。VPNHide 中的 Apps 与 Ports 角色分别用于 PackageManager 与 localhost，而原生后端处理其支持的接口和路由路径。对于非标准端口，应先禁用控制 API，再考虑屏蔽。任何 iptables/nftables 规则都应通过具有清晰回滚路径的模块应用，并分别测试 IPv4 与 IPv6 回环。 使用 root 下的 `ss -ulpn` 或 `lsof` 识别所有者。确认进程前不要隐藏端口；移动监听器比内核 Hook 更干净。

### 如何验证结果

```bash
adb shell su -c 'ip -4 -br addr; ss -H -u -l -n -p | grep -E ":(500|4500|1194|1701|51820)( |$)"'
```
`connection/listener not shown` 不能排除短生命周期或特定命名空间中的绑定；仍需重复内置检查。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

停止 IKE、IMS 或 VPN 进程可能中断移动网络或企业隧道。防火墙不会释放绑定，因此未必能消除该信号。

### 回滚

重新启动被停止的服务或 VPN，恢复原端口，并只删除临时的 UID 专用规则。重启通常会释放测试套接字。

## 证据等级

**高。**已根据首个物理 IPv4 的选择逻辑、五端口列表和 `EADDRINUSE` 核验；该 `kind` 为高置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[bind(2)](https://man7.org/linux/man-pages/man2/bind.2.html).
- 外部第一方文档或官方项目：[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `udp-vpn-port`, `loopback-port-conflict`, `established-vpn-socket`.

[返回原生检查参考](../)
