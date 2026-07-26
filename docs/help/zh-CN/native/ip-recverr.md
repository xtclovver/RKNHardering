---
title: "保留的阳性 `IP_RECVERR` ID"
permalink: /help/zh-CN/native/ip-recverr/
---

# 保留的阳性 `IP_RECVERR` ID

> **ID：** `IP_RECVERR`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 为兼容性保留该 ID；2.10.0 中没有独立的信号生成器
> **在最终判定中的作用：** 目录项/兼容性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectIpRecvErr()` 只尝试启用 `IP_RECVERR`。成功时不会生成任何输出；遇到 `EACCES`/`EPERM` 或 `ENOPROTOOPT` 时，则生成 `unavailable|ip_recverr|...`，Kotlin 会把它映射到 `SYSCALL_UNAVAILABLE`，而不是 `IP_RECVERR`。因此当前不会出现这个阳性 ID。

### 精确触发条件

不存在独立的 `ip_recverr` 生成器。可用性错误属于相邻的 ID。

## 结果含义

UI 中的 `IP_RECVERR` 行通常只会显示“未发现”。这既不能说明系统支持该功能，也不能说明不存在 VPN；请参考 `syscall-unavailable`。

**该行如何影响报告：**该 ID 仍保留在信号目录和 UI 中，但 2.10.0 不会生成这一类型的独立阳性行；通常由更具体的相邻信号覆盖。

## 限制与可能的误报

信号目录和旧版描述沿用了更宽泛的设计；当前代码既不会读取错误队列，也不会分析 PMTU 错误。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无需为这个 ID 修改任何内容。若出现 unavailable 结果，请记录 errno 和 ROM 版本。

### 有 root 权限

不要仅为让 `setsockopt` 成功而授予应用 `CAP_NET_ADMIN`：正常情况下 `IP_RECVERR` 并不需要它，更宽的权限反而会产生新信号。只有确认属于平台缺陷后才应修改策略。

### 如何验证结果

```bash
rg -n 'detectIpRecvErr|ip_recverr|SYSCALL_UNAVAILABLE' app/src/main
```
运行时请查看 `syscall-unavailable` 的详细信息。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

为了诊断探针而放宽套接字或 SELinux 策略，会扩大攻击面。

### 回滚

只撤销新增的 sepolicy 或 capability 规则，然后重启设备。

## 证据等级

**目录项/兼容性。**已根据 `EACCES`/`EPERM`/`ENOPROTOOPT` 分支以及 unavailable 映射逻辑核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[ip(7) IP_RECVERR](https://man7.org/linux/man-pages/man7/ip.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `syscall-unavailable`, `udp-pmtu-fail`.

[返回原生检查参考](../)
