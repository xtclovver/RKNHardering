---
title: "保留的旧版 TCP VPN 端口 ID"
permalink: /help/zh-CN/native/tcp-vpn-port/
---

# 保留的旧版 TCP VPN 端口 ID

> **ID：** `TCP_VPN_PORT`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 为兼容性保留该 ID；2.10.0 中没有独立的信号生成器
> **在最终判定中的作用：** 目录项/兼容性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`TCP_VPN_PORT` 和 `tcp_vpn_port` 映射仍存在于信号目录与旧版循环中，但当前 C++ 代码不会生成这一 `kind`。TCP 连接由 `established_vpn` 单独检查，而 localhost 端口占用由 `loopback_port_conflict` 处理。

### 精确触发条件

不存在独立的阳性生成器；UI 通常只显示“未发现”。

## 结果含义

不要把这一行与真正的 TCP 套接字扫描混为一谈。启用中的 `established-vpn-socket` 生成器会读取 `/proc/net/tcp` 并搜索远端端口。

**该行如何影响报告：**该 ID 仍保留在信号目录和 UI 中，但 2.10.0 不会生成这一类型的独立阳性行；通常由更具体的相邻信号覆盖。

## 限制与可能的误报

未来版本可能重新加入独立的端口探针；本页记录的是 2.10.0 的实际行为。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无需处理这个 ID。应关闭确实存在且不需要的本地 API 或监听端口，并检查相邻信号。

### 有 root 权限

不要为仅存在于信号目录中的一行安装端口隐藏模块。若触发 `loopback-port-conflict`，请使用最小范围的端口调整或防火墙配置。

### 如何验证结果

```bash
rg -n 'tcp_vpn_port|established_vpn|loopback_port_conflict' app/src/main
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

主要风险是端口仍然开放，却因为这一目录项显示干净而产生错误安全感。

### 回滚

无需回滚。

## 证据等级

**目录项/兼容性。**已确认 C++ 中没有对应的字面量生成器，同时信号目录中仍保留该映射。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `established-vpn-socket`, `loopback-port-conflict`.

[返回原生检查参考](../)
