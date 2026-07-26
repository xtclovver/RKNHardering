---
title: "保留的通用 VPN 文件 ID"
permalink: /help/zh-CN/native/vpn-file/
---

# 保留的通用 VPN 文件 ID

> **ID：** `VPN_FILE`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 为兼容性保留该 ID；2.10.0 中没有独立的信号生成器
> **在最终判定中的作用：** 目录项/兼容性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

信号目录包含旧版 `vpn_file` 类型，但当前 `detectVpnFiles()` 不会生成它。该函数按 `vpnhide`、`lsposed` 和 `zygisk` 前缀区分路径：前两者会获得专用 ID；`zygisk` 不在旧版允许列表中，因此通过 `UNKNOWN` 显示。

### 精确触发条件

2.10.0 中没有专用的 `vpn_file` 生成器；这个 ID 通常只会作为信息性的“未发现”行出现。

## 结果含义

这是用于兼容性的 URL，而不是启用中的通用文件检查。实际路径检查分别记录在 `vpnhide`、`lsposed` 和 `unknown-signals` 页面。

**该行如何影响报告：**该 ID 仍保留在信号目录和 UI 中，但 2.10.0 不会生成这一类型的独立阳性行；通常由更具体的相邻信号覆盖。

## 限制与可能的误报

名称可能造成误解：应用确实会检查若干特定文件，但不会把它们归到这个通用 ID。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

不要为了这一行修改文件系统。若确实不再需要某个 VPN 或 Root 框架，应使用其正常卸载流程，而不是掩盖一个仅存在于信号目录中的 ID。

### 有 root 权限

在 root 层掩盖通用 `vpn_file` ID 没有意义。若某个具体路径可见，应处理真正的生成来源，并同时检查挂载和系统属性。

### 如何验证结果

```bash
rg -n 'vpn_file|detectVpnFiles|findings.emplace_back' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

手工删除 `/data/adb` 或应用数据，可能损坏 Root 管理器及其模块。

### 回滚

使用对应工具的正常重装流程。不要在缺少正确 SELinux 标签的情况下直接复制目录来恢复。

## 证据等级

**目录项/兼容性。**已根据映射以及 C++ 中实际使用的路径前缀字符串核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[Android app data sandbox](https://source.android.com/docs/security/app-sandbox).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `vpnhide`, `lsposed`, `unknown-signals`.

[返回原生检查参考](../)
