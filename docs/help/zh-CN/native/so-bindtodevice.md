---
title: "历史 SO_BINDTODEVICE 名称下的旧版套接字身份检查"
permalink: /help/zh-CN/native/so-bindtodevice/
---

# 历史 SO_BINDTODEVICE 名称下的旧版套接字身份检查

> **ID：** `SO_BINDTODEVICE`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectSocketLeaks()` 实际并不调用 `SO_BINDTODEVICE`。它创建未连接的 UDP/IPv4 套接字，调用 `getsockname()`，并且只有本地地址非零时才生成 `so_bindtodevice|local_ip=...`。未连接套接字通常返回 `0.0.0.0`，因此该行很少出现。旧版策略把它作为中等置信度待复核项。

### 精确触发条件

未连接的 UDP 套接字立即具有非零本地 IPv4 地址。

## 结果含义

这是一种可疑的套接字身份，但页面名称在历史上并不准确。真正的 `SO_BINDTODEVICE` 检查记录在 `bindtodevice-leak` 页面。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

标准 Linux 通常在 `connect()` 或 `bind()` 后才选择地址，因此当前探针一般不会输出。容器或 Hook 可能改变这一行为。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

该行不存在时无需修改网络。若出现，请在干净设备上重复测试，并调查虚拟化或代理 SDK。

### 有 root 权限

寻找自动绑定或连接套接字的 Hook，而不是仅遮盖详情。把目标应用排除在进程内模块之外。

### 如何验证结果

复现需要一个小型原生测试：执行 `socket(AF_INET, SOCK_DGRAM)`，随后在没有 `bind()` 或 `connect()` 的情况下调用 `getsockname()`。`ss` 不会显示这种未注册且极短命的套接字。可在源码中定位：
```bash
rg -n 'detectSocketLeaks|so_bindtodevice' app/src/main/cpp/native_signs_probe.cpp
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

改变全局套接字绑定行为会破坏应用路由。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**中。**已根据实际实现核验；本页同时纠正了历史名称与实现不一致的问题。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html).
- 外部第一方文档或官方项目：[ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `bindtodevice-leak`, `getsockname-leak`.

[返回原生检查参考](../)
