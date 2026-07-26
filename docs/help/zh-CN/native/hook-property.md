---
title: "LSPosed/Magisk/Zygote Hook 系统属性"
permalink: /help/zh-CN/native/hook-property/
---

# LSPosed/Magisk/Zygote Hook 系统属性

> **ID：** `HOOK_PROPERTY`
> **类别：** Hook 与进程完整性
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectVpnFiles()` 读取 `persist.sys.lspd.hook`、`ro.magisk.version` 和 `init.svc.zygote_restart`；任一非空值都会生成 `hook_prop`。旧版策略将该 `kind` 归为高置信度并设置 `detected=true`。

### 精确触发条件

三个 Hook 相关属性之一为非空。

## 结果含义

这是修改运行时或 root 框架的高置信度旧版指标。属性名称比具体值更重要。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

列表很短且依赖版本。OEM 理论上可能使用 `init.svc.zygote_restart`，而现代框架也可能不再暴露这些键。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无 root 权限时，最佳方案是使用可信来源的干净 APK，不进行重新打包，也不使用 LSPatch、Frida Gadget、虚拟化或无 root Xposed。把应用移入“第二空间”不会自动清理其进程：容器本身可能注入库，并制造更多不一致。

### 有 root 权限

在已 root 设备上，除非确有必要，不要把目标应用纳入 Xposed/Vector 作用域，也不要向其加载 Zygisk 模块。对于 VPN 隐藏，优先采用 Java 过滤位于 `system_server`、原生过滤位于内核的设计。DenyList/App Profile、NoHello、Zygisk Next、SUSFS 等工具可能减少部分痕迹，但没有任何一种能保证同时抵御 maps、linker、mount 和原始系统调用检查。 若旧模块创建了属性，应更新或移除模块。宽泛的 `resetprop` 规则不能替代把目标应用排除在注入范围之外。

### 如何验证结果

```bash
adb shell getprop persist.sys.lspd.hook
adb shell getprop ro.magisk.version
adb shell getprop init.svc.zygote_restart
```
任意非空字符串都满足触发条件。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

伪造 zygote 服务属性可能干扰应用启动，并使崩溃诊断更困难。

### 回滚

删除对应 `resetprop` 规则或旧模块，然后重启。

## 证据等级

**高。**已根据 `hookPropNames` 核验；该 `kind` 位于旧版高置信度集合中。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Magisk](https://github.com/topjohnwu/Magisk).
- 外部第一方文档或官方项目：[Vector](https://github.com/JingMatrix/Vector).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `lsposed`, `hook-markers`, `root-magisk-property`.

[返回原生检查参考](../)
