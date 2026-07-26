---
title: "proc/self/maps 中具名的注入标记"
permalink: /help/zh-CN/native/hook-markers/
---

# proc/self/maps 中具名的注入标记

> **ID：** `HOOK_MARKERS`
> **类别：** Hook 与进程完整性
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

原生函数读取当前进程的 `/proc/self/maps`，并搜索 `frida-agent`、`frida-gadget`、`libfrida`、`libsubstrate`、`com.saurik.substrate`、`XposedBridge`、`libxposed`、`lspatch`、`LSPosed`、`libriru` 和 `libzygisk`。匹配时会记录标记与完整 maps 行。Kotlin 对已知标记赋予高置信度，但只设置 `needsReview`，不会直接把整个类别判定为 detected。

### 精确触发条件

任意 maps 行包含固定标记之一，就会生成待复核项；已知标记获得高置信度。

## 结果含义

该检查表明具有可识别名称的库或映射已加载进当前进程。这是较强的插桩证据，但不一定是恶意插桩；测试构建、无障碍/监控 SDK 或用户安装的模块也可能造成。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

重命名文件可以绕过字符串列表，但不能绕过其他完整性检查。匿名映射或 memfd 映射可能没有标记。理论上，无害路径若包含这些词也可能匹配。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无 root 权限时，最佳方案是使用可信来源的干净 APK，不进行重新打包，也不使用 LSPatch、Frida Gadget、虚拟化或无 root Xposed。把应用移入“第二空间”不会自动清理其进程：容器本身可能注入库，并制造更多不一致。

### 有 root 权限

在已 root 设备上，除非确有必要，不要把目标应用纳入 Xposed/Vector 作用域，也不要向其加载 Zygisk 模块。对于 VPN 隐藏，优先采用 Java 过滤位于 `system_server`、原生过滤位于内核的设计。DenyList/App Profile、NoHello、Zygisk Next、SUSFS 等工具可能减少部分痕迹，但没有任何一种能保证同时抵御 maps、linker、mount 和原始系统调用检查。

### 如何验证结果

对于自己的可调试构建，可以用 `run-as` 捕获 maps：
```bash
adb shell run-as com.notcvnt.rknhardering cat /proc/self/maps 2>/dev/null | grep -Ei 'frida|xposed|lsposed|zygisk|riru|substrate|lspatch'
```
发行构建通常无法使用 `run-as`。应以检查器自身详情为准，并与已加载模块列表比较。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

`/proc/self/maps` 包含路径和进程布局信息，未经脱敏不要完整公开。禁用模块也可能影响其他应用。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**中。**已根据固定 `kSuspiciousMarkers` 数组和 `evaluateHookMarkers()` 核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[/proc/pid/maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html).
- 外部第一方文档或官方项目：[Vector](https://github.com/JingMatrix/Vector).
- 外部第一方文档或官方项目：[Magisk/Zygisk](https://github.com/topjohnwu/Magisk).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `rwx-memory-regions`, `library-integrity`, `lsposed`, `hook-property`.

[返回原生检查参考](../)
