---
title: "大型 RWX 内存区域"
permalink: /help/zh-CN/native/rwx-memory-regions/
---

# 大型 RWX 内存区域

> **ID：** `RWX_MEMORY_REGIONS`
> **类别：** Hook 与进程完整性
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 低

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

读取 `/proc/self/maps` 时，C++ 会统计同时具有 `rwx` 权限且大小至少为 256 KiB 的映射。只要存在一处，就报告 `rwx_large` 数量；Kotlin 将其显示为低置信度信息。

### 精确触发条件

至少存在一个不小于 256 KiB、同时可写且可执行的内存区域。

## 结果含义

这可能表示 JIT 编译、运行时修补或插桩，但并非证据。当前版本中，该行不会生成待复核项，也不会改变 `detected`。

**该行如何影响报告：**该行属于信息或诊断数据，适合用于比较多次扫描，但本身不能证明存在 VPN 或篡改。

## 限制与可能的误报

ART/JIT、游戏、WebView、模拟器和合法引擎都可能使用 RWX 或过渡性映射。检查不会记录映射生命周期，也不会对内容计算哈希。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无 root 权限时，最佳方案是使用可信来源的干净 APK，不进行重新打包，也不使用 LSPatch、Frida Gadget、虚拟化或无 root Xposed。把应用移入“第二空间”不会自动清理其进程：容器本身可能注入库，并制造更多不一致。 若干净 APK 仍出现该信号，请冷启动后重复测试，并且不要先打开 WebView 或资源密集页面；这可能只是正常 JIT 活动。

### 有 root 权限

在已 root 设备上，除非确有必要，不要把目标应用纳入 Xposed/Vector 作用域，也不要向其加载 Zygisk 模块。对于 VPN 隐藏，优先采用 Java 过滤位于 `system_server`、原生过滤位于内核的设计。DenyList/App Profile、NoHello、Zygisk Next、SUSFS 等工具可能减少部分痕迹，但没有任何一种能保证同时抵御 maps、linker、mount 和原始系统调用检查。 不要仅为删除一行而通过系统属性禁用 JIT；这会降低性能，也不会消除其他 Hook 指标。

### 如何验证结果

```bash
# 仅适用于可调试构建：
adb shell run-as com.notcvnt.rknhardering cat /proc/self/maps | grep -E '^[0-9a-f]+-[0-9a-f]+ rwx'
```
比较地址范围与大小。发行构建中应依赖内置输出。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

尝试通过第三方模块改变内存权限可能造成崩溃并违反 W^X。未经脱敏不要发布完整 maps 列表。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**低。**已根据 `nativeReadSelfMapsSummary()` 中的 256 KiB 阈值核验；检查器刻意把该行作为信息处理。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[/proc/pid/maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `hook-markers`, `library-integrity`.

[返回原生检查参考](../)
