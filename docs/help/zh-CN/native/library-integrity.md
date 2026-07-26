---
title: "关键 libc 符号的来源完整性"
permalink: /help/zh-CN/native/library-integrity/
---

# 关键 libc 符号的来源完整性

> **ID：** `LIBRARY_INTEGRITY`
> **类别：** Hook 与进程完整性
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

C++ 针对 `getifaddrs`、`if_nametoindex`、`socket`、`fopen`、`inet_ntop` 和 `ioctl` 调用 `dlsym(RTLD_DEFAULT)` 与 `dladdr()`。若符号缺失，或其库名不包含 `libc.so`、`libc++` 或 `libm.so`，就被视为可疑。每一行都会生成中等置信度待复核项。

### 精确触发条件

符号缺失，或符号地址解析到非预期库。

## 结果含义

该信号能发现部分 PLT/ELF 拦截和非标准 libc 包装器。它不能证明存在 VPN，但可以解释 API 结果为何可能被修改。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

原始 `libc.so` 内部的 inline Hook、跳板和原始系统调用未必改变 `dladdr` 结果。调试构建中的厂商库或 sanitizer 也可能是合法的。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

使用未经重新打包、不含 sanitizer 或第三方加载器的官方 APK。若这是调试构建，请用发行构建重复测试。无 root 虚拟化或 LSPatch 必须从进程中彻底移除，而不是仅仅改名。

### 有 root 权限

把 RKNHardering 排除在 Zygisk/Xposed 作用域之外。对于 VPN 隐藏，应使用进程外的 `system_server`/内核后端。修改后必须重启验证，因为 `force-stop` 无法从 zygote 卸载框架。

### 如何验证结果

内置详情会显示符号、地址和库。原生测试工具可重复 `dlsym`/`dladdr` 调用；普通 APK 的 `ldd` 输出无法复现运行时命名空间。开发者可用：
```bash
rg -n 'nativeLibraryIntegrity|dlsym|dladdr' app/src/main/cpp/native_signs_probe.cpp
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

替换系统 libc 或 linker 配置可能让设备无法启动。不要在生产手机上通过二进制补丁“修复”地址。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**中。**已根据 `evaluateLibraryIntegrity()` 中精确的六符号列表与库允许列表核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[dladdr(3)](https://man7.org/linux/man-pages/man3/dladdr.3.html).
- 外部第一方文档或官方项目：[dlsym(3)](https://man7.org/linux/man-pages/man3/dlsym.3.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `hook-markers`, `rwx-memory-regions`, `jvm-native-mismatch`.

[返回原生检查参考](../)
