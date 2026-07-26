---
title: "原生 Root 指标汇总"
permalink: /help/zh-CN/native/root-indicators/
---

# 原生 Root 指标汇总

> **ID：** `ROOT_INDICATORS`
> **类别：** Root 与系统状态
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 服务状态

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

这是 root 检查状态的汇总 ID。当 `nativeDetectRoot()` 没有返回任何行时，检查器会在 `ROOT_INDICATORS` 下显示信息性的“未发现原生 root 指标”。若存在痕迹，则分别使用 `su`、属性、管理路径、挂载、SELinux、UID 与 Magisk 属性等具体 ID。

### 精确触发条件

没有独立的阳性触发条件；阳性结果分布在九个子页面中。

## 结果含义

干净结果只表示固定原生痕迹列表没有产生输出。它不检查 bootloader、Play Integrity、硬件支持的证明、所有 KernelSU/APatch 变体，也不覆盖每一种自定义挂载命名空间。

**该行如何影响报告：**这是一个汇总或回退 ID，用于把一组输出行关联到文档，并不一定拥有独立的阳性信号生成器。

## 限制与可能的误报

任何 root 检测模型都属于启发式。被隐藏的 `su` 可能不在列表中，而 OEM 测试构建即使没有用户安装的 root，也可能使用 `test-keys`。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

若不需要 root，可靠的修复方法是通过官方流程让设备恢复原厂状态：使用对应管理器卸载 root，或刷入与当前构建完全匹配的原厂 `boot`/`init_boot` 和系统分区。即使管理器已移除，解锁的 bootloader、自定义内核和残留目录仍可能暴露修改痕迹。恢复前必须备份设备；在固件已修改时重新锁定 bootloader，可能导致数据丢失或设备无法启动。

### 有 root 权限

Root 权限只能减少可观察表面，不能证明 root 不存在。尽量只向少数应用授予 `su`，不要向 RKNHardering 授权，禁用不必要的模块，也不要把 SELinux 改为 permissive。App Profile/DenyList 行为与挂载隔离必须在具体固件上验证。SUSFS 等方案属于实验性技术，需要兼容内核，也可能产生自身痕迹。参考测试仍需要一台独立的原厂设备。

### 如何验证结果

打开具体子项查看详情。一般定位可使用：
```bash
adb shell getprop ro.build.tags
adb shell getprop ro.debuggable
adb shell id
adb shell cat /sys/fs/selinux/enforce 2>/dev/null
```
shell UID 无法复现应用自身的挂载命名空间。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

把干净的汇总结果当作完整保证是错误的。恢复原厂状态可能清除数据，而在固件不兼容时重新锁定 bootloader 可能导致设备无法启动。

### 回滚

纯诊断操作无需回滚。若要取消 root，请使用对应方案的官方卸载流程和已保存的原厂镜像。

## 证据等级

**结构性。**已根据 `evaluateRootIndicators()` 中的 `rootFindings.isEmpty()` 分支及 `nativeDetectRoot()` 核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[Android SELinux](https://source.android.com/docs/security/features/selinux).
- 外部第一方文档或官方项目：[Magisk install/uninstall guidance](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `root-su-binary`, `root-management`, `root-suspicious-mount`, `root-selinux`.

[返回原生检查参考](../)
