---
title: "进程 UID/EUID/GID 等于 0"
permalink: /help/zh-CN/native/root-uid/
---

# 进程 UID/EUID/GID 等于 0

> **ID：** `ROOT_UID`
> **类别：** Root 与系统状态
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针调用 `getuid()`、`geteuid()` 和 `getgid()`。任一值为 0 时，详情会包含三个数值，检查器则生成高置信度待复核项。

### 精确触发条件

RKNHardering 实际以 UID、EUID 或 GID 0 运行。

## 结果含义

对于普通 Android 应用，这是极强异常。常见原因包括通过 root 或容器执行、修改过的启动器，或测试工具链。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

设备有 root 并不意味着所有应用都以 UID 0 运行，因此缺少该信号完全不能排除 Magisk 或 KernelSU。除 GID 0 外的特权附加组也不在此分析。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

通过正常 PackageManager 安装 APK，并从标准启动器启动。不要使用 `su -c am start` 或 root 包装器。为所有者用户重新安装通常会恢复普通应用 UID。

### 有 root 权限

不要向应用授予 root，并确认没有模块修改其进程凭据。此处不应靠“隐藏 root”解决：即使安装了 root 管理器，正确状态也应是普通应用 UID。

### 如何验证结果

```bash
adb shell pidof com.notcvnt.rknhardering
adb shell ps -A -o USER,UID,GID,PID,NAME | grep rknhardering
```
部分 Android 的 `ps` 格式不同；应用自身详情仍是最终依据。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

以 UID 0 运行 GUI 应用会让其获得全部数据访问权，并显著放大任何漏洞的影响。

### 回滚

停止 root 包装器，删除其自启动项，并正常重新安装 APK。

## 证据等级

**中。**已根据直接的 `uid/euid/gid == 0` 条件核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Android application sandbox](https://source.android.com/docs/security/app-sandbox).
- 外部第一方文档或官方项目：[credentials(7)](https://man7.org/linux/man-pages/man7/credentials.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `root-su-binary`, `root-management`.

[返回原生检查参考](../)
