---
title: "对 /system 具有写权限"
permalink: /help/zh-CN/native/root-system-rw/
---

# 对 /system 具有写权限

> **ID：** `ROOT_SYSTEM_RW`
> **类别：** Root 与系统状态
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针从应用 UID 调用 `access("/system", W_OK)`。成功时生成 `system_rw|/system is writable` 和高置信度待复核项。

### 精确触发条件

应用进程看到 `/system` 可写。

## 结果含义

现代生产 Android 中，`/system` 通常只读并受 verified boot 保护。普通 UID 具有写权限是强异常，可能来自环境、过度宽松的沙箱或虚拟化。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

`access(W_OK)` 检查有效权限与挂载标志，但不会真的写文件。异常容器可能返回不准确结果。若 RKNHardering 本身以 root 运行，也会合理触发。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

使用原厂固件，不要在授予扩展文件系统权限的容器中运行应用。恢复出厂设置不会修复已修改的系统镜像。

### 有 root 权限

不要向 RKNHardering 授予 root，也不要把系统全局重新挂载为读写。Systemless 模块应让应用视图保持只读。若 `/system` 因调试 remount 而可写，应恢复只读并重启。

### 如何验证结果

```bash
adb shell mount | grep -E ' /system( |/)| / '
adb shell test -w /system; echo $?
```
退出码 `0` 表示 shell 可写，但应用 UID 可能看到不同结果。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

重新挂载并写入系统分区可能破坏 AVB、OTA 更新并导致启动失败。不要通过真实创建文件来验证。

### 回滚

移除 remount 后重启。若系统镜像已修改，请按设备说明恢复原厂镜像与 verified-boot 元数据。

## 证据等级

**中。**已根据唯一的 `access(W_OK)` 条件核验；检查器会生成高置信度待复核项。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `root-overlay-mount`, `root-suspicious-mount`, `root-selinux`.

[返回原生检查参考](../)
