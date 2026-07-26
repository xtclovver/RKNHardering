---
title: "RKNHardering 本身是资料所有者（Profile Owner）"
permalink: /help/zh-CN/native/isolation-work-profile/
---

# RKNHardering 本身是资料所有者（Profile Owner）

> **ID：** `ISOLATION_WORK_PROFILE`
> **类别：** 模拟器、用户资料与隔离环境
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

检查器获取 `DevicePolicyManager` 并调用 `isProfileOwnerApp(context.packageName)`。只有 RKNHardering 软件包本身注册为 profile owner 时才生成信号。它比“应用是否运行于工作资料中”更窄：托管资料中的普通应用若没有 DPC 角色，可能不会生成该行。

### 精确触发条件

针对 RKNHardering 软件包，`isProfileOwnerApp()` 返回 `true`。

## 结果含义

该中等置信度待复核项表示非常具体的 DPC/profile-owner 角色，而不只是设备上存在工作资料。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

信号名称比实现更宽泛。对于 Shelter 或 Insular 中的普通应用，更可能触发基于用户 ID 的次要用户信号。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

若用户资料不属于测试范围，请在主用户（`user 0`）中安装并运行应用。删除工作资料、私密空间或克隆资料前先导出数据，因为删除资料会清除其中的应用和存储。Shelter 与 Insular 可用于管理资料，但不会隐藏独立 Android 用户的存在。 若 RKNHardering 被误设为 DPC，请先导出数据，再通过 Shelter、Insular 或系统设置移除资料管理。

### 有 root 权限

使用 root 伪造用户 ID、`/data/user/<id>` 路径或 `DevicePolicyManager` 响应会造成不一致状态，并可能损坏用户资料。更安全的做法是在正确用户中运行应用，而不是遮盖资料。仅为单项检查在目标进程内放置 Hook，还可能额外触发 `HOOK_MARKERS`、`RWX_MEMORY_REGIONS` 和 `LIBRARY_INTEGRITY`。 仅 Hook `DevicePolicyManager` 会让真实用户 ID 和其他 API 中的管理状态继续可见。

### 如何验证结果

```bash
adb shell dpm list-owners
adb shell dumpsys device_policy | grep -A8 -B2 -i 'profile owner'
```
这些命令可能需要 shell 权限；应用自身详情仍为最终依据。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

移除 profile owner 通常会同时删除工作资料及其数据。必须先导出重要内容。

### 回滚

通过可信 DPC 重新创建托管资料，并恢复数据。

## 证据等级

**中。**已根据精确的 `isProfileOwnerApp` 调用核验；本页修正了此前过于宽泛的解释。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[DevicePolicyManager.isProfileOwnerApp](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#isProfileOwnerApp%28java.lang.String%29).
- 外部第一方文档或官方项目：[AOSP managed profiles](https://source.android.com/docs/devices/admin/managed-profiles).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `isolation-secondary-user`, `isolation-profile`.

[返回原生检查参考](../)
