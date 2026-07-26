---
title: "隔离用户资料汇总项"
permalink: /help/zh-CN/native/isolation-profile/
---

# 隔离用户资料汇总项

> **ID：** `ISOLATION_PROFILE`
> **类别：** 模拟器、用户资料与隔离环境
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 服务状态

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

这是一个汇总 ID。当前检查器从 `/data/user/<id>/` 提取用户 ID，并另外调用 `DevicePolicyManager.isProfileOwnerApp()`；阳性结果会被分配给 `ISOLATION_CLONE`、`ISOLATION_SECONDARY_USER` 或 `ISOLATION_WORK_PROFILE`。不存在独立的 `ISOLATION_PROFILE` 信号生成器。

### 精确触发条件

该 ID 本身不会触发；请查看三个子信号。

## 结果含义

用户资料不会被视为 VPN 证据，但会改变软件包可见性、UID、按资料配置的 VPN 行为和数据访问。因此“第二空间”并不是透明绕过。

**该行如何影响报告：**这是一个汇总或回退 ID，用于把一组输出行关联到文档，并不一定拥有独立的阳性信号生成器。

## 限制与可能的误报

私密空间与 OEM 克隆使用不同用户类型；当前实现主要只能看到数值用户 ID，以及应用自身是否为 profile owner。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

若用户资料不属于测试范围，请在主用户（`user 0`）中安装并运行应用。删除工作资料、私密空间或克隆资料前先导出数据，因为删除资料会清除其中的应用和存储。Shelter 与 Insular 可用于管理资料，但不会隐藏独立 Android 用户的存在。

### 有 root 权限

使用 root 伪造用户 ID、`/data/user/<id>` 路径或 `DevicePolicyManager` 响应会造成不一致状态，并可能损坏用户资料。更安全的做法是在正确用户中运行应用，而不是遮盖资料。仅为单项检查在目标进程内放置 Hook，还可能额外触发 `HOOK_MARKERS`、`RWX_MEMORY_REGIONS` 和 `LIBRARY_INTEGRITY`。

### 如何验证结果

```bash
adb shell pm list users
adb shell am get-current-user
adb shell dumpsys user | head -160
```
把用户 ID 与详情中的 `dataDir` 路径对应起来。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

删除用户资料会清除其中的应用与数据。实验前必须导出数据。

### 回滚

通过正常 DPC 或系统设置流程重新创建资料，并从备份恢复数据。

## 证据等级

**服务状态。**已根据 `evaluateIsolation()` 以及没有直接分配该汇总 ID 的事实核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 外部第一方文档或官方项目：[AOSP managed profiles](https://source.android.com/docs/devices/admin/managed-profiles).
- 外部第一方文档或官方项目：[AOSP Private Space](https://source.android.com/docs/security/features/private-space).
- 外部第一方文档或官方项目：[Application Sandbox](https://source.android.com/docs/security/app-sandbox).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `isolation-clone`, `isolation-secondary-user`, `isolation-work-profile`.

[返回原生检查参考](../)
