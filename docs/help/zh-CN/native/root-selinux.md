---
title: "SELinux Permissive 模式或 enforce 文件不可访问"
permalink: /help/zh-CN/native/root-selinux/
---

# SELinux Permissive 模式或 enforce 文件不可访问

> **ID：** `ROOT_SELINUX`
> **类别：** Root 与系统状态
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

C++ 读取 `/sys/fs/selinux/enforce`。值为 `0` 时生成高置信度 `selinux|permissive`。若文件完全无法打开，则生成 `selinux|absent`；Kotlin 把后者作为低置信度待复核项。

### 精确触发条件

`enforce=0`，或无法打开 enforce 文件。

## 结果含义

Permissive 模式是重大安全修改。`absent` 则含义不确定：路径可能被 SELinux 或命名空间隐藏、容器内缺失，或普通应用没有访问权限。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

该检查不会分析完整策略。Enforcing 不等于原厂策略；root 模块仍可添加权限。文件缺失也不等于 permissive。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

需要干净基线时，不要安装以 permissive 模式启动 SELinux 的固件。生产 ROM 应保持 enforcing。若文件只对应用不可见，应评估相邻信号，而不是削弱策略。

### 有 root 权限

绝不要为了 VPNHide 或其他模块把 SELinux 切换到 permissive。针对具体 AVC 拒绝，应使用最窄规则，或停止使用不兼容模块。仅替换可见 `enforce` 值而不真正执行策略，会制造虚假的安全感。

### 如何验证结果

```bash
adb shell getenforce
adb shell cat /sys/fs/selinux/enforce 2>/dev/null
adb logcat -d | grep 'avc: denied' | tail -50
```
shell 的 `getenforce` 与应用 UID 的读取结果可能在可访问性上不同，但不会改变内核真实模式。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

Permissive 模式会关闭 SELinux 强制执行并放大入侵影响。错误 sepolicy 也可能造成启动循环。

### 回滚

恢复 enforcing 模式并删除最近添加的宽泛 sepolicy 规则。若设备无法启动，请恢复 boot 镜像，或通过安全模式禁用模块。

## 证据等级

**中。**已根据 `nativeDetectRoot()` 的两个分支核验；permissive 与 absent 的置信度不同。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `root-property`, `root-system-rw`, `syscall-unavailable`.

[返回原生检查参考](../)
