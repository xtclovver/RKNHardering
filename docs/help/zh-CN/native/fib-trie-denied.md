---
title: "访问 /proc/net/fib_trie 被拒绝或失败"
permalink: /help/zh-CN/native/fib-trie-denied/
---

# 访问 /proc/net/fib_trie 被拒绝或失败

> **ID：** `FIB_TRIE_DENIED`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectFibTrieAccess()` 只尝试打开 `/proc/net/fib_trie`。打开成功时不输出任何内容；`EACCES` 或 `EPERM` 会生成 `SELinux denies`，`ENOENT` 为中性结果，其他 errno 也会生成一行。在深度检查器中，该 `kind` 既不属于高置信度，也不属于信息性集合，因此会产生中等置信度的 `needsReview` 证据。

### 精确触发条件

打开 `/proc/net/fib_trie` 时返回 `EACCES`、`EPERM`，或除 `ENOENT` 之外的其他错误。

## 结果含义

这项检查描述诊断路径的可访问性，而不是检测 VPN。在现代 Android 上，`untrusted_app` 被拒绝可能是正常策略。该行值得复核，但绝不意味着应当“修复”SELinux。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

名称容易造成误解：拒绝访问通常反而提高隐私并关闭信息泄漏。成功打开后，代码不会继续读取内容，也不会报告“可访问”。shell 与应用 UID 运行在不同 SELinux 域中。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

不要削弱任何安全设置。记录 Android 版本和 ROM，并与同一构建的干净设备比较。若应用报告 `errno=N`，先解码 errno，再检查 procfs 挂载是否损坏。

### 有 root 权限

不要为了让该行消失而添加 allow 规则，这会向普通应用暴露路由数据。实验室诊断时应检查 AVC 日志，而不是把 SELinux 改为 permissive。

### 如何验证结果

```bash
adb shell 'cat /proc/net/fib_trie >/dev/null; echo shell_rc=$?'
adb logcat -d | grep -E 'avc: denied.*fib_trie' | tail -30
```
shell 的成功或失败都不能复现 `untrusted_app` 上下文；最终结果必须在 RKNHardering 内确认。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

SELinux permissive 模式或宽泛的 allow 规则会暴露网络状态并削弱整个沙箱，其风险远高于该待复核信号。

### 回滚

删除测试 sepolicy 规则，恢复 enforcing 模式并重启设备。确认 `getenforce` 返回 `Enforcing`。

## 证据等级

**中。**已根据 errno 分支核验；该 `kind` 仍属于中等置信度待复核项。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[/proc/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- 外部第一方文档或官方项目：[AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `bpf-map-accessible`, `sysfs-vpn-leak`, `syscall-unavailable`.

[返回原生检查参考](../)
