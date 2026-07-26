---
title: "应用无法使用 NETLINK_SOCK_DIAG"
permalink: /help/zh-CN/native/inet-diag-denied/
---

# 应用无法使用 NETLINK_SOCK_DIAG

> **ID：** `INET_DIAG_DENIED`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针只调用 `socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)`。若创建套接字返回 `EACCES` 或 `EPERM`，就生成 `inet_diag_denied`；创建成功的套接字会立即关闭，不会执行转储。该 `kind` 产生中等置信度待复核项。

### 精确触发条件

内核或 SELinux 阻止创建 `NETLINK_SOCK_DIAG` 套接字。

## 结果含义

这描述的是沙箱或 ROM 的限制，不是 VPN 证据；拒绝访问只表示无法读取套接字诊断信息。应使用该行解释覆盖范围为何不可用。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

探针不会测试成功创建后能否发送 `SOCK_DIAG` 请求，也不会按协议族区分策略。原生 Android 上这种拒绝可能完全符合预期。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

不要尝试绕过限制。与同一固件上的基线比较，并记住其他套接字检查独立运行。

### 有 root 权限

不要授予 `NET_ADMIN` 或 `NET_RAW`，也不要扩大 RKNHardering 的 sepolicy。开发 ROM 时，应在专用测试域中验证最小策略，而不是修改生产环境的 `untrusted_app` 域。

### 如何验证结果

```bash
adb shell 'cat /proc/net/netlink 2>/dev/null | head'
adb logcat -d | grep -Ei 'avc: denied.*sock_diag|NETLINK_SOCK_DIAG' | tail -30
```
精确结果只能从应用域中观察。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

允许普通应用打开 inet_diag 可能暴露其他 UID 的套接字并削弱隐私。

### 回滚

删除能力或 sepolicy 修改并重启。确认 SELinux 处于 enforcing。

## 证据等级

**中。**已根据唯一的 `EACCES`/`EPERM` 分支以及检查器的中等置信度路径核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[sock_diag kernel documentation](https://www.kernel.org/doc/html/latest/networking/diagnostic.html).
- 外部第一方文档或官方项目：[AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `established-vpn-socket`, `syscall-unavailable`, `fib-trie-denied`.

[返回原生检查参考](../)
