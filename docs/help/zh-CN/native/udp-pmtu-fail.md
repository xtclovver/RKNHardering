---
title: "向环回地址发送 1500 字节 UDP 数据报失败"
permalink: /help/zh-CN/native/udp-pmtu-fail/
---

# 向环回地址发送 1500 字节 UDP 数据报失败

> **ID：** `UDP_PMTU_FAIL`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

这是同一探针的另一分支：`sendto(127.0.0.1:53, 1500)` 返回 -1，详情中包含 errno。与 `udp-pmtu-ok` 不同，该 `kind` 不在信息性集合中，因此当前检查器会生成中等置信度 `needsReview`。

### 精确触发条件

任何 `sendto()` 错误都会触发，不区分 errno。

## 结果含义

环回发送失败并不常见，但不能证明存在 VPN。可能原因包括 SELinux 或防火墙 Hook、资源限制、无效套接字状态、取消竞态或被修改的网络栈。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

代码不会分类 errno，也没有设置 `IP_MTU_DISCOVER`。因此 `EMSGSIZE` 不能自动解释为 PMTU 结果，而 `EACCES` 与 `ENOBUFS` 的含义完全不同。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

记录精确 errno，重启设备，并在不启用 VPN、防火墙或 DNS 过滤应用的情况下重复测试。不要仅为消除错误而降低 MTU。

### 有 root 权限

检查 `dmesg` 和 AVC 消息、iptables/nftables 以及套接字 Hook 模块。只删除能够明确证明会阻断环回流量的规则，不要向应用授予 capability。

### 如何验证结果

```bash
adb logcat -d | grep -E 'avc: denied|udp_pmtu|sendto' | tail -80
adb shell iptables-save 2>/dev/null | grep -E 'lo|127[.]0[.]0[.]1|dport 53'
adb shell ip6tables-save 2>/dev/null | grep -E 'lo|::1|dport 53'
```
errno 以 RKNHardering 详情为准；shell 发送使用不同 UID。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

重置全部防火墙规则属于破坏性操作，可能关闭 VPN kill switch 和系统保护。不要全局 flush 规则集。

### 回滚

恢复已保存的规则，或通过管理器禁用责任模块；重启并验证 DNS 解析。

## 证据等级

**中。**已根据兜底失败分支和默认中等置信度评估核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[sendto(2)](https://man7.org/linux/man-pages/man2/sendto.2.html).
- 外部第一方文档或官方项目：[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `udp-pmtu-ok`, `traceroute-denied`, `syscall-unavailable`.

[返回原生检查参考](../)
