---
title: "保留的 `dns_prop` ID"
permalink: /help/zh-CN/native/dns-property/
---

# 保留的 `dns_prop` ID

> **ID：** `DNS_PROPERTY`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 为兼容性保留该 ID；2.10.0 中没有独立的信号生成器
> **在最终判定中的作用：** 目录项/兼容性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`DNS_PROPERTY` 和旧版 `dns_prop` 映射仍保留在信号目录及 UI 中，但 2.10.0 的 `native_signs_probe.cpp` 不会生成 `dns_prop` 行。`net.vpn.dns*`、`dhcp.tun0.dns*` 等 DNS 相关键目前归入共享的 `vpn_prop` 类型，因此应参考 `vpn-property` 页面。

### 精确触发条件

不存在独立的阳性信号生成器。检查器仍会为这个类型输出一条信息性的“未发现”记录。

## 结果含义

保留本页是为了维持稳定 URL 和向后兼容。这并不表示完全没有 DNS 检查：服务器端 DNS 检查和 `vpn_prop` 属于其他类别。

**该行如何影响报告：**该 ID 仍保留在信号目录和 UI 中，但 2.10.0 不会生成这一类型的独立阳性行；通常由更具体的相邻信号覆盖。

## 限制与可能的误报

未来版本可能恢复独立的 `dns_prop`；届时代码一旦变化，就必须重新审查本页。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

当前版本无需绕过这个 ID。应处理真实的 DNS 信号：让解析器与预期路由保持一致、消除泄漏，并联合测试 HTTP、DNS 和 UDP。

### 有 root 权限

不存在信号生成器时不需要 root。不要仅为了让 `dns-property` 显示为绿色而安装模块；模块本身可能引入 Root 或 Hook 指标。

### 如何验证结果

```bash
rg -n 'dns_prop|DNS_PROPERTY' app/src/main
rg -n 'net\.vpn\.dns|dhcp\.tun0\.dns' app/src/main/cpp/native_signs_probe.cpp
```
第一条搜索显示信号目录/UI 映射，第二条显示实际的 `vpn_prop` 生成器。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

主要风险是把仅存在于信号目录中的记录误认为“没有 DNS 泄漏”的证明。

### 回滚

无需专门回滚；只需撤销那些已经降低网络可用性的 DNS 修改。

## 证据等级

**目录项/兼容性。**已确认 C++ 中不存在字面量 `dns_prop` 生成器，同时 `NativeSignalCatalog` 中保留了该映射。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[Android DNS/VPN Builder](https://developer.android.com/reference/android/net/VpnService.Builder).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `vpn-property`, `general-diagnostics`.

[返回原生检查参考](../)
