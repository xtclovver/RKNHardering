---
title: "UDP GSO 被接受且环回发送成功"
permalink: /help/zh-CN/native/gso-ok/
---

# UDP GSO 被接受且环回发送成功

> **ID：** `GSO_OK`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 存在原生信号生成器，但当前 UI 解析器会丢弃该行
> **在最终判定中的作用：** 目录项/兼容性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针先成功设置 `UDP_SEGMENT=1200`，随后通过 `sendto()` 向环回地址的 53 端口成功发送 4,800 字节。原生结果中的 `kind` 没有详情字段，因此只有在序列化行包含分隔符时，解析器才能收到 `gso_ok`。当前 C++ 只追加字面量 `gso_ok`，没有 `|`；而深度检测的 `parseRow()` 要求第二个分隔符之后同时存在 `kind` 和非空详情。加上前缀后，该行成为 `vdet|gso_ok`，所以当前 Kotlin 解析器会将其丢弃。

### 精确触发条件

在 C++ 层，`setsockopt` 和 `sendto` 均成功；但在 2.10.0 的 UI 层，由于输出格式缺少详情字段，该生成器不会形成可见结果。

## 结果含义

UI 中没有显示这一行，并不表示 GSO 失败，而是当前生成器与解析器的格式不匹配。格式修复后，该信号仍应保持为信息性结果。

**该行如何影响报告：**该 ID 仍保留在信号目录和 UI 中，但 2.10.0 不会生成这一类型的独立阳性行；通常由更具体的相邻信号覆盖。

## 限制与可能的误报

除了解析器缺陷，环回 GSO 也不测量 VPN 路径，不能证明硬件卸载是否生效。成功本身并不代表获得了反检测效果。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

不要仅因为 UI 中缺少这一行就修改设备。开发时可以把 C++ 输出改为 `gso_ok|sent=4800`，或允许解析器接受空详情，并补充单元测试。

### 有 root 权限

既不需要也不应使用 root。不要仅为了让诊断行出现而修改内核。

### 如何验证结果

```bash
rg -n 'gso_ok|parseRow|indexOf' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt
```
修复后，请运行检查器单元测试，并在支持 `UDP_SEGMENT` 的真实设备上验证。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

修改解析器会影响所有格式错误的深度检测行；必须添加测试，避免未经校验就接受空白或损坏的 `kind`。

### 回滚

若测试或遥测出现回归，只需撤销代码修改；设备上没有持久化变更。

## 证据等级

**目录项/兼容性。**已核验 C++ 输出行缺少分隔符/详情，以及 Kotlin `parseRow()` 中 `sep <= 0` 与空字段拒绝逻辑。该 ID 仍保留在信号目录中。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `gso-failed`, `gso-send-failed`, `general-diagnostics`.

[返回原生检查参考](../)
