---
title: "未知或未映射的原生 Kind"
permalink: /help/zh-CN/native/unknown-signals/
---

# 未知或未映射的原生 Kind

> **ID：** `UNKNOWN`
> **类别：** 服务状态信号
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 服务状态

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`NativeSignalCatalog.info(null)` 和未知 ID 都使用 `UNKNOWN`。在旧版与深度映射器中，未知 kind 通常解析为 `null`，随后该结果可能获得回退文档，也可能无法通过特定解析器。本页用于向前兼容，而不对应某一个 C++ 探针。

### 精确触发条件

UI 或链接收到空/未知 `NativeSignalId`，或者新的原生输出行尚未加入目录映射。

## 结果含义

这表示信号生成器、解析器、枚举与文档之间存在版本对齐缺陷。仅凭一条未知输出无法分配置信度或缓解措施；必须先获得原始 kind/detail 和提交/版本信息。

**该行如何影响报告：**这是一个汇总或回退 ID，用于把一组输出行关联到文档，并不一定拥有独立的阳性信号生成器。

## 限制与可能的误报

发行版 APK 可能不会显示完整原始行。若 APK 与文档版本混用，slug 和标题也可能不同。未知结果不能自动视为干净或已检测。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

保存导出的报告、APK 版本、ABI 和精确详情。重新安装未经重新打包的官方发行版并重复测试。提交 issue 时只附最少必要日志，并删除个人数据。

### 有 root 权限

在不加载会改变 JNI 或字符串的模块时重复测试。添加自定义原生探针时，必须同时更新 `NativeSignalId`、`NativeSignalCatalog`、映射器、UI 字符串、俄语文章和单元测试。

### 如何验证结果

```bash
rg -n 'NativeSignalId|fromLegacyVpnKind|fromDeepVpnKind|UNKNOWN' app/src/main/java/com/notcvnt/rknhardering
./gradlew testDebugUnitTest --tests com.notcvnt.rknhardering.NativeSignalCatalogTest
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

公开的原始日志可能包含接口名称、IP 地址、路径和软件包名。提交 issue 前请删除秘密与个人数据。

### 回滚

回退不兼容的生成器/目录改动，或安装彼此匹配的 APK 与文档版本。

## 证据等级

**结构性。**已根据目录回退与映射表核验。这属于服务级信号。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 外部第一方文档或官方项目：[Project issues](https://github.com/xtclovver/RKNHardering/issues).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `native-library`, `general-diagnostics`, `syscall-unavailable`.

[返回原生检查参考](../)
