---
title: "BPF 映射可访问性的保留深度检测 ID"
permalink: /help/zh-CN/native/deep-bpf-map-accessible/
---

# BPF 映射可访问性的保留深度检测 ID

> **ID：** `DEEP_BPF_MAP_ACCESSIBLE`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 为兼容性保留该 ID；2.10.0 中没有独立的信号生成器
> **在最终判定中的作用：** 目录项/兼容性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`fromDeepVpnKind("bpf_map_accessible")` 会映射到 `DEEP_BPF_MAP_ACCESSIBLE`，但整合后的 `nativeDetectVpnDetector()` 并未调用 `detectBpfMaps()`。目前同一个 `kind` 字符串只由旧版流水线生成，并被赋予 ID `BPF_MAP_ACCESSIBLE`。

### 精确触发条件

当前深度检测流水线中没有信号生成器。理论上的触发条件是成功打开三个 netd BPF 固定路径中的任意一个。

## 结果含义

没有深度检测结果并不能说明 BPF 映射已经受到保护。应检查旧版 `bpf-map-accessible` 信号，以及应用 UID 实际拥有的访问权限。

**该行如何影响报告：**该 ID 仍保留在信号目录和 UI 中，但 2.10.0 不会生成这一类型的独立阳性行；通常由更具体的相邻信号覆盖。

## 限制与可能的误报

同一个 `kind` 对应两个 ID，可能在未来修改后造成误解。本页记录的是 2.10.0 的状态；若之后接入该函数，必须同步更新映射与测试。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

保留系统默认的 SELinux/BPF 权限，不要削弱 `/sys/fs/bpf` 的访问控制。当前这个 ID 不需要任何处理。

### 有 root 权限

不要删除已固定的 netd 映射，也不要禁用 eBPF。若目标是阻止访问，只应针对 `untrusted_app` 做最小范围的策略修改，并验证流量统计是否仍然正常。

### 如何验证结果

```bash
rg -n 'detectBpfMaps|nativeDetectVpnDetector|nativeDetectVpnAdvanced|bpf_map_accessible' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

删除或损坏 netd BPF 映射可能导致防火墙、流量统计和网络功能失效。不要执行破坏性清理。

### 回滚

撤销 sepolicy 或模块修改并重启设备。如果 netd 状态已经受损，应恢复 boot/system 镜像，而不是手工重建映射。

## 证据等级

**目录项/兼容性。**已确认深度检测函数中没有相关调用，而旧版流水线存在生成器；当前仅属于目录登记状态。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[Linux BPF](https://docs.kernel.org/bpf/index.html).
- 外部第一方文档或官方项目：[AOSP eBPF traffic monitoring](https://source.android.com/docs/core/datausage/ebpf-traffic-monitor).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `bpf-map-accessible`, `proc-net-dev-vpn`.

[返回原生检查参考](../)
