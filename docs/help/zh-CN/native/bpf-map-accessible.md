---
title: "可访问 netd 的 BPF 接口索引映射"
permalink: /help/zh-CN/native/bpf-map-accessible/
---

# 可访问 netd 的 BPF 接口索引映射

> **ID：** `BPF_MAP_ACCESSIBLE`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

旧版探针尝试以只读方式打开三个路径：`/sys/fs/bpf/map_netd_iface_index_name_map`、`/sys/fs/bpf/netd_shared/map_netd_iface_index_name_map` 和 `/sys/fs/bpf/netd_iface_index_name_map`。只要任意路径打开成功，就生成 `bpf_map_accessible`；旧版策略将其归为高置信度。

### 精确触发条件

普通应用进程能够打开上述固定 BPF pin 路径之一。

## 结果含义

原生 Android 通常会限制访问。如果应用可以读取，该映射可能暴露 ifindex 到接口名称的关系，并绕过表层隐藏。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

探针只测试路径能否打开，不会读取映射，也不会确认其中存在 VPN 条目。不同 Android 版本的路径布局可能不同。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

不要在生产 ROM 上放宽 SELinux 或 BPF 文件系统权限。若自定义 ROM 暴露了访问，最干净的处理方式是恢复到启用 enforcing 的原生构建。

### 有 root 权限

只做最小策略修复：目标 UID 不应能读取 netd 映射。不要全局禁用 BPF 或 netd。VPNHide Next 声称支持 eBPF 过滤，但这属于高风险内核实验。

### 如何验证结果

```bash
adb shell ls -l /sys/fs/bpf 2>/dev/null | head -80
adb shell 'for p in /sys/fs/bpf/map_netd_iface_index_name_map /sys/fs/bpf/netd_shared/map_netd_iface_index_name_map /sys/fs/bpf/netd_iface_index_name_map; do [ -r "$p" ] && echo readable:$p; done'
```
Shell 是否可访问，不等于应用 UID 是否可访问。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

修改 netd BPF 映射或策略可能破坏流量统计、防火墙和网络连接。不要删除已 pin 的映射。

### 回滚

撤销 sepolicy 或模块修改，并重启 netd 或设备；若系统不稳定，请恢复 boot 镜像。

## 证据等级

**高。**已根据三个固定路径核验；旧版策略将该信号归为高置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Linux BPF docs](https://docs.kernel.org/bpf/index.html).
- 外部第一方文档或官方项目：[AOSP eBPF traffic monitoring](https://source.android.com/docs/core/datausage/ebpf-traffic-monitor).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `deep-bpf-map-accessible`, `ifindexname-vpn`.

[返回原生检查参考](../)
