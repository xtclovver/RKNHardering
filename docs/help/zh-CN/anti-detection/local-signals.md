---
title: Android 本地信号——Binder、TUN、路由与本地主机
permalink: /help/zh-CN/anti-detection/local-signals/
---

# Android 本地信号——Binder、TUN、路由与本地主机

本地检查回答的不是“数据包去了哪里？”，而是“Android 如何向这个 UID 描述网络？”。即使流量直连且 GeoIP 正确，这些信号仍可能可见。

## 本地通道一览

| 通道 | RKNHardering 中的示例 | 为什么一个 Hook 不够 |
|---|---|---|
| 框架/Binder | `TRANSPORT_VPN`、`IS_VPN`、`VpnTransportInfo`、`NOT_VPN`、`LinkProperties`、回调 | 数据由 `system_server` 生成；原生 Hook 不会改变它 |
| libc/JNI | `NetworkInterface`、`getifaddrs()`、ioctl | 针对 `ConnectivityManager` 的 Java Hook 不会影响 libc 或内核 |
| netlink/内核 | `RTM_GETLINK`、`RTM_GETADDR`、路由、策略规则、qdisc | 原始系统调用会绕过普通 Zygisk/libc 拦截 |
| proc/sysfs | `/proc/net/*`、`/sys/class/net` | SELinux 行为取决于 ROM；并非每台设备都会拒绝访问 |
| PackageManager | VPN 客户端和 `VpnService` 声明 | 与隧道当前是否活动无关 |
| 本地控制面 | SOCKS/HTTP、Xray gRPC、Clash/sing-box REST | 密码不会隐藏监听器；扫描仍能识别协议和端口 |
| dumpsys/系统服务 | `vpn_management`、活动的 `VpnService` 实例 | 普通应用通常受限，但 ROM 和权限级别会改变可用性 |

## 无 root

### 可以做什么

不需要系统 HTTP/SOCKS 代理和 PAC 设置时，应将其关闭。检查 `settings get global http_proxy`、Java 属性和按网络设置。系统代理是独立的直接检测来源，而且对隐藏 VPN 没有帮助。

关闭不必要的本地主机监听器。Clash/mihomo/sing-box/Xray 中的控制 API 应被禁用，或至少不能由目标应用访问。强密钥可以保护控制命令，但 RKNHardering 还会识别 SOCKS5、HTTP CONNECT，以及已知的 REST 或 gRPC API。

可以利用 Android 的软件包可见性机制，但不要高估它。从 Android 11 开始，应用通常只能看到经过过滤的软件包集合；不过 `QUERY_ALL_PACKAGES`、intent 查询、共享 UID、安装器关系和 OEM 策略都可能扩大可见范围。参见 Android 官方[软件包可见性过滤](https://developer.android.com/training/package-visibility)文档。

如果要求所有本地通道都看起来干净，应把 VPN 移到外部网关。一次架构调整即可从受测 Android 设备上移除 `VpnService`、TUN、VPN 应用和本地主机守护进程。

### 无 root 时通常无法解决的内容

沙箱中的 APK 无法在不修改系统或内核的前提下，让 Android 内核针对另一个应用返回按 UID 过滤的 netlink dump。它也无法可靠改写另一个应用收到的 Binder `NetworkCapabilities` 响应，更无法在 TUN 接口仍为其他应用正常工作的同时，把该接口从 `getifaddrs()` 中隐藏。

修改版 APK 或所谓“免 root Xposed”并不等价。重新打包会改变应用签名和完整性，而进程注入会直接触及 `HOOK_MARKERS`、`RWX_MEMORY_REGIONS`、`LIBRARY_INTEGRITY`，以及 beta 直接系统调用或链接器检查。对 RKNHardering 而言，这通常比原始 VPN 信号更糟。

### 次级资料空间

工作资料可能隐藏另一个资料中安装的 VPN 应用，并允许独立的网络设置；但 Android 仍共享同一个内核和网络栈，而且 RKNHardering 能看到用户 ID 和资料状态。详情见[资料空间](../profiles/)。

## 有 root

完整覆盖本地信号需要两层，并在必要时增加第三层：

1. **框架层：**在 Vector/LSPosed 中运行 VPNHide 模块，作用域只选择 `System Framework`。它会在 Binder 对象被序列化到目标进程之前进行清理。
2. **原生层：**kmod、KPM 或 Zygisk 三者中只能选择一个。优先采用内核变体，因为原始系统调用无法绕过其过滤，而且目标进程本身不会被修改。
3. **端口/软件包层：**为目标 UID 进行 `PackageManager` 过滤和回环访问阻断。

详细安装说明见 [VPNHide 与 VPNHide Next](../root-vpnhide/)。

### NetworkCapabilities 与 LinkProperties

上游 VPNHide 声称会在 `system_server` 中过滤 `NetworkCapabilities`、`NetworkInfo`、`LinkProperties`、活动网络、网络列表和回调。这是正确的介入点：RKNHardering 收到的是已经清理过的 Parcel，而不是在自身进程中加载 Xposed bridge。

务必核对作用域。在 Vector/LSPosed 中只选择 **`System Framework`**，不要选择 RKNHardering。把目标应用加入作用域会产生进程内 Hook 暴露面，而且 VPNHide 的架构并不需要这样做。

### 网络接口、路由与 netlink

内核后端至少必须覆盖：

- `ioctl(SIOCGIFFLAGS/SIOCGIFNAME/SIOCGIFCONF/...)`；
- `getifaddrs()` 和 `NetworkInterface`；
- netlink `RTM_GETLINK`、`RTM_GETADDR` 与路由 dump；
- 在允许访问时覆盖 `/proc/net/route` 和 IPv6 路由视图；
- 所选后端支持时，覆盖接口索引侧信道和策略规则。

上游 VPNHide 记录了已知缺口：原始系统调用可以绕过 Zygisk；已发布矩阵中的当前内核后端没有覆盖部分 `/proc/net/tcp*` 与 `if_inet6` 路径；KPM 也有单独的功能对等限制。因此，“模块已启用”必须通过 RKNHardering 的具体条目验证，不能只看管理器状态页面。

VPNHide Next 声称提供更广的模式，覆盖 sysfs/procfs、MTU/MSS/TCP_INFO、PMTU/GSO、BPF、qdisc、时序以及链路本地行为。这属于外部项目声明。应在实际固件上比较 Minimum、Medium 和 Maximum 模式，并始终保留恢复路径。

### 本地主机与 API

最佳方案是关闭监听器。无法关闭时，应按 UID 阻止访问。上游 VPNHide 提供独立的 `portshide` 组件，为所选应用创建规则。VPNHide Next 声称使用 `security_socket_connect` 内核 Hook，而不是 iptables。

不要根据一次 `connection refused` 就下结论：它表示连接被拒绝，可能正是预期结果。`timeout` 表示操作没有及时完成；对扫描器而言，这是不同的行为特征，也可能成为时序信号。应以 RKNHardering 自身显示的分类为准。

### PackageManager

VPNHide 的 Apps 角色会针对所选观察者 UID，过滤枚举、intent 解析、直接查询、安装器信息和 UID 映射。系统 UID 与应用查询自身必须继续正常工作。配置完成后，应确认启动器和安装器仍能运行，而且 VPN 客户端仍能识别自身。

## 验证结果

查找目标软件包 UID：

```bash
adb shell cmd package list packages -U | grep 'com.notcvnt.rknhardering'
```

检查基线状态：

```bash
adb shell dumpsys connectivity
adb shell ip -details link
adb shell ip route show table all
adb shell ip rule
adb shell settings get global http_proxy
```

安装了对应上游 VPNHide 后端时，只使用只读诊断：

```bash
adb shell su -c 'cat /data/system/vpnhide_config.json'
adb shell su -c 'ls -la /data/adb/modules | grep -i vpnhide'
adb shell su -c 'cat /proc/vpnhide_ctl 2>/dev/null || cat /proc/vpnhide_targets 2>/dev/null'
adb logcat -d | grep -iE 'VpnHide|Vector|LSPosed'
```

`/proc/vpnhide_*` 路径会因版本或分支而异。`no such file or directory` 表示路径不存在，或该版本使用其他控制接口；不要手动创建这个文件。

更改后强制停止应用并运行两次检查。Zygisk 和端口规则可能要求重启进程。内核层或 `system_server` 层通常可以在不完整重启设备的情况下应用配置更新，但首次安装模块后必须重启。

## 剩余信号

干净的本地视图不会移除 GeoIP、DNS、STUN 或服务端指纹。内核隐藏不会自动隐藏 root。软件包隐藏也不会改变文件签名或进程内 Hook。反过来也一样：干净的 root 命名空间不会隐藏 `TRANSPORT_VPN`。

[返回反检测指南首页](../)
