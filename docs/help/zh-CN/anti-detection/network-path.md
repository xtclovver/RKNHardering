---
title: 网络路径——GeoIP、DNS、CDN、STUN 与通话
permalink: /help/zh-CN/anti-detection/network-path/
---

# 网络路径——GeoIP、DNS、CDN、STUN 与通话

即使 VPNHide 配置得十分完善，本节仍然重要。内核与框架 Hook 可以改变 Android 本地响应，但远端服务器看到的仍是真实地址、ASN、延迟和传输可用性。

## RKNHardering 检查什么

**本项目已核验：**网络层包括 `GEO_IP`、俄罗斯与非俄罗斯服务之间的 IP 共识、DNS 比较、`CdnPullingChecker`、STUN、Telegram 与 WhatsApp 通话传输、底层网络探测、RTT 三角测量、ICMP 欺骗和域名可达性。部分结果仅用于诊断，但独立通道之间存在分歧时，仍可能共同促成最终 `DETECTED` 结论。

关键指标包括：

- GeoIP 把地址归类为外国、托管/数据中心，或代理/VPN；
- 俄罗斯与非俄罗斯服务组报告不同的规范化 IP 地址；
- IPv4 与 IPv6 采用不同路径；
- DNS 在 VPN 和底层网络上得到不同解析结果；
- CDN 或重定向服务观察到不同路径；
- STUN 暴露独立的 UDP 出口；
- 设备物理位置在俄罗斯，而网络出口显示为外国，或反过来；
- 绑定到底层网络的连接返回另一个地址；
- 本地代理报告的公网 IP 与直连路径不同。

## 无 root

### 方案 A：外部路由器或专用网关

这是最干净的无 root 架构。VPN 或代理运行在路由器上，手机连接普通 Wi-Fi。Android 本机不存在 `VpnService` 或 TUN 痕迹，因此 RKNHardering 只能观察外部网络路径；这条路径必须在内部保持一致。

**社区报告：**[RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense) 项目提供面向路由器的配置，同时明确警告，仅在路由器层使用 TUN 并不能解决 CDN pulling。其现成资料包括 [Sub-Store](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md) 和 [S-UI](https://github.com/jinndi/RKNHardering-defense/blob/main/S-UI.md)。应把这些内容当作路由示例，而不是当前应用版本必然通过的证明。

实际需要核验三件事：HTTP(S)、DNS 和 UDP 必须从同一条预期路径离开；IPv6 要么采用相同配置，要么只在特定实验配置中有意关闭；手机不得保留可能意外成为底层网络的移动数据后备路径。

### 方案 B：按应用分流

Android 官方通过 `VpnService.Builder.addAllowedApplication()` 与 `addDisallowedApplication()` 支持允许列表和排除列表。在 Android 版 sing-box 中，可通过 **Settings → Profile Override → Per-app Proxy** 配置。路由规则文档见 [sing-box route rule](https://sing-box.sagernet.org/configuration/route/rule/)。

以当前 sing-box 语法表达的基本思路如下：

```json
{
  "route": {
    "rules": [
      {
        "package_name": ["com.notcvnt.rknhardering"],
        "action": "route",
        "outbound": "direct"
      }
    ]
  }
}
```

这不是可以直接使用的完整配置：`direct` 标签、DNS 规则和 schema 版本必须与你的安装相匹配。在替换当前可用配置之前，应使用客户端内置检查器验证配置，并保留备份副本。

**限制：**当前 `TUN_ACTIVE_PROBE` 会有意识别“TUN 接口存在，但 RKNHardering 的 `vpnActive` 为 false”的状态。因此，按应用绕过可能一方面消除外国 IP，另一方面又确认该软件包被显式排除。要获得干净的无 root 结果，通常应把它与外部网关配合，而不是使用本地 `VpnService`。

### DNS 必须走同一条路径

不要让 HTTP 直连而 DNS 经过 VPN，也不要反过来。RKNHardering 会把解析行为与网络结果进行比较。对于被排除的应用，应使用底层网络 DNS，或使用通过相同出口离开的独立解析器。不要为了路由 DNS 而设置系统 HTTP 代理：这会产生单独的 `SYSTEM_PROXY` 信号。

在 sing-box 配置中，DNS 规则应与流量规则分开，但二者都应导向同一预期路径。[SUB-STORE.md](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md) 提供了大型社区示例；不要在未核对自己的标签、规则集和受信软件包前整段照搬。

### STUN、通话与 UDP

仅支持 TCP 的代理可能在 HTTP 上看起来干净，但 UDP 和 STUN 却直连。应根据预期行为选择修正方式：

- 如果应用应当直连，HTTP、DNS 和 UDP 都必须直连；
- 如果必须使用同一个代理或 VPN 出口，客户端必须真正支持 UDP，而不是静默回退；
- 阻止 STUN 会移除响应，但“无响应”不一定等同于干净：RKNHardering 可能报告 `unsupported`、`no signal` 或待复核状态；
- 阻止通话端点可能破坏 Telegram 或 WhatsApp。只应在具备明确回滚流程的测试配置中这样做。

### 地理位置与漫游

不要把 GPS 欺骗当作主要策略。检查还会使用 MCC/MNC、SIM、蜂窝与 Wi-Fi 上下文以及服务端数据；不一致的伪造只会制造更多矛盾。合理的配置应当能解释观测到的位置—出口组合。家庭归属地路由的漫游可能是合法情况，代码为此保留了独立的 `HOME_ROUTED_ROAMING` 上下文。

## 有 root

Root 不能替代上述步骤。只有先让网络路径保持一致，root 才能隐藏本机存在 VPN 这一事实。

实用顺序如下：

1. 在 VPN 客户端或网关上配置软件包路由。
2. 让 HTTP、DNS 和 UDP 使用同一预期出口。
3. 使用 VPNHide 或 VPNHide Next 关闭 Binder 与原生指标。
4. 禁止目标 UID 访问本地主机控制 API。
5. 确认 root 或 Hook 痕迹没有成为新的待复核原因。

当 RKNHardering 应当直连时，之所以仍需要内核或框架隐藏，正是因为本地 TUN 依然存在。当 RKNHardering 应当留在隧道内时，需要注意上游 VPNHide 的架构限制：把活动 VPN 网络替换为物理网络，在分流场景下最为自洽。该项目明确指出，服务端信号不属于本地隐藏的覆盖范围。参见 [VPNHide detection vectors](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)。

对于本地主机，最佳方案是不暴露任何 API。若其他应用确实需要该 API，VPNHide `portshide` 或 VPNHide Next 的内核级阻断应针对 RKNHardering UID 生效。Clash API 的密码对安全有帮助，但不会隐藏开放端口或协议本身；RKNHardering 会扫描回环接口和已知 REST 端点。

## 控制面配置

若无明确需求，Mihomo/Clash 的 `external-controller` 和 sing-box/Xray API 不应监听 `0.0.0.0`。对实验用手机，更安全的选项是：

- 禁用控制器或 API；
- 当客户端与面板都支持时，绑定到 Unix socket；
- 保持只监听回环地址，使用强密钥，并在 root 层额外阻止目标 UID；
- 不要把避开 `9090`、`9091`、`9097` 或 `19090` 等常见端口当作唯一防护：更换端口无法阻止完整扫描。

Mihomo 官方文档：[通用配置](https://wiki.metacubex.one/en/config/general/)。sing-box 官方文档：[配置](https://sing-box.sagernet.org/configuration/)。

## 验证结果

先在不使用 root 专属命令的情况下记录网络基线：

```bash
adb shell dumpsys connectivity
adb shell ip addr
adb shell ip route
adb shell ip rule
adb shell settings get global http_proxy
adb shell pm list users
```

在 Android 上，SELinux 可能限制 `/proc` 的部分内容；`permission denied` 表示权限不足，不代表路由或套接字不存在。不要只为诊断就把 SELinux 切换为 permissive：这会削弱安全性，并直接产生 `ROOT_SELINUX` 信号。

更改后重启应用：

```bash
adb shell am force-stop com.notcvnt.rknhardering
adb shell monkey -p com.notcvnt.rknhardering 1
```

在同一网络上至少运行两次检查。然后分别切换 Wi-Fi 与移动数据再次测试：网络 epoch 的变化应能解释结果变化，而不是把它误认为“随机成功”。

## 剩余信号

即使公网 IP 正确，托管或代理数据库、数据中心 ASN、RTT、CDN 行为和服务端指纹仍可能留下信号。即使位于外部路由器之后，RKNHardering 也可能正确观察到外国出口。反过来，本地隐藏也不会修复分流 DNS 或 IPv6 泄漏。

[返回反检测指南首页](../)
