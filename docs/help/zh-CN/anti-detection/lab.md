---
title: 实验室方法、验证命令与回滚
permalink: /help/zh-CN/anti-detection/lab/
---

# 实验室方法、验证命令与回滚

一次随机运行证明不了任何事情。网络会变化、GeoIP 提供商会产生分歧、Android 会切换默认网络，而 beta 策略会有意抑制不稳定观测。下面是一套最低限度的可复现流程。

## 测试配置

至少创建四种配置，并且每次只改变一个变量。

| ID | 状态 | 目的 |
|---|---|---|
| B0 | 干净设备，VPN 关闭 | 建立 OEM/ROM/root/模拟器误报基线 |
| B1 | VPN 开启，RKNHardering 位于 VPN 内 | 获取完整的 VPN 与服务端信号集合 |
| B2 | VPN 开启，RKNHardering 被排除 | 明确展示 TUN、分流绕过和直连出口的组合 |
| H1 | 所选隐藏方法 | 与 B1/B2 对比，并识别新出现的 Hook/root 信号 |
| R1 | 外部路由器，本机 VPN 关闭 | 最佳的架构级无 root 基线 |
| P1 | 工作资料、私密资料或分身资料 | 将隔离与网络路径分开测试 |

对于已 root 场景，还应分别以“仅框架”“仅原生后端”和“两者组合”运行 H1。这样可以快速定位哪一层没有生效。

## 每次运行前需要记录的内容

- 设备型号和 build fingerprint；
- Android 版本、`uname -r` 显示的内核版本，以及 SELinux 状态；
- 当前用户 ID 和资料类型；
- root 管理器/框架及模块的准确版本；
- VPN 客户端、TUN 或代理模式、MTU、IPv4/IPv6 状态和软件包路由；
- Wi-Fi 或移动网络，以及测试时间；
- 预期出口和 DNS 路径；
- 应用显示时的网络 epoch 标识符。

不要在未脱敏的情况下公开 SuperKey、订阅详情、API 密钥、完整 VPN 配置、私有 IP 地址或主机名。

## 无 root 状态收集

```bash
adb shell getprop ro.build.fingerprint
adb shell uname -a
adb shell getenforce
adb shell pm list users
adb shell am get-current-user
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell dumpsys connectivity
adb shell ip -details addr
adb shell ip -details route show table all
adb shell ip rule
adb shell settings get global http_proxy
```

在某些 ROM 上，普通 shell 无法看到全部策略规则或 `/proc/net` 文件。这属于诊断权限限制，不是系统干净的证据。

每次运行之间强制停止应用：

```bash
adb shell am force-stop com.notcvnt.rknhardering
adb shell monkey -p com.notcvnt.rknhardering 1
```

`monkey` 会启动应用的 launcher activity；但当应用没有启动器入口或设备处于锁定状态时，它可能失败。此时请手动启动应用。

## 额外的 root 诊断

```bash
adb shell su -c 'id'
adb shell su -c 'ls -la /data/adb/modules'
adb shell su -c 'cat /data/system/vpnhide_config.json 2>/dev/null'
adb shell su -c 'cat /proc/vpnhide_ctl 2>/dev/null || cat /proc/vpnhide_targets 2>/dev/null'
adb logcat -c
# 手动运行一次测试
adb logcat -d | grep -iE 'RKNHardering|VpnHide|Vector|LSPosed|Zygisk'
```

不要为了读取文件而执行 `chmod 777`、关闭 SELinux 或更改所有权。这些操作会破坏安全模型，并产生额外检测信号。

## 不进行完整扫描时检查本地主机

RKNHardering 已经会执行扫描。若要手动检查已知控制端点，只测试具体地址即可：

```bash
adb shell 'toybox nc -z -w 1 127.0.0.1 9090; echo exit=$?'
adb shell 'toybox nc -z -w 1 127.0.0.1 19090; echo exit=$?'
```

`nc` 是否可用取决于 ROM。`connection refused` 表示该地址和端口没有监听器接受连接；`timeout` 表示操作未能及时完成；`not found` 表示 shell 中不存在该命令。Shell UID 和 RKNHardering UID 可能受不同防火墙规则约束，因此仍应以应用自身结果为最终判断依据。

## 各层验收标准

### 网络路径

- 预期 IP 至少连续两次运行保持稳定；
- 俄罗斯与非俄罗斯分组之间不应出现无法解释的分歧；
- IPv4/IPv6 与 DNS 不应执行相互矛盾的策略；
- STUN/UDP 行为应符合所选模型；
- 网络变化应产生新的预期 epoch，而不是随机混合旧、新结果。

### 框架层

- 不再存在 `TRANSPORT_VPN`、`IS_VPN` 或 `VpnTransportInfo`；
- `NOT_VPN` 与活动网络保持一致；
- `LinkProperties` 中不包含 VPN 接口、路由或 DNS 服务器；
- 回调和 Binder beta 路径不应与普通 API 相互矛盾。

### 原生层

- 无论按名称还是按类型，都不再存在 TUN/TAP 接口；
- `getifaddrs()`、ioctl、netlink、route/proc/sysfs 及相关视图保持一致；
- 接口索引和 SIOCGIFCONF 不留下可用于回归识别的差异；
- 套接字身份、MTU/MSS/PMTU 与 qdisc 行为不应和所声称的物理接口相矛盾。

### 完整性

- 除非绝对必要，目标进程不得接收 Xposed 或 Zygisk 后端注入；
- 不应出现新的 RWX、maps、链接器或库完整性不一致；
- SELinux 保持 enforcing，系统分区保持只读；
- root 路径和挂载不应对目标 UID 可见；
- 用户/资料与预期场景一致。

## 定位原因

| 观测结果 | 最可能的原因 | 修正方法 |
|---|---|---|
| Java 层干净，原生层不干净 | 原生后端未启用、UID 错误或 Hook 不受支持 | 核验后端、UID 和内核版本；不要再添加第二个后端 |
| 原生层干净，但仍有 `TRANSPORT_VPN` | 框架模块没有在 `system_server` 中加载 | 检查 Vector/LSPosed、`System Framework` 作用域，并重启设备 |
| VPN 已隐藏，但检测到本地主机 | 端口角色或 API 监听器未被覆盖 | 关闭 API，或使用 UID 防火墙/端口隐藏规则 |
| 本地全部干净，但结论仍为 detected | GeoIP、IP 共识、CDN、STUN 或位置问题 | 修正路由和出口，不要继续添加 Hook |
| 启用 Zygisk 后出现 RWX/链接器发现 | 进程内后端本身可被检测 | 切换到内核后端，并移除对目标进程的注入 |
| 只剩工作资料相关条目 | 场景确实运行在大于 0 的用户 ID 下 | 改在所有者用户中运行，或接受“待复核”是准确结果 |
| Shell 中出现 `permission denied` | 权限不足或受 SELinux 限制 | 不要把它解释为干净；在不削弱 SELinux 的前提下使用可用诊断 |
| `address already in use` | 另一个监听器占用了端口 | 找到占用者或关闭 API；单纯换端口无法躲过完整扫描 |
| `invalid config` | JSON 或 schema 错误 | 恢复备份、校验文件，并通过界面应用配置 |

## 风险与回滚计划

开始 root 或内核测试前，应准备有记录的回滚流程：

1. 记录原厂 boot/init_boot 镜像和已知可用的修补镜像存放位置。
2. 确认如何进入 bootloader 或 recovery。
3. 确认如何启用所选 root 管理器的安全模式。
4. 记录最后安装的是哪个模块。
5. 备份 `/data/system/vpnhide_config.json` 和 VPN 配置。
6. 导出工作资料或私密资料中保存的数据。

发生故障时，应禁用最近一次更改。不要在已经损坏的状态上继续安装另一个模块。若网络访问丢失，先把原生后端和端口规则恢复到原始状态，再检查框架层。若安装内核 ZIP 后出现 boot loop，不要再加载另一个内核模块“修复”它——应恢复已知可用的镜像，或通过该模块的官方机制将其禁用。

## 本指南的完整性检查

[完整矩阵](../matrix/)依据当前枚举和注册表源生成，并由 `docs/help/zh-CN/anti-detection/_validate.py` 检查。脚本必须确认：

- 65/65 个 `EvidenceSource` 条目；
- 85/85 个 `NativeSignalId` 条目；
- 41/41 个 beta ID；
- 每一行的“无 root”和“有 root”列均已填写；
- 不存在损坏的内部 Markdown 链接。

该脚本有意不发起任何网络请求，也不会把项目与外部归档进行比较。`docs` 之外的文件会在创建归档时通过整棵目录树的哈希另行检查。

[返回反检测指南首页](../)
