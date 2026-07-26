---
title: 次级用户、工作资料、私密空间与应用分身
permalink: /help/zh-CN/anti-detection/profiles/
---

# 次级用户、工作资料、私密空间与应用分身

资料空间很适合分离数据与软件包，但不适合隐藏“隔离本身存在”这一事实。Android 把工作资料实现为独立用户：UID 按 `100000 * userId + appId` 计算，数据单独保存，系统 API 也知道当前用户和资料。RKNHardering 会明确检查这些信息。

官方参考资料：[AOSP 工作资料](https://source.android.com/docs/devices/admin/managed-profiles)和 [AOSP 私密空间](https://source.android.com/docs/security/features/private-space)。

## RKNHardering 区分的内容

稳定版原生信号：

- `ISOLATION_PROFILE` — 通用资料空间上下文；
- `ISOLATION_CLONE` — 典型的分身用户范围，包括类似 MIUI 的 ID；
- `ISOLATION_SECONDARY_USER` — 任意 `userId > 0`；
- `ISOLATION_WORK_PROFILE` — 托管资料或资料所有者指标。

β 层还会加入 `beta.user_profile`、`beta.foreground_user`、沙箱进程/文件系统/命名空间身份，以及 fscrypt 身份。单独出现时，这些信号通常只会导致待复核；但若资料信号与独立网络差异组合，就可能形成 β 法定人数。

## 无 root

### 工作资料：Shelter 与 Insular

[Shelter](https://gitea.angry.im/PeterCxy/Shelter) 和 [Insular](https://gitlab.com/secure-system/Insular) 使用官方托管资料机制。它们可以：

- 安装独立的 RKNHardering 或 VPN 客户端副本；
- 分离应用数据与账号；
- 让应用看不到只安装在另一个资料中的软件包；
- 在支持的 ROM 上提供按资料独立的 VPN 设置。

不过，设备网络和内核仍然共享，而且用户 ID 可见。因此，资料空间适合实现特定的软件包可见性布局，但不能替代内核或 Binder 隐藏。

最干净的无 root 方案是让 RKNHardering 留在所有者用户中，并把 VPN 移到外部路由器。这样既不需要资料空间，也不会产生隔离信号。

当 RKNHardering 运行在工作资料，而 VPN 只存在于所有者资料时，应用可能获得直连路径，也可能看不到 VPN 软件包。代价是明确的 `userId > 0`、工作资料状态，以及网络策略之间可能出现的分歧。应把它视为实验，而不是保证通过的方案。

### Android 15+ 的私密空间

私密空间是独立的私密资料。空间锁定时，资料会停止，其应用也会被隐藏；解锁后，它就是另一个用户上下文中的普通独立应用副本。检查无法在锁定的空间内运行，而解锁后资料身份依然存在。

私密空间能够有效阻止常规软件包枚举看到其中应用，但不会自动改变 TUN 或系统网络模型。如果主资料中运行着全设备 VPN，私密空间内的应用仍可能观察到共享网络指标。

### OEM 双开应用与第二空间

Xiaomi/MIUI、Samsung Dual Messenger、Huawei PrivateSpace 及其他 OEM 实现采用不同的用户与资料模型。当前 RKNHardering 原生代码会单独识别用户 999、950–959 等分身范围。修改启动器标签或软件包别名不会改变这一点。

### 检查资料空间

```bash
adb shell pm list users
adb shell am get-current-user
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell dumpsys user
```

`dumpsys user` 可能包含个人账号或资料信息；不要在未脱敏的情况下公开完整输出。检查特定用户：

```bash
adb shell cmd package list packages --user 0 | grep com.notcvnt.rknhardering
```

只在只读检查时，把 `0` 替换成 `pm list users` 报告的 ID。删除资料会销毁其中保存的全部数据。

## 有 root

Root 本身不会让资料空间不可见，但有助于把 VPNHide 正确应用到每个应用副本的 UID。

上游 VPNHide 通过 `packages.list` 或 `pm list packages -U` 把软件包名称解析为 UID；当前版本必须同时考虑 user 与 app ID。VPNHide Next 声称完整支持工作资料。保存目标后，应确认内核控制列表包含实际启动的那份 RKNHardering 副本的 UID。

UID 查询示例：

```bash
adb shell cmd package list packages -U --user 0 | grep com.notcvnt.rknhardering
adb shell cmd package list packages -U --user 10 | grep com.notcvnt.rknhardering
```

不要在未重新核对的情况下，跨重新安装或重启手动沿用旧 UID。App ID 通常稳定，但资料/用户部分会不同。

只使用 app ID 的框架 Hook 可能会对所有资料生效；使用完整 UID 的后端则需要分别添加每个副本。应遵循实际使用版本的 README 与诊断说明。

Root 隐藏模块也必须针对资料副本的 UID 执行 unmount，而不能只处理所有者用户中的实例。否则主用户应用可能看起来干净，但工作资料副本仍能看到 `/data/adb` 或挂载痕迹。

## 实用布局

### 场景 1：干净的无 root 配置

- RKNHardering 在所有者用户中运行。
- VPN 在外部路由器上运行。
- 手机上不存在 VPN 应用、系统代理或本地控制器。

这会最大限度减少本地和隔离指标。服务端 GeoIP、CDN、DNS 和 RTT 信号仍然存在。

### 场景 2：无 root 的软件包分离

- VPN 客户端只存在于工作资料中。
- RKNHardering 只存在于所有者用户中。
- 核验 ROM 是只对该资料应用 VPN，还是对整台设备应用 VPN。

这可能从所有者上下文中移除软件包可见性和本地 `VpnService`，但 OEM 行为不一致。应在两个资料中分别记录 `dumpsys connectivity` 并核验出口。

### 场景 3：RKNHardering 位于资料空间中

- RKNHardering 在工作、私密或次级资料中运行。
- VPN 在所有者用户中运行，或位于路由器上。

资料本身会成为信号。此布局只适合研究 `ISOLATION_*` 信号和 β 法定人数的敏感性。

### 场景 4：Root + VPNHide，多用户覆盖

- 为每一个已安装副本把目标加入 VPNHide。
- 框架作用域仅限 `System Framework`。
- 让内核后端按完整 UID 进行过滤。
- 分别核验 Ports 与 Apps 角色。

这可以覆盖本地网络视图，但 `ISOLATION_*` 仍然如实存在。不要试图在全局破坏 `UserManager`：这可能导致启动器、软件包管理器和设备策略异常。

## 风险与回滚

删除工作资料或私密空间会清除其中的应用、密钥、账号和本地文件。删除前应通过受支持的机制导出所需数据。Shelter 和 Insular 各自提供了卸载说明；应按官方流程操作，而不是强制移除设备策略控制器。

没有备份时，不要在主力设备上使用 `pm create-user` 或 `pm remove-user` 创建或删除系统用户。本指南中的命令仅用于读取状态。

[返回反检测指南首页](../)
