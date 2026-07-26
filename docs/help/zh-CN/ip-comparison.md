---
title: IP 比较
permalink: /help/zh-CN/ip-comparison/
---

# IP 比较

## 检查内容与原因

该模块分别在俄罗斯服务组和非俄罗斯服务组内建立共识，然后比较两组得到的规范化公网 IP 地址，以暴露路由差异。

## 结果含义

出现差异可能表示分流、VPN 或代理、服务错误、不同地址族，或网络正在切换。它不能单独证明任何一种具体原因。

## 限制与可能的误报

部分服务故障、IPv4 与 IPv6 差异、强制门户或网络切换，都可能暂时破坏共识。在做出更改之前，应在稳定网络上重复测试。

## 针对此向量的建议

外部项目 [gowarp-server](https://github.com/paulkarpunin/gowarp-server) 介绍了如何在已 root 的 Linux 服务器上配置 WARP。这不是由本项目核验的“必然绕过 IP 比较”保证。不要在未审查的情况下执行 curl-to-bash 命令。应先检查脚本，核验其防火墙和路由改动，完成备份，并在具备明确恢复路径的独立 VPS 上测试。之后，再分别重复运行两个检查器分组。

## 所需权限与风险

检查本身使用应用现有的网络访问权限。修改 WARP 或 VPS 需要服务器 root 权限；路由或防火墙配置错误可能中断连接。这些改动不会隐藏本地原生指标、设备 root、自定义固件或服务端检测。

## 证据级别

**本项目已核验：**RKNHardering 已实现并测试共识与比较逻辑。**外部项目声明：**WARP 或 VPS 布局仍然是有条件的方案。

## 来源与最后核验日期

- 外部项目声明：[gowarp-server](https://github.com/paulkarpunin/gowarp-server)。
- 讨论：[issue #79](https://github.com/xtclovver/RKNHardering/issues/79)。
- 本项目已核验：`IpComparisonChecker` 与 RKNHardering README。
- 最后核验：2026-07-11。

[返回简体中文目录](./)
