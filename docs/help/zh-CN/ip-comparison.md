---
title: IP 比较
permalink: /help/zh-CN/ip-comparison/
---

# IP 比较

## 检查内容与目的

模块先判断 RU 与 non-RU 组内共识，再比较两组的规范公网 IP，以发现路由差异。

## 结果含义

差异可能来自分流、VPN/代理、服务错误、IPv4/IPv6 差异或网络切换，不能单独证明具体原因。

## 限制与可能的误报

临时服务故障、强制门户和网络切换可能破坏共识。采取措施前应在稳定网络上复测。

## 针对该向量的建议

外部项目 [gowarp-server](https://github.com/paulkarpunin/gowarp-server) 声明可在具有 Root 权限的 Linux 服务器上配置 WARP；这不是项目验证的绕过保证。不要运行 curl-to-bash。应先审计脚本、检查防火墙与路由、备份服务器，并在具有明确恢复方法的测试 VPS 上试验。

## 所需权限与风险

检查使用应用现有网络权限。WARP/VPS 修改需要服务器 Root，路由或防火墙错误可能导致失联。它不会隐藏设备原生信号、Root、自定义固件或服务器端检测。

## 证据等级

**项目验证：**共识和比较逻辑已在 RKNHardering 中实现并测试。**外部项目声明：**WARP/VPS 场景仍是有条件的。

## 来源与最后核验日期

- 外部项目声明：[gowarp-server](https://github.com/paulkarpunin/gowarp-server)。
- 讨论：[issue #79](https://github.com/xtclovver/RKNHardering/issues/79)。
- 项目验证：IpComparisonChecker 与 README。
- 最后核验：2026-07-11。

[返回语言目录](./)
