---
title: "原生信号：udp-vpn-port"
permalink: /help/zh-CN/native/udp-vpn-port/
---

# 原生信号：udp-vpn-port

## 检查内容与目的

RKNHardering 检查稳定原生向量 `udp-vpn-port`，将应用可见的内核、进程、接口、路由、属性、文件或套接字状态与 Android 预期行为比较。

## 结果含义

Detected 或 review 表示该向量提供了需要分析的证据。clean 或 unavailable 只描述该向量，不能证明不存在 VPN 或修改。

## 限制与可能的误报

设备厂商、Android 版本、SELinux、临时网络状态和工作资料可能影响结果。应结合分类和最终结论判断。

## 针对该向量的建议

先确定进程、属性、文件、套接字或端口的所有者；一次只停用一个组件并复测。

## 所需权限与风险

检查本身不需要额外用户权限。Root、内核、Hook、防火墙或资料修改的风险高于诊断。

## 证据等级

**项目验证：**该向量已在 RKNHardering 中实现，并由 checker/catalog 测试覆盖。外部声明和社区配置仍是有条件的。

## 来源与最后核验日期

- Project verified / проверено проектом: RKNHardering source and tests.
- Discussion context: [issue #51](https://github.com/xtclovver/RKNHardering/issues/51).
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[返回 Native signs 参考](../)
