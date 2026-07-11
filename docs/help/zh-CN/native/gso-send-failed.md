---
title: "原生信号：gso-send-failed"
permalink: /help/zh-CN/native/gso-send-failed/
---

# 原生信号：gso-send-failed

## 检查内容与目的

RKNHardering 检查稳定原生向量 `gso-send-failed`，将应用可见的内核、进程、接口、路由、属性、文件或套接字状态与 Android 预期行为比较。

## 结果含义

Detected 或 review 表示该向量提供了需要分析的证据。clean 或 unavailable 只描述该向量，不能证明不存在 VPN 或修改。

## 限制与可能的误报

设备厂商、Android 版本、SELinux、临时网络状态和工作资料可能影响结果。应结合分类和最终结论判断。

## 针对该向量的建议

核对具体路由、表、接口或 MTU/MSS，网络稳定后复测。不要盲目删除路由；先准备回滚并逐步验证连接。

## 所需权限与风险

路由修改可能中断连接；保存配置并先在测试环境验证。

## 证据等级

**项目验证：**该向量已在 RKNHardering 中实现，并由 checker/catalog 测试覆盖。外部声明和社区配置仍是有条件的。

## 来源与最后核验日期

- Community reported / сообщено сообществом: [issue #48](https://github.com/xtclovver/RKNHardering/issues/48) and [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense).
- Project verified / проверено проектом: RKNHardering source and tests.
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[返回 Native signs 参考](../)
