---
title: "原生信号：root-indicators"
permalink: /help/zh-CN/native/root-indicators/
---

# 原生信号：root-indicators

## 检查内容与目的

RKNHardering 检查稳定原生向量 `root-indicators`，将应用可见的内核、进程、接口、路由、属性、文件或套接字状态与 Android 预期行为比较。

## 结果含义

Detected 或 review 表示该向量提供了需要分析的证据。clean 或 unavailable 只描述该向量，不能证明不存在 VPN 或修改。

## 限制与可能的误报

设备厂商、Android 版本、SELinux、临时网络状态和工作资料可能影响结果。应结合分类和最终结论判断。

## 针对该向量的建议

不要只为隐藏 Root 信号而获取 Root。将报告项与 Root 管理器、固件、挂载和 SELinux 状态核对。

## 所需权限与风险

特权系统修改可能造成无法启动或数据丢失；必须先备份并准备恢复路径。

## 证据等级

**项目验证：**该向量已在 RKNHardering 中实现，并由 checker/catalog 测试覆盖。外部声明和社区配置仍是有条件的。

## 来源与最后核验日期

- External project claim / заявлено внешним проектом: [VPN Hide](https://github.com/okhsunrog/vpnhide).
- Project verified / проверено проектом: RKNHardering source and tests.
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[返回 Native signs 参考](../)
