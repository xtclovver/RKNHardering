---
title: "原生信号：root-system-rw"
permalink: /help/zh-CN/native/root-system-rw/
---

# 原生信号：root-system-rw

## 检查内容与目的

RKNHardering 通过应用可见的 Android 与原生状态检查稳定向量 `root-system-rw`。

## 结果含义

Review 表示发现了需要与设备配置核对的项；它是辅助证据，不是独立结论。

## 限制与可能的误报

厂商固件、企业管理、模拟器、工作资料和合法开发工具可能产生相似状态。

## 针对该向量的建议

将该项与 Root 管理器、固件、挂载、属性、UID 和 SELinux 核对。不要只为隐藏信号而获取 Root。

## 所需权限与风险

检查本身不需要额外权限。Root、固件、挂载、属性或资料修改可能导致无法启动、数据丢失或隔离减弱；必须先备份。

## 证据等级

**项目验证：**该向量由 checker/catalog 测试覆盖。外部缓解声明仍是有条件的。

## 来源与最后核验日期

- Project verified / проверено проектом: RKNHardering source and tests.
- External project claim / заявлено внешним проектом: [VPN Hide](https://github.com/okhsunrog/vpnhide).
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[返回 Native signs 参考](../)

