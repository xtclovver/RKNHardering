---
title: "Native signal: isolation-secondary-user"
permalink: /help/en/native/isolation-secondary-user/
---

# Native signal: isolation-secondary-user

## What is checked and why

RKNHardering checks the stable native vector `isolation-secondary-user` using app-visible Android and native state.

## What the result means

A review result means this vector exposed an artifact that should be compared with the device configuration. It is supporting evidence, not a standalone verdict.

## Limitations and possible false positives

Vendor firmware, enterprise management, emulators, profiles, and legitimate development tools can produce similar state.

## Recommendations for this vector

Confirm whether a cloned app, secondary user, managed profile, or vendor isolation feature is intentional before disabling it.

## Required permissions and risks

The check needs no extra permission. Privileged root, firmware, mount, property, or profile changes can cause boot failure, data loss, or weaker isolation; back up first.

## Evidence level

**Project verified:** this vector is implemented and covered by checker/catalog tests. External mitigation claims remain conditional.

## Sources and last verification date

- Project verified / проверено проектом: RKNHardering source and tests.
- External project claim / заявлено внешним проектом: [VPN Hide](https://github.com/okhsunrog/vpnhide).
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[Back to Native signs reference](../)

