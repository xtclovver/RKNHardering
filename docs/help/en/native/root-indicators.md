---
title: "Native signal: root-indicators"
permalink: /help/en/native/root-indicators/
---

# Native signal: root-indicators

## What is checked and why

RKNHardering checks the stable native vector `root-indicators` to compare app-visible kernel, process, interface, route, property, file, or socket state with expected Android behavior.

## What the result means

A detected or review result means this vector returned evidence worth examining. A clean or unavailable line only describes this vector; it does not prove that no VPN or modification exists.

## Limitations and possible false positives

Device vendors, Android versions, SELinux policy, transient network state, and legitimate work-profile or enterprise software can change the observation. Treat one line in the context of the category and final verdict.

## Recommendations for this vector

Do not root or modify the system merely to hide a root signal. Verify the reported artifact against your root manager, firmware, mount state, SELinux state, and a known-clean device image.

## Required permissions and risks

The check uses app-visible native state. Remediation may involve privileged system changes with boot-loop, data-loss, warranty, and security risks; back up first and keep a recovery path.

## Evidence level

**Project verified:** the vector is implemented in RKNHardering and covered by its checker/catalog tests. External mitigation claims and community configurations remain conditional.

## Sources and last verification date

- External project claim / заявлено внешним проектом: [VPN Hide](https://github.com/okhsunrog/vpnhide).
- Project verified / проверено проектом: RKNHardering source and tests.
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[Back to Native signs reference](../)
