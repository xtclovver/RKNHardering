---
title: "Native signal: getsockname-leak"
permalink: /help/en/native/getsockname-leak/
---

# Native signal: getsockname-leak

## What is checked and why

RKNHardering checks the stable native vector `getsockname-leak` to compare app-visible kernel, process, interface, route, property, file, or socket state with expected Android behavior.

## What the result means

A detected or review result means this vector returned evidence worth examining. A clean or unavailable line only describes this vector; it does not prove that no VPN or modification exists.

## Limitations and possible false positives

Device vendors, Android versions, SELinux policy, transient network state, and legitimate work-profile or enterprise software can change the observation. Treat one line in the context of the category and final verdict.

## Recommendations for this vector

Identify the owning process, property, file, socket, port, or syscall result before changing configuration. Stop one component at a time and re-run the scan; do not expose local proxy ports or delete files blindly.

## Required permissions and risks

The check requires no extra user permission beyond the app's existing access. Any root, kernel, hook, firewall, or profile change has a larger security and data-loss risk than the diagnostic itself.

## Evidence level

**Project verified:** the vector is implemented in RKNHardering and covered by its checker/catalog tests. External mitigation claims and community configurations remain conditional.

## Sources and last verification date

- Project verified / проверено проектом: RKNHardering source and tests.
- Discussion context: [issue #51](https://github.com/xtclovver/RKNHardering/issues/51).
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[Back to Native signs reference](../)
