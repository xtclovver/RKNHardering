---
title: "Native signal: proc-ipv6-route-vpn"
permalink: /help/en/native/proc-ipv6-route-vpn/
---

# Native signal: proc-ipv6-route-vpn

## What is checked and why

RKNHardering checks the stable native vector `proc-ipv6-route-vpn` to compare app-visible kernel, process, interface, route, property, file, or socket state with expected Android behavior.

## What the result means

A detected or review result means this vector returned evidence worth examining. A clean or unavailable line only describes this vector; it does not prove that no VPN or modification exists.

## Limitations and possible false positives

Device vendors, Android versions, SELinux policy, transient network state, and legitimate work-profile or enterprise software can change the observation. Treat one line in the context of the category and final verdict.

## Recommendations for this vector

Inspect the exact route, table, interface, MTU/MSS, or kernel capability and repeat after the network is stable. Do not delete routes blindly: preserve a rollback path and verify connectivity after each change.

## Required permissions and risks

The check uses app-visible network state. Server or root routing changes can interrupt connectivity or lock you out; back up configuration and test on a disposable environment.

## Evidence level

**Project verified:** the vector is implemented in RKNHardering and covered by its checker/catalog tests. External mitigation claims and community configurations remain conditional.

## Sources and last verification date

- Community reported / сообщено сообществом: [issue #48](https://github.com/xtclovver/RKNHardering/issues/48) and [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense).
- Project verified / проверено проектом: RKNHardering source and tests.
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[Back to Native signs reference](../)
