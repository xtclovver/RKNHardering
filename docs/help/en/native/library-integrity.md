---
title: "Native signal: library-integrity"
permalink: /help/en/native/library-integrity/
---

# Native signal: library-integrity

## What is checked and why

RKNHardering checks the stable native vector `library-integrity` to compare app-visible kernel, process, interface, route, property, file, or socket state with expected Android behavior.

## What the result means

A detected or review result means this vector returned evidence worth examining. A clean or unavailable line only describes this vector; it does not prove that no VPN or modification exists.

## Limitations and possible false positives

Device vendors, Android versions, SELinux policy, transient network state, and legitimate work-profile or enterprise software can change the observation. Treat one line in the context of the category and final verdict.

## Recommendations for this vector

Audit loaded modules and hook frameworks before changing anything. VPN Hide claims coverage through kmod/KPM/Zygisk/LSPosed, but those components require root or hooking and may themselves create root, hook, Zygisk, LSPosed, or vpnhide signals.

## Required permissions and risks

RKNHardering itself uses ordinary app/native access. Countermeasures such as VPN Hide may require root plus kmod or KPM, Zygisk, and LSPosed; they can destabilize boot, weaken isolation, or reveal hooks. VPN Hide does not hide root, custom firmware, or server-side detection.

## Evidence level

**Project verified:** the vector is implemented in RKNHardering and covered by its checker/catalog tests. External mitigation claims and community configurations remain conditional.

## Sources and last verification date

- External project claim / заявлено внешним проектом: [VPN Hide](https://github.com/okhsunrog/vpnhide).
- Project verified / проверено проектом: RKNHardering source and tests.
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[Back to Native signs reference](../)
