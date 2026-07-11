---
title: IP comparison
permalink: /help/en/ip-comparison/
---

# IP comparison

## What is checked and why

The module establishes consensus inside the RU and non-RU checker groups, then compares their canonical public IPs to reveal routing differences.

## What the result means

A mismatch can result from split tunneling, a VPN or proxy, endpoint failure, different address families, or a network transition. It does not prove one cause by itself.

## Limitations and possible false positives

Partial endpoint failures, IPv4/IPv6 differences, captive portals, and network handovers can temporarily break consensus. Re-run on a stable network before acting.

## Recommendations for this vector

The external [gowarp-server](https://github.com/paulkarpunin/gowarp-server) project claims to configure WARP on root-managed Linux servers. This is not a project-verified bypass guarantee. Do not run its curl-to-bash command. Audit the script, review firewall and routing changes, back up the server, and test on a disposable VPS with a known recovery path. Re-run both checker groups afterward.

## Required permissions and risks

The check uses the app's existing network access. A WARP/VPS change requires server root and can lock you out through a routing or firewall mistake. It does not hide local native signals, device root, custom firmware, or server-side detection.

## Evidence level

**Project verified:** the consensus and comparison behavior is implemented and tested in RKNHardering. **External project claim:** the WARP/VPS mitigation remains conditional.

## Sources and last verification date

- External project claim: [gowarp-server](https://github.com/paulkarpunin/gowarp-server).
- Discussion: [issue #79](https://github.com/xtclovver/RKNHardering/issues/79).
- Project verified: IpComparisonChecker and the RKNHardering README.
- Last verified: 2026-07-11.

[Back to language index](./)
