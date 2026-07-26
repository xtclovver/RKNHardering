---
title: IP Comparison
permalink: /help/en/ip-comparison/
---

# IP Comparison

## What is checked and why

The module establishes consensus separately within the Russian and non-Russian service groups, then compares their canonical public IP addresses to expose routing differences.

## What the result means

A discrepancy can indicate split tunneling, a VPN or proxy, a service error, different address families, or a transitional network state. It does not prove any particular cause.

## Limitations and possible false positives

Partial service failures, IPv4 and IPv6 differences, a captive portal, or a network transition can temporarily disrupt consensus. Repeat the test on a stable network before making changes.

## Recommendations for this vector

The external [gowarp-server](https://github.com/paulkarpunin/gowarp-server) project describes configuring WARP on a rooted Linux server. This is not a project-verified guarantee that the IP comparison will be bypassed. Do not run a curl-to-bash command without review. First inspect the script, verify its firewall and routing changes, make a backup, and test it on a separate VPS with a known recovery path. Then repeat both checker groups.

## Required permissions and risks

The check itself uses the application's existing network access. WARP or VPS changes require root access on the server and can interrupt connectivity when routing or firewall configuration is wrong. They do not conceal local native indicators, device root, custom firmware, or server-side detection.

## Evidence level

**Project-verified:** consensus and comparison are implemented and tested in RKNHardering. **Claimed by an external project:** the WARP or VPS arrangement remains conditional.

## Sources and last verification date

- Claimed by an external project: [gowarp-server](https://github.com/paulkarpunin/gowarp-server).
- Discussion: [issue #79](https://github.com/xtclovver/RKNHardering/issues/79).
- Project-verified: `IpComparisonChecker` and the RKNHardering README.
- Last verified: 2026-07-11.

[Back to the language contents](./)
