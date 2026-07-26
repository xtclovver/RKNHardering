---
title: Laboratory Methodology, Verification Commands, and Rollback
permalink: /help/en/anti-detection/lab/
---

# Laboratory Methodology, Verification Commands, and Rollback

One random run proves nothing. Networks change, GeoIP providers disagree, Android switches the default network, and the beta policy deliberately suppresses unstable observations. The following is a minimum reproducible protocol.

## Test Profiles

Create at least four profiles and change only one variable at a time.

| ID | State | Purpose |
|---|---|---|
| B0 | Clean device, VPN disabled | Baseline for OEM/ROM/root/emulator false positives |
| B1 | VPN enabled, RKNHardering inside the VPN | Complete set of VPN and server-side signals |
| B2 | VPN enabled, RKNHardering excluded | Explicitly demonstrates TUN plus split-tunnel bypass and direct egress |
| H1 | Selected hiding method | Comparison with B1/B2 and detection of new hook/root signals |
| R1 | External router, local VPN disabled | Best architectural non-root baseline |
| P1 | Work, private, or clone profile | Isolation tested separately from the network path |

For rooted scenarios, also run H1 with framework-only, native-only, and combined configurations. This quickly reveals which layer is not working.

## What to Record Before Each Run

- device model and build fingerprint;
- Android version, kernel version from `uname -r`, and SELinux state;
- current user ID and profile;
- root manager/framework and exact module versions;
- VPN client, TUN or proxy mode, MTU, IPv4/IPv6 state, and package route;
- Wi-Fi or mobile network and time of test;
- expected egress and DNS path;
- network epoch identifier, when the app displays one.

Do not publish a SuperKey, subscription details, API secrets, the complete VPN configuration, or private IP addresses and hostnames without redaction.

## Non-Root State Collection

```bash
adb shell getprop ro.build.fingerprint
adb shell uname -a
adb shell getenforce
adb shell pm list users
adb shell am get-current-user
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell dumpsys connectivity
adb shell ip -details addr
adb shell ip -details route show table all
adb shell ip rule
adb shell settings get global http_proxy
```

On some ROMs, the ordinary shell cannot see all policy rules or `/proc/net` files. This is a diagnostic permission limitation, not evidence that the system is clean.

Force-stop the app between runs:

```bash
adb shell am force-stop com.notcvnt.rknhardering
adb shell monkey -p com.notcvnt.rknhardering 1
```

`monkey` launches the app’s launcher activity, but it may fail when the app has no launcher entry or the device is locked. Launch the app manually in that case.

## Additional Root Diagnostics

```bash
adb shell su -c 'id'
adb shell su -c 'ls -la /data/adb/modules'
adb shell su -c 'cat /data/system/vpnhide_config.json 2>/dev/null'
adb shell su -c 'cat /proc/vpnhide_ctl 2>/dev/null || cat /proc/vpnhide_targets 2>/dev/null'
adb logcat -c
# Run one test manually
adb logcat -d | grep -iE 'RKNHardering|VpnHide|Vector|LSPosed|Zygisk'
```

Do not run `chmod 777`, disable SELinux, or change ownership merely to read a file. Those actions damage the security model and create additional detections.

## Checking Localhost Without a Full Scan

RKNHardering already performs the scan. For a manual check of known controller endpoints, specific addresses are sufficient:

```bash
adb shell 'toybox nc -z -w 1 127.0.0.1 9090; echo exit=$?'
adb shell 'toybox nc -z -w 1 127.0.0.1 19090; echo exit=$?'
```

Availability of `nc` depends on the ROM. `connection refused` means no listener accepts a connection on that address and port; `timeout` means the operation did not finish in time; `not found` means the command is absent from the shell. The shell UID and the RKNHardering UID may be subject to different firewall rules, so the app result remains the final criterion.

## Acceptance Criteria by Layer

### Network Path

- the expected IP remains stable across at least two runs;
- RU and non-RU groups do not diverge without explanation;
- IPv4/IPv6 and DNS do not follow contradictory policies;
- STUN/UDP behavior matches the selected model;
- a network change creates a new expected epoch rather than a random mixture of results.

### Framework

- no `TRANSPORT_VPN`, `IS_VPN`, or `VpnTransportInfo` remains;
- `NOT_VPN` and the active network are consistent;
- `LinkProperties` contains no VPN interface, routes, or DNS servers;
- callback and Binder beta paths do not contradict the ordinary API.

### Native

- no TUN/TAP interface remains by either name or type;
- `getifaddrs()`, ioctl, netlink, route/proc/sysfs, and related views are consistent;
- interface indices and SIOCGIFCONF do not leave regression oracles;
- socket identity, MTU/MSS/PMTU, and qdisc behavior do not contradict the claimed physical interface.

### Integrity

- the target process receives no Xposed or Zygisk backend unless strictly necessary;
- no new RWX, maps, linker, or library-integrity mismatch appears;
- SELinux remains enforcing and the system remains read-only;
- root paths and mounts are not visible to the target UID;
- the user/profile matches the intended scenario.

## Localizing the Cause

| Observation | Most likely cause | Correction |
|---|---|---|
| Java is clean, native is not | Native backend inactive, wrong UID, or unsupported hook | Verify the backend, UID, and kernel version; do not add a second backend |
| Native is clean, `TRANSPORT_VPN` remains | Framework module did not load in `system_server` | Verify Vector/LSPosed, the `System Framework` scope, and reboot |
| VPN is hidden, localhost is found | Ports role or API listener is not covered | Disable the API or use a UID firewall/port-hiding rule |
| Everything is locally clean, verdict is detected | GeoIP, IP consensus, CDN, STUN, or location | Correct the route and egress rather than adding hooks |
| RWX/linker findings appear after Zygisk | In-process backend is detectable | Move to a kernel backend and remove the target from injection |
| Only work-profile rows remain | The scenario genuinely runs under user ID greater than 0 | Run under the owner user, or accept review as an accurate signal |
| `permission denied` in the shell | Insufficient permissions or SELinux restriction | Do not treat it as clean; use available diagnostics without weakening SELinux |
| `address already in use` | Another listener occupies the port | Identify the owner or disable the API; changing a port does not defeat the complete scan |
| `invalid config` | JSON or schema error | Restore the backup, validate the file, and apply it through the UI |

## Risks and Rollback Plan

Before a root or kernel test, prepare a documented rollback procedure:

1. Record where the stock boot/init_boot image and the known-good patched image are stored.
2. Know how to enter the bootloader or recovery.
3. Know how to enable the selected root manager’s safe mode.
4. Record which module was installed last.
5. Save a copy of `/data/system/vpnhide_config.json` and the VPN configuration.
6. Export any data stored in work or private profiles.

When something fails, disable the most recent change. Do not install another module over a broken state. If network access is lost, first restore the native backend and port rules to their original state, then inspect the framework layer. If a boot loop begins after installing a kernel ZIP, do not load another kernel module “to fix it”—restore a known-good image or disable the responsible module through its official mechanism.

## Completeness Check for This Guide

The [complete matrix](../matrix/) is generated from the current enum and registry sources and is checked by `docs/help/en/anti-detection/_validate.py`. The script must confirm:

- 65 of 65 `EvidenceSource` entries;
- 85 of 85 `NativeSignalId` entries;
- 41 of 41 beta IDs;
- completed “without root” and “with root” columns for every row;
- no broken internal Markdown links.

The script deliberately makes no network requests and does not compare the project with an external archive. Files outside `docs` are checked separately during archive creation by hashing the tree.

[Back to the anti-detection index](../)
