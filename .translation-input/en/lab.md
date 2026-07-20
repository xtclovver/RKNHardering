---
title: Laboratory procedure, verification commands, and rollback
permalink: /help/en/anti-detection/lab/
---

# Laboratory procedure, verification commands, and rollback

One random run proves nothing. Networks change, GeoIP providers disagree, Android switches the default network, and β policy deliberately suppresses unstable observations. The following is a minimal reproducible protocol.

## Test profiles

Create at least four profiles, changing one variable at a time.

| ID | State | Purpose |
|---|---|---|
| B0 | Clean device, VPN disabled | Baseline OEM/ROM/root/emulator false positives |
| B1 | VPN enabled, RKNHardering inside the VPN | Full set of VPN and server-side signals |
| B2 | VPN enabled, RKNHardering excluded | Clearly shows TUN + split-tunnel bypass and direct egress |
| H1 | Selected hiding method | Compare with B1/B2 and look for new hook/root signals |
| R1 | External router, local VPN disabled | Best non-root architectural baseline |
| P1 | Work/private/clone profile | Isolation separated from the network path |

For rooted devices, also run H1 with framework-only, native-only, and combined configurations. This quickly shows which layer is not working.

## What to record before a run

- device model and build fingerprint;
- Android version, kernel version from `uname -r`, and SELinux state;
- current userId/profile;
- root manager/framework and exact module versions;
- VPN client, TUN/proxy mode, MTU, IPv4/IPv6, and package route;
- Wi-Fi/mobile network and time;
- expected egress and DNS;
- network epoch identifier, if the application displays it.

Do not publish a SuperKey, subscriptions, API secrets, a complete VPN configuration, or private IP addresses/hostnames without redaction.

## Without root: collect the state

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

On some ROMs, an ordinary shell cannot see every policy rule or `/proc/net` file. This is a diagnostic permission limitation, not proof of a clean state.

Force-stop between runs:

```bash
adb shell am force-stop com.notcvnt.rknhardering
adb shell monkey -p com.notcvnt.rknhardering 1
```

`monkey` starts the launcher activity, but it may fail if the application has no launcher entry or the device is locked. In that case, start it manually.

## With root: additional diagnostics

```bash
adb shell su -c 'id'
adb shell su -c 'ls -la /data/adb/modules'
adb shell su -c 'cat /data/system/vpnhide_config.json 2>/dev/null'
adb shell su -c 'cat /proc/vpnhide_ctl 2>/dev/null || cat /proc/vpnhide_targets 2>/dev/null'
adb logcat -c
# Start one test manually
adb logcat -d | grep -iE 'RKNHardering|VpnHide|Vector|LSPosed|Zygisk'
```

Do not run `chmod 777`, disable SELinux, or change ownership merely to read a file. That damages the security model and creates additional detections.

## Check localhost without a full scan

RKNHardering already performs the scan. To check known controller endpoints manually, specific addresses are sufficient:

```bash
adb shell 'toybox nc -z -w 1 127.0.0.1 9090; echo exit=$?'
adb shell 'toybox nc -z -w 1 127.0.0.1 19090; echo exit=$?'
```

Availability of `nc` depends on the ROM. `connection refused` means that no listener at that address/port accepted the connection; `timeout` means no response arrived in time; `not found` means the shell does not contain the command. The shell UID and the RKNHardering UID may see different firewall rules, so the application's result is the final criterion.

## Acceptance criteria by layer

### Network path

- the expected IP is stable in at least two runs;
- RU/non-RU groups do not disagree without explanation;
- IPv4/IPv6 and DNS do not follow different policies;
- STUN/UDP behavior matches the selected model;
- a network change creates a new expected epoch rather than a random mixture of results.

### Framework

- no `TRANSPORT_VPN`, `IS_VPN`, or `VpnTransportInfo`;
- `NOT_VPN` and the active network are consistent;
- LinkProperties contains no VPN interface/routes/DNS;
- callback and Binder β paths do not contradict ordinary APIs.

### Native

- no TUN/TAP by name or type;
- `getifaddrs`, ioctl, netlink, route/proc/sysfs views are consistent;
- ifindex and SIOCGIFCONF leave no oracle;
- socket identity, MTU/MSS/PMTU/qdisc do not contradict the claimed physical interface.

### Integrity

- the target process receives no Xposed/Zygisk backend unless required;
- no new RWX/maps/linker/library mismatch;
- SELinux is enforcing and the system is read-only;
- root paths/mounts are not visible to the target UID;
- user/profile matches the planned scenario.

## How to localize the cause

| Observation | Most likely cause | Fix |
|---|---|---|
| Java is clean, native is dirty | Native backend is inactive, targets the wrong UID, or uses an unsupported hook | Check backend, UID, and kernel version; do not add a second backend |
| Native is clean, `TRANSPORT_VPN` remains | Framework module did not load into `system_server` | Check Vector/LSPosed, `System Framework`, and reboot |
| VPN is hidden, localhost is found | Ports role/API listener is still exposed | Disable the API or use a UID firewall/portshide |
| Everything local is clean, final result is detected | GeoIP/IP consensus/CDN/STUN/location | Fix routing/egress, not hooks |
| RWX/linker findings appeared after Zygisk | In-process backend was detected | Switch to a kernel backend and remove the target from injection |
| Only work-profile rows trigger | The scenario really runs under userId > 0 | Run under the owner user or accept review as a truthful signal |
| `permission denied` in the shell | Insufficient privileges/SELinux | Do not treat it as clean; use available diagnostics without weakening SELinux |
| `address already in use` | Another listener occupies the port | Find its owner/disable the API; changing the port does not defeat a full scan |
| `invalid config` | JSON/schema error | Restore the backup, validate the file, and apply it through the UI |

## Risks and rollback plan

Before a root/kernel test, prepare a documented rollback:

1. Location of the stock boot/init_boot image and a known-good patched image.
2. How to enter the bootloader/recovery.
3. How to enable the selected root manager's safe mode.
4. Which module was installed last.
5. Where a copy of `/data/system/vpnhide_config.json` and the VPN configuration is stored.
6. Which data resides in the work/private profile and how it was exported.

When something fails, disable the most recent change. Do not install another module on top of a broken state. If networking is lost, first restore the native backend/ports to their original state, then inspect the framework layer. If a boot loop began after a kernel ZIP, do not load another kernel module “to fix it”: restore a known-good image or disable the responsible module using its official procedure.

## Completeness check for this guide

The [complete matrix](../matrix/) is built from the current enum/registry sources and checked by `docs/help/en/anti-detection/_validate.py`. The script must confirm:

- 65/65 `EvidenceSource`;
- 85/85 `NativeSignalId`;
- 41/41 β IDs;
- populated “without root” and “with root” columns for every row;
- no broken internal Markdown links.

The script intentionally makes no network requests and does not compare the project with an external archive. Files outside `docs` are checked separately during final archive assembly using a tree hash.

[Back to the table of contents](../)
