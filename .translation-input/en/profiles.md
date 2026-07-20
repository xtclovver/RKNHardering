---
title: Secondary spaces, work profiles, Private Space, and clones
permalink: /help/en/anti-detection/profiles/
---

# Secondary spaces, work profiles, Private Space, and clones

A profile separates data and packages well, but is poorly suited to fully concealing isolation. Android implements a work profile as a separate user: the UID is calculated as `100000 * userId + appId`, data is stored separately, and system APIs know the current user/profile. RKNHardering checks this explicitly.

Official sources: [AOSP Work profiles](https://source.android.com/docs/devices/admin/managed-profiles) and [AOSP Private space](https://source.android.com/docs/security/features/private-space).

## What RKNHardering distinguishes

Stable native signals:

- `ISOLATION_PROFILE` — general profile context;
- `ISOLATION_CLONE` — characteristic clone-user ranges, including MIUI-like IDs;
- `ISOLATION_SECONDARY_USER` — any `userId > 0`;
- `ISOLATION_WORK_PROFILE` — managed/profile-owner indicators.

The beta layer adds `beta.user_profile`, `beta.foreground_user`, sandbox process/filesystem/namespace identity, and fscrypt identity. Individually they usually lead to review, but a profile combined with an independent network discrepancy can satisfy the beta quorum.

## Without root

### Work profiles: Shelter and Insular

[Shelter](https://gitea.angry.im/PeterCxy/Shelter) and [Insular](https://gitlab.com/secure-system/Insular) use the official managed-profile mechanism. They can:

- install a separate copy of RKNHardering or the VPN client;
- separate application data and accounts;
- hide packages that are installed only in the other profile;
- provide separate per-profile VPN settings on supported ROMs.

However, the device network and kernel remain shared, and the userId is visible. A profile is therefore useful for a specific package-visibility scenario, but does not replace kernel/Binder hiding.

The cleanest non-root arrangement keeps RKNHardering under the primary user and moves the VPN to an external router. No profile is then required, and no isolation signal is introduced.

If RKNHardering runs in the work profile while the VPN exists only in the owner profile, the application may receive a direct path and may not see the VPN package. The cost is an explicit `userId > 0`, work-profile state, and possible differences in network policy. Treat this as an experiment, not as a guaranteed pass.

### Private Space on Android 15+

Private Space is a separate private profile. When locked, the profile is stopped and its applications are hidden; when unlocked, it is an ordinary separate application copy in a different user context. A check cannot run inside a locked space, and the profile identity remains after unlocking.

Private Space hides applications from routine package enumeration well, but it does not automatically change the TUN or system-network model. If a device-wide VPN runs in the primary profile, the application in Private Space may still observe shared network signals.

### OEM Dual Apps / Second Space

Xiaomi/MIUI, Samsung Dual Messenger, Huawei PrivateSpace, and other OEM implementations use different user/profile models. Current RKNHardering native code separately recognizes clone ranges such as user 999 and 950–959. Renaming a launcher icon or package alias does not change this.

### Inspecting the profile

```bash
adb shell pm list users
adb shell am get-current-user
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell dumpsys user
```

`dumpsys user` may contain personal account/profile information; do not publish the complete output without redaction. For a specific user:

```bash
adb shell cmd package list packages --user 0 | grep com.notcvnt.rknhardering
```

Replace `0` with an ID from `pm list users` only for read-only inspection. Installing or deleting a profile can destroy its data.

## With root

Root does not make a profile invisible by itself. It helps apply VPNHide correctly to the UID of each application copy.

Upstream VPNHide resolves package names to UIDs through `packages.list`/`pm list packages -U`; current versions should account for both user and appId. VPNHide Next claims full work-profile support. After saving the targets, verify that the kernel control list contains the UID of the exact RKNHardering copy you are launching.

Example UID lookup:

```bash
adb shell cmd package list packages -U --user 0 | grep com.notcvnt.rknhardering
adb shell cmd package list packages -U --user 10 | grep com.notcvnt.rknhardering
```

Do not copy UIDs manually across reboots or reinstalls without checking again. The appId is usually stable, but the profile/user portion differs.

If a framework hook uses only appId, it may apply to all profiles. If the backend uses the complete UID, each copy must be added separately. Follow the README and diagnostics for the specific version.

A root-hiding module must also unmount for the UID/profile copy rather than only for the owner instance. Otherwise the primary copy appears clean while the work-profile copy can see `/data/adb` or mount traces.

## Practical scenarios

### Scenario 1: clean non-root setup

- RKNHardering under the owner user.
- VPN on an external router.
- No VPN application, system proxy, or local controller on the phone.

This minimizes local and isolation signals. Server-side GeoIP/CDN/DNS/RTT signals remain.

### Scenario 2: package separation without root

- VPN client only in the work profile.
- RKNHardering only under the owner user.
- Verify whether the ROM applies the VPN only to the profile or to the entire device.

This may remove package visibility and the local `VpnService` from the owner context, but OEM behavior differs. Capture `dumpsys connectivity` in both profiles and verify egress.

### Scenario 3: RKNHardering inside a profile

- RKNHardering in a work/private/secondary profile.
- VPN under the owner user or on the router.

The profile becomes a signal itself. This is useful only for studying the sensitivity of `ISOLATION_*` and the beta quorum.

### Scenario 4: root + VPNHide for multiple users

- The target is added to VPNHide for every copy.
- Framework scope is limited to `System Framework`.
- The kernel backend filters complete UIDs.
- Ports/App roles are verified separately.

This covers the local network model, but `ISOLATION_*` remains truthful. Do not break `UserManager` globally: doing so can disrupt the launcher, package manager, and device policies.

## Risks and rollback

Deleting a work profile or Private Space erases applications, keys, accounts, and local files inside that profile. Export required data through supported mechanisms before deletion. Shelter and Insular provide their own teardown procedures; follow them instead of forcibly removing the DPC.

Do not create or remove system users with `pm create-user`/`pm remove-user` on a primary device without a backup. The commands in this guide are restricted to reading state.

[Back to the contents](../)
