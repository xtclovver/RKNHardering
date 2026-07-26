---
title: Secondary Users, Work Profiles, Private Space, and App Clones
permalink: /help/en/anti-detection/profiles/
---

# Secondary Users, Work Profiles, Private Space, and App Clones

A profile separates data and packages well, but it is poorly suited to concealing the fact that isolation exists. Android implements a work profile as a separate user: the UID is calculated as `100000 * userId + appId`, data is stored separately, and system APIs know the current user and profile. RKNHardering checks this explicitly.

Official references: [AOSP Work profiles](https://source.android.com/docs/devices/admin/managed-profiles) and [AOSP Private space](https://source.android.com/docs/security/features/private-space).

## What RKNHardering distinguishes

Stable native signals:

- `ISOLATION_PROFILE` — general profile context;
- `ISOLATION_CLONE` — characteristic clone-user ranges, including MIUI-like IDs;
- `ISOLATION_SECONDARY_USER` — any `userId > 0`;
- `ISOLATION_WORK_PROFILE` — managed-profile or profile-owner indicators.

The β layer adds `beta.user_profile`, `beta.foreground_user`, sandbox process/filesystem/namespace identity, and fscrypt identity. Individually, these usually lead to review, but a profile combined with an independent network discrepancy can form a β quorum.

## Without root

### Work profiles: Shelter and Insular

[Shelter](https://gitea.angry.im/PeterCxy/Shelter) and [Insular](https://gitlab.com/secure-system/Insular) use the official managed-profile mechanism. They can:

- install a separate copy of RKNHardering or a VPN client;
- separate application data and accounts;
- hide packages that are installed only in another profile from the application;
- provide separate per-profile VPN settings on supported ROMs.

The device network and kernel remain shared, however, and the user ID is visible. A profile is therefore useful for a specific package-visibility arrangement, but it does not replace kernel or Binder hiding.

The cleanest non-root arrangement is to keep RKNHardering in the owner user and move the VPN to an external router. No profile is then needed, and no isolation signal is created.

When RKNHardering runs in a work profile while the VPN exists only in the owner profile, the application may receive a direct path and may not see the VPN package. The cost is an explicit `userId > 0`, work-profile state, and possible disagreement between network policies. Treat this as an experiment, not as a guaranteed pass.

### Private Space on Android 15+

Private Space is a separate private profile. When the space is locked, the profile is stopped and its applications are hidden; when unlocked, it is an ordinary separate application copy in another user context. A check cannot run inside a locked space, and the profile identity remains after it is unlocked.

Private Space is effective at hiding applications from routine package enumeration, but it does not automatically change the TUN or system-network model. If a device-wide VPN runs in the main profile, an application in Private Space may still observe shared network indicators.

### OEM Dual Apps and Second Space

Xiaomi/MIUI, Samsung Dual Messenger, Huawei PrivateSpace, and other OEM implementations use different user and profile models. The current RKNHardering native code separately recognizes clone ranges such as user 999 and users 950–959. Renaming a launcher label or package alias does not change this.

### Inspecting profiles

```bash
adb shell pm list users
adb shell am get-current-user
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell dumpsys user
```

`dumpsys user` may contain personal account or profile information; do not publish its full output without redaction. To inspect a specific user:

```bash
adb shell cmd package list packages --user 0 | grep com.notcvnt.rknhardering
```

Replace `0` with an ID reported by `pm list users` only for read-only inspection. Removing a profile can destroy all data stored inside it.

## With root

Root does not make a profile invisible by itself. It helps apply VPNHide correctly to the UID of each application copy.

Upstream VPNHide resolves package names to UIDs through `packages.list` or `pm list packages -U`; current versions must account for the user and app ID. VPNHide Next states that it fully supports work profiles. After saving the targets, verify that the kernel control list contains the UID of the exact RKNHardering copy being launched.

Example UID lookup:

```bash
adb shell cmd package list packages -U --user 0 | grep com.notcvnt.rknhardering
adb shell cmd package list packages -U --user 10 | grep com.notcvnt.rknhardering
```

Do not copy a UID manually across reinstalls or reboots without checking it again. The app ID is usually stable, but the profile or user portion differs.

A framework hook that uses only the app ID may apply across every profile; a backend that uses the full UID requires each copy to be added separately. Follow the README and diagnostics for the exact version in use.

A root-hiding module must also perform its unmount operation for the UID of the profile copy, not only for the owner instance. Otherwise the main application can look clean while the work-profile copy still sees `/data/adb` or mount artifacts.

## Practical arrangements

### Scenario 1: clean non-root setup

- RKNHardering runs under the owner user.
- The VPN runs on an external router.
- No VPN application, system proxy, or local controller is present on the phone.

This minimizes local and isolation indicators. Server-side GeoIP, CDN, DNS, and RTT signals remain.

### Scenario 2: package separation without root

- The VPN client exists only in the work profile.
- RKNHardering exists only under the owner user.
- Verify whether the ROM applies the VPN only to that profile or to the whole device.

This can remove package visibility and the local `VpnService` from the owner context, but OEM behavior varies. Capture `dumpsys connectivity` in both profiles and verify the egress.

### Scenario 3: RKNHardering inside a profile

- RKNHardering runs in a work, private, or secondary profile.
- The VPN runs under the owner user or on a router.

The profile itself becomes a signal. This arrangement is useful only for studying sensitivity to `ISOLATION_*` signals and the β quorum.

### Scenario 4: root plus VPNHide for multiple users

- Add the target to VPNHide for every installed copy.
- Limit the framework scope to `System Framework`.
- Make the kernel backend filter full UIDs.
- Verify Ports and App roles separately.

This covers the local network view, but `ISOLATION_*` remains truthful. Do not attempt to break `UserManager` globally: doing so can disrupt the launcher, package manager, and device policies.

## Risks and rollback

Removing a work profile or Private Space erases applications, keys, accounts, and local files inside it. Export required data through supported mechanisms before removal. Shelter and Insular provide their own teardown instructions; follow those rather than forcibly removing the device policy controller.

Do not create or remove system users with `pm create-user` or `pm remove-user` on a primary device without a backup. The commands in this guide are limited to reading state.

[Back to the contents](../)
