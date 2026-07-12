# Beta checks research

## Scope and repository baseline

- Baseline: `8bb3b2eda6933fde4d30c8bcdcc487aa08fa85ef` (`main`).
- Safety-contract follow-up baseline: `50824cc` (`main`).
- Android: min SDK 26, target/compile SDK 36.
- ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64`.
- The first increment contains settings, additive evidence metadata, availability and suppression models, verdict policy, UI/export wiring, and tests. Existing native detector output is not accepted as beta evidence.

## Decisions

- User-facing beta labels retain the widely supported Greek `β` glyph. The visually similar `ꞵ` required by the original handoff is not rendered reliably by Android system fonts on supported devices.
- Non-SDK calls are best effort. Android 9 and later restrict non-SDK access through direct references, reflection, and JNI; blocked reflection commonly appears as `NoSuchMethodException`. A blocked call maps to `UNAVAILABLE` or `PERMISSION_DENIED`, never to a clean result.
- `UserManager.isManagedProfile()` describes the context user from API 30. `UserManager.isProfile()` does so from API 33. `UserManager.isHeadlessSystemUserMode()` is available from API 31. UID-derived user ID and public APIs are Tier A; exact hidden user type remains Tier B.
- Private Space uses `android.os.usertype.profile.PRIVATE`. Ordinary applications cannot enumerate locked private profiles; an app inside a locked Private Space is stopped. Failure to enumerate another profile is neutral.
- WireGuard `WG_CMD_GET_DEVICE` is registered with `GENL_UNS_ADMIN_PERM`; current OpenVPN DCO peer dumps use `GENL_ADMIN_PERM`. Global WireGuard/OpenVPN/XFRM/BPF/netfilter inspection is therefore Tier C for this app and is not enabled without a separately consented privileged provider.
- Existing `RTM_GETRULE` parsing uses route structures and must be replaced with `fib_rule_hdr` and `FRA_*` before policy-rule output can affect R2. Existing broad `inet_diag` output must gain exact `SO_COOKIE` correlation, completeness limits, cancellation, benign fixtures, and parser tests first.
- The socket/routing source now uses a connected self-owned UDP descriptor, `SO_COOKIE` exact inet_diag lookup, read-only libnetd getters, destination `RTM_GETROUTE`, `fib_rule_hdr`/`FRA_UID_RANGE`, and `RTM_GETADDR`. Table IDs, marks, rule counts, `/32` and `/128` addresses remain informational without a typed causal mismatch.
- Socket/routing probes are exposed as opt-in beta after parser, cancellation, FD-lifecycle, benign, and emulator checks. Device-matrix coverage remains incomplete, so unavailable/partial getters never become an authoritative negative and this family cannot produce a hard signal by itself.
- Stable and beta evidence from the same underlying group cannot form an R2 quorum. The first implementation maps stable sources to groups and excludes same-group corroboration.
- The normative check registry owns source/domain/independence metadata. Unknown or contradictory metadata is suppressed as `ABI_OR_PARSER_MISMATCH`; causal probes remain non-hard until typed counter/tuple/egress validation exists.
- A scan registers a default-network callback and treats its initial `onAvailable`/capabilities/link-properties sequence as the baseline, not as a transition. Only the app's default network participates in epoch stability; auxiliary IMS/EIMS/VCN network churn is excluded. An unstable attempt is retried once after a short cancellation-aware delay, and only a second unstable attempt is reported as `RACE` with exported change reasons.
- Canary, proxy, interface-marker, and privileged counter observations remain suppressed from verdict impact until their check-specific repetition, benign-context, underlying-path, and causal-delta requirements are complete. Network-request consent is passed as the immutable scan snapshot rather than reread during a probe.
- Privileged AIDL protocol version 2 adds session cancellation. The provider does not hold its session monitor while native work runs, so timeout or scan cancellation can reach native polling without opening a command/path surface.
- A hidden-API family disabled by the user is `SKIPPED`, not `UNSUPPORTED`. Capability failures and user choices remain distinct in coverage and exports.

## Authoritative sources

- Android non-SDK restrictions: https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces (checked 2026-07-11).
- Android `UserManager`: https://developer.android.com/reference/android/os/UserManager (checked 2026-07-11).
- AOSP Private Space architecture: https://source.android.com/docs/security/features/private-space (checked 2026-07-11).
- AOSP `UserManager.java`: `frameworks/base/core/java/android/os/UserManager.java`, current source and Android 15/16 release tags.
- AOSP `IUserManager.aidl`: `frameworks/base/core/java/android/os/IUserManager.aidl`, current source. Binder use requires a version-pinned descriptor/signature adapter and permission-aware results.
- Android common kernel WireGuard: `drivers/net/wireguard/netlink.c`; `WG_CMD_GET_DEVICE` uses `GENL_UNS_ADMIN_PERM`.
- Android common kernel OpenVPN DCO: `drivers/net/ovpn/netlink-gen.c`; peer dump operations use `GENL_ADMIN_PERM`.
- Android bionic UAPI import process: `platform/bionic/libc/kernel/uapi` and `generate_uapi_headers.sh`; device kernels may expose a different supported subset.
- Android `ParcelFileDescriptor.fromDatagramSocket`: https://developer.android.com/reference/android/os/ParcelFileDescriptor#fromDatagramSocket(java.net.DatagramSocket) (checked 2026-07-11). API 26–28 wrap the socket's internal descriptor, so the wrapper is retained with a weak owner reference for the socket lifetime; API 29+ closes the duplicated wrapper normally.
- Android common-kernel inet_diag UAPI: `include/uapi/linux/inet_diag.h`; exact lookup carries `idiag_cookie[2]`. Current inet_diag handlers validate the supplied cookie before returning a socket.
- Android common-kernel routing UAPI: `include/uapi/linux/rtnetlink.h`, `include/uapi/linux/fib_rules.h`, and `include/uapi/linux/if_addr.h`. Policy rules use `fib_rule_hdr` and `FRA_*`, not `rtmsg` route attributes.
- AOSP netd client: `system/netd/include/NetdClient.h` and `system/netd/client/NetdClient.cpp`. Only bounded local getters `getNetworkForSocket` and `getNetworkForProcess` are resolved; the blocking dnsproxyd-backed `getNetworkForDns`, setters, and VPN protection calls are not invoked.
- Android `ConnectivityManager.NetworkCallback`: https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback (checked 2026-07-11). Callback transitions are latched so an A→B→A change cannot be mistaken for a stable epoch.

## Capability tiers

- Tier A: current UID/user/path facts, public `UserManager`, public connectivity snapshot, self-owned descriptors and sockets, supported route/link/address queries, `/proc/self`, and privacy-safe local facts.
- Tier B: hidden reflection/Binder queries, private `libnetd_client` symbols, broad socket diagnostics, selected `/proc/net` and sysfs data. Denial is expected and neutral.
- Tier C: global WireGuard/OpenVPN DCO/XFRM state and BPF/netfilter capability queries. They run only when both beta masters are enabled and the user explicitly selects Shizuku or root. The fixed AIDL has no command/path surface, pins the provider UID and protocol version, sanitizes rows in the provider process, and never falls back between providers. Other-process state remains out of scope.

## Verification

- Baseline: `gradlew.bat testDebugUnitTest` with Android Studio JBR 21.
- Each real probe must add version/capability guards, parser tests, denied/unavailable tests, benign and positive fixtures, suppression/privacy tests, verdict tests, and UI/export tests before verdict impact is enabled.
- Safety-contract follow-up: targeted beta policy/registry/epoch/export tests and full `testDebugUnitTest` with Android Studio JBR 21 and in-process Kotlin compiler.
- Privileged-provider follow-up: Shizuku 13.1.5 and libsu 6.0.0 contract tests, AIDL generation, provider identity/no-fallback tests, and native builds for `arm64-v8a`, `armeabi-v7a`, and `x86_64`.
- Epoch/guard follow-up: tracker bootstrap/transition and retry tests, immutable network-consent tests, counter/canary suppression tests, privileged cancellation tests, export parity, full unit tests, lint, and debug assembly with Android Studio JBR 21.
- Final local verification: `gradlew.bat test lint assembleDebug -Pkotlin.compiler.execution.strategy=in-process --no-daemon` with Android Studio JBR 21; 1017 tests completed, 2 skipped, lint passed, and native debug libraries/APK assembled for all configured ABIs.
