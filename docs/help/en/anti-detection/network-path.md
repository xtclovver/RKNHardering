---
title: Network Path — GeoIP, DNS, CDN, STUN, and Calls
permalink: /help/en/anti-detection/network-path/
---

# Network Path — GeoIP, DNS, CDN, STUN, and Calls

This section matters even with a perfect VPNHide setup. Kernel and framework hooks can alter local Android responses, but remote servers still see the actual address, ASN, latency, and transport availability.

## What RKNHardering checks

Project-verified: the network layer includes `GEO_IP`, IP consensus across Russian and non-Russian services, DNS comparison, `CdnPullingChecker`, STUN, Telegram and WhatsApp call transport, underlying-network probes, RTT triangulation, ICMP spoofing, and domain reachability. Some results are diagnostic, but disagreement between independent channels can contribute to a final `DETECTED` verdict.

Key indicators include:

- a foreign country, hosting/datacenter classification, or proxy/VPN classification from GeoIP;
- different canonical IP addresses reported by Russian and non-Russian groups;
- different IPv4 and IPv6 paths;
- DNS resolving differently over the VPN and the underlying network;
- a CDN or redirector observing a different path;
- STUN exposing a separate UDP egress;
- the device being physically in Russia while its network exit appears foreign, or the reverse;
- a connection bound to the underlying network returning a different address;
- a local proxy reporting a different public IP from the direct path.

## Without root

### Option A: an external router or dedicated gateway

This is the cleanest non-root arrangement. The VPN or proxy runs on the router, while the phone connects to an ordinary Wi-Fi network. Android has no local `VpnService` or TUN artifacts. RKNHardering can therefore observe only the external network path, which must be made internally consistent.

Community-reported: the [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense) project provides router-oriented configurations and separately warns that a router-level TUN alone does not solve CDN pulling. Its ready-made materials include [Sub-Store](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md) and [S-UI](https://github.com/jinndi/RKNHardering-defense/blob/main/S-UI.md). Treat them as routing examples, not as proof that the current application version will pass.

In practice, verify three things: HTTP(S), DNS, and UDP must leave through the same expected path; IPv6 must either be configured the same way or intentionally disabled for the specific laboratory profile; and the phone must not retain a fallback mobile path that can unexpectedly become the underlying network.

### Option B: per-app split tunneling

Android officially supports allow and disallow lists through `VpnService.Builder.addAllowedApplication()` and `addDisallowedApplication()`. In sing-box for Android, this can be configured through **Settings → Profile Override → Per-app Proxy**. Route-rule documentation: [sing-box route rule](https://sing-box.sagernet.org/configuration/route/rule/).

The basic idea in current sing-box syntax looks like this:

```json
{
  "route": {
    "rules": [
      {
        "package_name": ["com.notcvnt.rknhardering"],
        "action": "route",
        "outbound": "direct"
      }
    ]
  }
}
```

This is not a complete ready-to-use configuration: the `direct` tag, DNS rules, and schema version must match your installation. Before replacing a working profile, validate the configuration with the client's built-in checker and keep a backup copy.

**Limitation:** the current `TUN_ACTIVE_PROBE` deliberately detects a state in which a TUN interface exists while `vpnActive` is false for RKNHardering. Per-app bypass can therefore remove the foreign IP while simultaneously confirming that the package was explicitly excluded. For a clean non-root result, it is generally paired with an external gateway rather than a local `VpnService`.

### DNS must follow the same path

Do not leave HTTP direct while DNS goes through the VPN, or the reverse. RKNHardering compares resolution behavior with network results. For an excluded application, use the underlying network's DNS or a separate resolver that exits through the same outbound. Do not set a system HTTP proxy merely to route DNS: that creates a separate `SYSTEM_PROXY` signal.

In sing-box configurations, the DNS rule should be separate from the traffic rule, but both should lead to the same intended path. A large community example is available in [SUB-STORE.md](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md); do not copy it wholesale without checking your own tags, rule sets, and trusted packages.

### STUN, calls, and UDP

A TCP-only proxy can look clean over HTTP while UDP and STUN leave directly. Choose the correction according to the intended behavior:

- when the application should use a direct path, HTTP, DNS, and UDP must all be direct;
- when one proxy or VPN egress is required, the client must genuinely support UDP instead of silently falling back;
- blocking STUN removes the response, but no response is not always equivalent to a clean result: RKNHardering can report `unsupported`, `no signal`, or a review state;
- blocking call endpoints can break Telegram or WhatsApp. Do this only in a test profile with a clear rollback procedure.

### Geolocation and roaming

Do not treat GPS spoofing as the primary strategy. The check uses MCC/MNC, SIM, cellular and Wi-Fi context, and server-side data; inconsistent spoofing creates more contradictions. A sound configuration should explain the observed location–egress pair. Home-routed roaming can be legitimate, and the code retains a distinct `HOME_ROUTED_ROAMING` context.

## With root

Root does not replace the steps above. It can hide the local fact that a VPN exists only after the network path has already been made consistent.

A practical sequence is:

1. Configure package routing in the VPN client or on the gateway.
2. Make HTTP, DNS, and UDP use the same intended egress.
3. Close Binder and native indicators with VPNHide or VPNHide Next.
4. Deny the target UID access to localhost control APIs.
5. Confirm that the root or hook footprint has not become a new reason for review.

When RKNHardering is meant to go direct, kernel or framework hiding is needed precisely because the local TUN still exists. When RKNHardering is meant to remain inside the tunnel, account for an architectural limitation of upstream VPNHide: replacing the active VPN network with the physical network is most coherent under split tunneling. The project explicitly identifies server-side signals as outside the scope of local hiding. See [VPNHide detection vectors](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).

For localhost, the best option is not to expose an API at all. When another application needs it, VPNHide `portshide` or a VPNHide Next kernel-level block should apply to the RKNHardering UID. A password on the Clash API is useful for security, but it does not conceal the open port or the protocol itself; RKNHardering scans loopback and known REST endpoints.

## Control-plane configuration

Mihomo/Clash `external-controller` and sing-box/Xray APIs should not listen on `0.0.0.0` without a specific need. For a laboratory phone, safer choices are:

- disable the controller or API;
- bind it to a Unix socket when both the client and panel support that;
- keep it on loopback with a strong secret and additionally block the target UID at the root level;
- do not treat moving away from common ports such as `9090`, `9091`, `9097`, or `19090` as the only protection: changing the port does not prevent a full scan.

Official Mihomo documentation: [general configuration](https://wiki.metacubex.one/en/config/general/). Official sing-box documentation: [configuration](https://sing-box.sagernet.org/configuration/).

## Verifying the result

First capture a network baseline without root-only commands:

```bash
adb shell dumpsys connectivity
adb shell ip addr
adb shell ip route
adb shell ip rule
adb shell settings get global http_proxy
adb shell pm list users
```

On Android, SELinux may restrict parts of `/proc`; `permission denied` means insufficient privileges, not that a route or socket is absent. Do not switch SELinux to permissive merely for diagnostics: that weakens security and creates a direct `ROOT_SELINUX` signal.

After a change, restart the application:

```bash
adb shell am force-stop com.notcvnt.rknhardering
adb shell monkey -p com.notcvnt.rknhardering 1
```

Run at least two checks on the same network. Then repeat separately after switching between Wi-Fi and mobile data: a change in the network epoch should explain changed results rather than being mistaken for a “random success.”

## Residual signals

Even with the correct public IP, hosting or proxy databases, a datacenter ASN, RTT, CDN behavior, and a server fingerprint may remain. Even behind an external router, RKNHardering can legitimately observe a foreign exit. Conversely, local hiding does not fix split DNS or an IPv6 leak.

[Back to the contents](../)
