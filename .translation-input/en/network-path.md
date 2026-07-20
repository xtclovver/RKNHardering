---
title: Network path — GeoIP, DNS, CDN, STUN, and calls
permalink: /help/en/anti-detection/network-path/
---

# Network path — GeoIP, DNS, CDN, STUN, and calls

This section still matters with a perfect VPNHide setup. Kernel and framework hooks change local Android responses, but remote servers continue to see the real address, ASN, latency, and transport availability.

## What RKNHardering checks

Verified by the project: the network layer includes `GEO_IP`, IP consensus between RU and non-RU services, DNS comparison, `CdnPullingChecker`, STUN and Telegram/WhatsApp call transports, underlying-network probes, RTT triangulation, ICMP spoofing, and domain reachability. Some results are diagnostic, but disagreement between independent channels can contribute to the final `DETECTED` result.

Key indicators:

- a foreign country, hosting/datacenter, or proxy/VPN classification in GeoIP;
- different canonical IPs for RU and non-RU groups;
- different IPv4 and IPv6 paths;
- DNS resolves addresses differently over the VPN and underlying network;
- a CDN/redirector observes another channel;
- STUN exposes a separate UDP egress;
- the application is physically in Russia while network egress appears foreign, or the reverse;
- a connection bound to the underlying network produces another address;
- a local proxy returns a different external IP from the direct path.

## Without root

### Option A: external router or separate gateway

This is the cleanest non-root scenario. The VPN/proxy runs on the router while the phone connects to an ordinary Wi-Fi network. Android then has no local `VpnService`/TUN artifacts. RKNHardering sees only the external network path, so that path must be internally consistent.

Reported by the community: [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense) provides router scenarios and separately warns that a router TUN alone does not solve CDN pulling. Its ready-made materials include [Sub-Store](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md) and [S-UI](https://github.com/jinndi/RKNHardering-defense/blob/main/S-UI.md). Treat them as routing examples, not proof that the current application version will pass.

In practice, verify three things: HTTP(S), DNS, and UDP must use the same expected channel; IPv6 must either follow the same policy or be deliberately disabled in a specific laboratory profile; and the phone must not have a fallback mobile path that unexpectedly becomes the underlying network.

### Option B: per-app split tunneling

Android officially supports allow/disallow lists through `VpnService.Builder.addAllowedApplication()` and `addDisallowedApplication()`. In sing-box for Android, this can be configured through **Settings → Profile override → Per-app proxy**. Rule documentation: [sing-box route rule](https://sing-box.sagernet.org/configuration/route/rule/).

A minimal illustration using current sing-box syntax looks like this:

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

This is not a complete ready-to-use configuration: the `direct` tag, DNS rules, and schema version must match your installation. Before replacing a working profile, validate the configuration with the client's built-in checker and keep a copy.

**Limitation:** the current `TUN_ACTIVE_PROBE` deliberately notices when a TUN exists while `vpnActive` is false for RKNHardering. Per-app bypass can therefore remove the foreign IP while simultaneously confirming that the package was explicitly excluded. For a clean non-root result, it is usually paired with an external gateway rather than a local `VpnService`.

### DNS must follow the same path

Do not leave a design such as “HTTP direct, DNS over VPN”, or the reverse. RKNHardering compares the resolver path with network results. For an excluded application, use the underlying network's DNS or a separate resolver that uses the same outbound. Do not set a system HTTP proxy merely to route DNS: it creates a separate `SYSTEM_PROXY` signal.

In sing-box configurations, the DNS rule should be separate from the traffic rule, but both must lead to the same expected channel. A large community example is available in [SUB-STORE.md](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md); do not copy it wholesale without checking your own tags, rule sets, and trusted packages.

### STUN, calls, and UDP

A TCP-only proxy often looks clean over HTTP while UDP/STUN goes direct. Choose the correction according to the intended design:

- when the application needs a direct path, HTTP, DNS, and UDP should all be direct;
- when one proxy/VPN egress is required, the client must genuinely support UDP rather than silently falling back;
- blocking STUN removes the response, but no response is not always equivalent to a clean result: RKNHardering can report `unsupported`, `no signal`, and review;
- blocking call endpoints can break Telegram/WhatsApp. Do this only in a test profile with a clear rollback.

### Geolocation and roaming

Do not use GPS spoofing as the primary strategy. The check uses MCC/MNC, SIM, cell/Wi-Fi, and server-side data; inconsistent spoofing creates more contradictions. A normal configuration should explain the observed “location — egress” pair. Home-routed roaming can be legitimate, and the code maintains a separate `HOME_ROUTED_ROAMING` context.

## With root

Root does not replace the steps above. It can hide the local fact of a VPN only after the network path has already been made consistent.

Recommended sequence:

1. Configure package routing in the VPN client or gateway.
2. Obtain the same expected HTTP/DNS/UDP egress.
3. Cover Binder/native indicators with VPNHide or VPNHide Next.
4. Deny the target UID access to the localhost control API.
5. Verify that the root/hook footprint did not become a new reason for review.

When RKNHardering must go direct, kernel/framework hiding is needed precisely because the local TUN still exists. When it must travel inside the tunnel, account for an architectural limitation documented by upstream VPNHide: replacing the active VPN network with a physical network is most coherent in a split-tunnel scenario. The project explicitly describes server-side signals as outside the scope of local hiding. Details: [VPNHide detection vectors](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).

For localhost, the best option is not to start an API at all. If other applications need it, VPNHide `portshide` or VPNHide Next kernel blocking should target the RKNHardering UID. A password on the Clash API is useful for security, but it does not hide the open port or protocol fingerprint; RKNHardering scans loopback and known REST endpoints.

## Control-plane configuration

Mihomo/Clash `external-controller` and sing-box/Xray APIs should not listen on `0.0.0.0` unless necessary. On a laboratory phone, safer options are:

- disable the controller/API;
- bind it to a Unix socket when the client and panel support that;
- keep it on loopback with a strong secret and additionally block the target UID at root level;
- do not rely on changing common ports such as `9090`, `9091`, `9097`, and `19090` as the only “protection”: a full scan is not defeated by moving a port.

Official Mihomo documentation: [general configuration](https://wiki.metacubex.one/en/config/general/). Official sing-box documentation: [configuration](https://sing-box.sagernet.org/configuration/).

## Verify the result

First capture a network baseline without root commands:

```bash
adb shell dumpsys connectivity
adb shell ip addr
adb shell ip route
adb shell ip rule
adb shell settings get global http_proxy
adb shell pm list users
```

On Android, SELinux may block parts of `/proc`; `permission denied` means insufficient privileges, not the absence of a route or socket. Do not switch SELinux to permissive for diagnostics: that weakens security and creates a direct `ROOT_SELINUX` signal.

After a change:

```bash
adb shell am force-stop com.notcvnt.rknhardering
adb shell monkey -p com.notcvnt.rknhardering 1
```

Run at least two checks on the same network. Then repeat separately after switching between Wi-Fi and mobile data: a changed network epoch should explain changed results rather than being mistaken for a “random success”.

## Residual signals

Even with the correct external IP, hosting/proxy databases, datacenter ASN, RTT, CDN, and server fingerprints may remain. Even behind an external router, RKNHardering may correctly observe a foreign exit. Conversely, local hiding cannot repair split DNS or an IPv6 leak.

[Back to the table of contents](../)
