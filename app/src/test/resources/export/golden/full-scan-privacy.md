# RKNHardering Scan Report

```text
RKNHardering Scan Report
=======================
VERDICT      : [DETECTED]
EXPOSURE     : REMOTE_ENDPOINT_DISCOVERED
PRIVACY MODE : ON
TIMESTAMP    : 2023-11-14T22:13:20Z
```

## Verdict
- Status: [DETECTED]
- Explanation: The automated check considers the bypass confirmed. The local Xray API exposed a remote endpoint address.

### What this means
- A red verdict means the automated check collected enough signs of a bypass.
- An actual remote endpoint address was obtained, not just a public IP.

### What was discovered
- Exposure level: Remote endpoint discovered
- Local Xray API: 127.0.*.*:8080
- Remote endpoint: 198.51.*.*:443
- Local proxy: SOCKS5 127.0.*.*:1080
- Owner app: Example VPN (com.example.vpn, uid 10123)
- IP via VPN Network: 198.51.*.*
- IP outside VPN: 192.168.*.*
- Direct public IP: 198.51.*.*
- Public IP via proxy: 203.0.*.*
- IP from RU checkers: 198.51.*.*
- IP from non-RU checkers: 203.0.*.*

### Why this verdict was reached
- A local Xray API was found on the device.
- The direct IP and the IP via the local proxy differ.
- A local proxy was found, but the bypass was not automatically confirmed.
- RU and non-RU IP checkers returned different public IPs.
- GeoIP indicates an external or suspicious address.


## Section Summary
| Section | Status | Summary |
| --- | --- | --- |
| GeoIP | [DETECTED] | GeoIP says 203.0.*.* |
| IP comparison | [DETECTED] | Mismatch between 198.51.*.* and 203.0.*.* |
| CDN pulling | [DETECTED] | rutracker.org exposed 203.0.*.* |
| Direct signs | [DETECTED] | Installed app com.example.vpn at 198.51.*.* |
| Indirect signs | [DETECTED] | Indirect route mismatch 198.51.*.* |
| Native signs | [DETECTED] | Native getifaddrs() reports tun0 |
| ICMP spoofing β | [REVIEW] | instagram.com replied and google.com was too fast |
| RTT triangulation β | [REVIEW] | RTT target mix needs review |
| Location signals | [OK] | <none> |
| Split tunnel bypass | [DETECTED] | Bypass via 198.51.*.* |

## GeoIP
- Status: [DETECTED]
- Name: GeoIP
- Findings count: 1
- Evidence count: 1
- Matched apps: 0
- Active apps: 0
- Call transport signals: 0
- STUN probe groups: 0
- Geo facts: present

### Findings
- GeoIP says 203.0.*.* | informational=true | source=GEO_IP

### Evidence
- source=GEO_IP | detected=true | confidence=HIGH | description=Hosting signal for 203.0.*.*

### Matched apps
- <none>

### Active apps
- <none>

### Call transport
- <none>

### Geo facts
- ip=203.0.*.* | countryCode=FI | asn=AS64502 Example VPN | outsideRu=true | hosting=true | proxyDb=true | fetchError=false

## IP comparison
- Status: [DETECTED]
- Summary: Mismatch between 198.51.*.* and 203.0.*.*

### RU
- Status: [DETECTED]
- Title: RU
- Status label: mismatch
- Summary: RU checker returned 198.51.*.*
- Canonical IP: 198.51.*.*
- Ignored IPv6 errors: 1
- Responses:
  - label=ru-main | scope=RU | url=https://ru.example/check | ip=198.51.*.* | error=<none> | ipv4Records=<none> | ipv6Records=<none> | ignoredIpv6Error=false

### NON_RU
- Status: [DETECTED]
- Title: NON_RU
- Status label: ok
- Summary: NON_RU checker returned 203.0.*.*
- Canonical IP: 203.0.*.*
- Ignored IPv6 errors: 0
- Responses:
  - label=non-ru-main | scope=NON_RU | url=https://non-ru.example/check | ip=203.0.*.* | error=<none> | ipv4Records=<none> | ipv6Records=<none> | ignoredIpv6Error=false

## CDN pulling
- Status: [DETECTED]
- Summary: rutracker.org exposed 203.0.*.*

### Findings
- CDN trace matched 203.0.*.* | detected=true | source=SPLIT_TUNNEL_BYPASS

### Responses
#### Response 1: rutracker.org
- URL: https://rutracker.org/cdn-cgi/trace
- IP: 203.0.*.*
- IPv4: 203.0.*.*
- IPv6: 2001:db8:0:0:*:*:*:*
- IPv4 unavailable: false
- IPv4 error: IPv4 retry saw 198.51.*.*
- IPv6 error: IPv6 timeout 2001:db8:0:0:*:*:*:*
- Error: <none>
- Important fields:
  - ip: 203.0.*.*
  - loc: FI
- Raw body:
```text
ip=203.0.*.*
loc=FI
```

## Direct signs
- Status: [DETECTED]
- Name: Direct
- Findings count: 1
- Evidence count: 1
- Matched apps: 1
- Active apps: 1
- Call transport signals: 0
- STUN probe groups: 0
- Geo facts: <none>

### Findings
- Installed app com.example.vpn at 198.51.*.* | detected=true | source=INSTALLED_APP | confidence=HIGH | family=v2ray | package=com.example.vpn

### Evidence
- source=ACTIVE_VPN | detected=true | confidence=HIGH | kind=TARGETED_BYPASS | family=v2ray | package=com.example.vpn | description=VPN service active

### Matched apps
- Example VPN | package=com.example.vpn | family=v2ray | kind=TARGETED_BYPASS | source=INSTALLED_APP | active=true | confidence=HIGH | version=1.2.3 | appType=V2RayNG | coreType=Xray/V2Ray | corePath=lib/arm64-v8a/libxray.so | goVersion=go1.24.1 | services=ExampleService

### Active apps
- package=com.example.vpn | service=ExampleService | family=v2ray | kind=TARGETED_BYPASS | source=ACTIVE_VPN | confidence=HIGH | version=1.2.3 | appType=V2RayNG | coreType=Xray/V2Ray | corePath=lib/arm64-v8a/libxray.so | goVersion=go1.24.1 | services=ExampleService

### Call transport
- <none>

## Indirect signs
- Status: [DETECTED]
- Name: Indirect
- Findings count: 1
- Evidence count: 0
- Matched apps: 0
- Active apps: 0
- Call transport signals: 1
- STUN probe groups: 1
- Geo facts: <none>

### Findings
- Indirect route mismatch 198.51.*.* | detected=true | source=ROUTING

### Evidence
- <none>

### Matched apps
- <none>

### Active apps
- <none>

### Call transport
- service=TELEGRAM | probeKind=DIRECT_UDP_STUN | path=UNDERLYING | status=ERROR | target=198.51.*.* | targetPort=3478 | resolvedIps=198.51.*.* | mappedIp=198.51.*.* | observedPublicIp=203.0.*.* | confidence=MEDIUM | experimental=true | summary=STUN error from 198.51.*.*

### STUN probe groups
- scope=GLOBAL | responded=1/2
  - target=stun.example.org:3478 | scope=GLOBAL | hasResponse=true | mappedIpv4=203.0.*.* | mappedIpv6=2001:db8:0:0:*:*:*:*
  - target=198.51.*.*:3478 | scope=GLOBAL | hasResponse=false | error=timeout from 198.51.*.*

## Native signs
- Status: [DETECTED]
- Name: Native signs
- Findings count: 1
- Evidence count: 1
- Matched apps: 0
- Active apps: 0
- Call transport signals: 0
- STUN probe groups: 0
- Geo facts: <none>

### Findings
- Native getifaddrs() reports tun0 | detected=true | source=NATIVE_INTERFACE | confidence=HIGH

### Evidence
- source=NATIVE_INTERFACE | detected=true | confidence=HIGH | description=native interface tun0 is visible

### Matched apps
- <none>

### Active apps
- <none>

### Call transport
- <none>

## ICMP spoofing β
- Status: [REVIEW]
- Name: ICMP spoofing
- Findings count: 2
- Evidence count: 1
- Matched apps: 0
- Active apps: 0
- Call transport signals: 0
- STUN probe groups: 0
- Geo facts: <none>

### Findings
- instagram.com replied and google.com was too fast | needsReview=true | source=ICMP_SPOOFING
- Blocked target instagram.com (157.240.*.*): 3/3 replies | informational=true

### Evidence
- source=ICMP_SPOOFING | detected=true | confidence=MEDIUM | description=ICMP route behavior looked inconsistent

### Matched apps
- <none>

### Active apps
- <none>

### Call transport
- <none>

## RTT triangulation β
- Status: [REVIEW]
- Name: RTT triangulation
- Findings count: 1
- Evidence count: 0
- Matched apps: 0
- Active apps: 0
- Call transport signals: 0
- STUN probe groups: 0
- Geo facts: <none>

### Findings
- RTT target mix needs review | needsReview=true | source=RTT_TRIANGULATION

### Evidence
- <none>

### Matched apps
- <none>

### Active apps
- <none>

### Call transport
- <none>

## Location signals
- Status: [OK]
- Name: Location
- Findings count: 0
- Evidence count: 0
- Matched apps: 0
- Active apps: 0
- Call transport signals: 0
- STUN probe groups: 0
- Geo facts: <none>

### Findings
- <none>

### Evidence
- <none>

### Matched apps
- <none>

### Active apps
- <none>

### Call transport
- <none>

## IP каналы
| Канал | Target | IP | Family | Страна | ASN | Источники |
| --- | --- | --- | --- | --- | --- | --- |
| DIRECT | RU | 198.51.*.* | V4 | RU | AS64501 Example Direct | geoip, ipcomp:ru:ru-main |
| VPN | NON_RU | 203.0.*.* | V4 | FI | AS64502 Example VPN | underlying-prober.non-ru.vpn, bypass.vpn |

Флаги: crossChannelMismatch=true, dualStackObserved=true, probeTargetDivergence=true, probeTargetDirectDivergence=true, geoCountryMismatch=true, sameAsnAcrossChannels=true, channelConflict=DIRECT, VPN, foreignIps=203.0.*.*, needsReview=true

Channel IPs:
- DIRECT: 198.51.*.*
- VPN: 203.0.*.*

Unparsed IP inputs:
- source=fixture.raw | raw=bad field 203.0.*.*

## TUN probe diagnostics
- Enabled: true
- Mode override: CURL_COMPATIBLE
- Active network is VPN: true
- VPN network present: true
- Underlying network present: true
### VPN path
- Interface: tun0
- Selected mode: CURL_COMPATIBLE
- Selected IP: 203.0.*.*
- Selected error: <none>
- DNS path mismatch: true
- Strict: mode=STRICT_SAME_PATH | status=FAILED | ip=<none> | error=timeout from 198.51.*.* | endpointAttempts=endpoint=https://198.51.*.*/ip family=ipv4 status=FAILED ip=<none> error=timeout from 198.51.*.* | transport=engine=native-libcurl resolveStrategy=native-default curlCode=0 httpCode=200 nativeLibraryLoaded=true caBundleVersion=test-ca resolvedAddressesUsed=203.0.*.*
- Curl compatible: mode=CURL_COMPATIBLE | status=SUCCEEDED | ip=203.0.*.* | error=<none> | endpointAttempts=endpoint=https://203.0.*.*/ip family=ipv4 status=SUCCEEDED ip=203.0.*.* error=<none> | transport=engine=native-libcurl resolveStrategy=native-default curlCode=0 httpCode=200 nativeLibraryLoaded=true caBundleVersion=test-ca resolvedAddressesUsed=203.0.*.*
### Underlying path
- <none>

## Split tunnel bypass
- Status: [DETECTED]
- Local proxy: 127.0.0.1:1080 | type=SOCKS5 | authRequired=true
- Owner app: Example VPN (com.example.vpn, uid 10123)
- Direct IP: 198.51.*.*
- Proxy IP: 203.0.*.*
- VPN network IP: 198.51.*.*
- Underlying IP: 192.168.1.55
- Xray API: 127.0.0.1:8080 | handlerAvailable=true | stats=statCount=2 sampleNames=outbound>>>proxy>>>traffic>>>uplink

### Findings
- Bypass via 198.51.*.* | detected=true | source=SPLIT_TUNNEL_BYPASS | confidence=HIGH

### Evidence
- source=XRAY_API | detected=true | confidence=HIGH | description=Xray exposed 198.51.*.*

### Proxy checks
- endpoint=127.0.0.1:1080 | type=SOCKS5 | authRequired=true | ownerStatus=RESOLVED | proxyIp=203.0.*.* | status=CONFIRMED_BYPASS | mtProtoReachable=true | mtProtoTarget=149.154.*.*:443 | summaryReason=CONFIRMED_BYPASS

### Xray outbounds
- tag=proxy | protocol=vless | address=198.51.*.* | port=443 | sni=example.org | senderSettingsType=tcp | proxySettingsType=none | uuidPresent=true | publicKeyPresent=true

## Footer
- Timestamp: 2023-11-14T22:13:20Z
- App version: 0.0-golden
- Build type: golden
- Privacy mode: ON