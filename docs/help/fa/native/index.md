---
title: مرجع بررسی‌های بومی RKNHardering
permalink: /help/fa/native/
---

# مرجع بررسی‌های بومی RKNHardering

این مرجع **هر ۸۵ ورودی `NativeSignalId` در نسخهٔ 2.10.0** را توضیح می‌دهد. این مجموعه توصیه‌های کلی نیست: هر صفحه به یک شرط مشخص در Kotlin یا C++ متصل است، نقش خط را در حکم نهایی شرح می‌دهد و اقدام‌های ممکن **بدون روت** را از اقدام‌هایی که **به روت نیاز دارند** جدا می‌کند.

در صفحهٔ هر سیگنال، API، syscall، درخواست netlink، فایل، ویژگی سیستمی یا heuristic دقیق؛ محدودیت‌ها؛ فرمان‌های راستی‌آزمایی؛ خطرها و روش بازگردانی ذکر شده‌اند. شناسه‌های تاریخی که در pipeline فعلی تولیدکننده ندارند صریحاً علامت‌گذاری شده‌اند. ردیف `gso_ok` نیز مشخص شده است: C++ آن را بدون مقدار detail تولید می‌کند و parser رابط کاربری نسخهٔ 2.10.0 ردیف را حذف می‌کند.

ماتریس عملی همهٔ بررسی‌های محلی و سمت سرور در [راهنمای کامل anti-detection](../anti-detection/matrix/) آمده است. ابتدا [مدل تهدید](../anti-detection/threat-model/) و [روش آزمایشگاهی](../anti-detection/lab/) را بخوانید؛ وگرنه ممکن است با حذف یک ردیف، سه سیگنال تازه ایجاد شود.

## تفسیر نقش هر سیگنال

- **بالا** — ردیف معمولاً `detected=true` را تنظیم می‌کند.
- **متوسط** — ردیف `needsReview=true` را تنظیم می‌کند؛ نیازمند بررسی است، اما به‌تنهایی حکم نهایی نیست.
- **پایین** — دادهٔ telemetry یا خط پایه بدون آستانهٔ تشخیص.
- **ترکیبی** — یک شناسه برای چند شاخه با اثرهای متفاوت استفاده می‌شود.
- **رجیستری/سازگاری** — شناسه وجود دارد، اما نسخهٔ 2.10.0 تولیدکنندهٔ فعال اختصاصی ندارد یا در parser شکاف وجود دارد.

فرمان‌های ADB این صفحه‌ها فقط ابزار تشخیصی‌اند. `adb shell` با UID و دامنهٔ SELinux متفاوتی اجرا می‌شود؛ بنابراین خروجی آن جای اجرای دوبارهٔ بررسی درون RKNHardering را نمی‌گیرد. آزمایش‌های روت یا سطح هسته را ابتدا روی دستگاه آزمایشی انجام دهید و یک نسخه از boot image و روشی شناخته‌شده برای غیرفعال‌کردن ماژول از recovery داشته باشید.

## رابط‌ها

| صفحه | شناسه | نقش | وضعیت | موضوع مقاله |
|---|---|---|---|---|
| [interface-enumeration](./interface-enumeration/) | `INTERFACE_ENUMERATION` | ترکیبی | بررسی فعال | فهرست‌برداری اصلی رابط‌های شبکه |
| [tuntap-type](./tuntap-type/) | `TUNTAP_TYPE` | بالا | بررسی فعال | نوع رابط ARPHRD_TUNNEL/TUN-TAP مستقل از نام |
| [ipsec-interface](./ipsec-interface/) | `IPSEC_INTERFACE` | پایین | بررسی فعال | رابط‌های IPsec/XFRM |
| [jvm-native-mismatch](./jvm-native-mismatch/) | `JVM_NATIVE_MISMATCH` | ترکیبی | بررسی فعال | ناسازگاری میان Java `NetworkInterface` و `getifaddrs` بومی |
| [inet6-vpn-interface](./inet6-vpn-interface/) | `INET6_VPN_INTERFACE` | بالا | بررسی فعال | بررسی قدیمی ioctl برای رابط‌های ثابت VPN |
| [arp-vpn-interface](./arp-vpn-interface/) | `ARP_VPN_INTERFACE` | رجیستری/سازگاری | شناسه برای سازگاری حفظ شده است؛ در 2.10.0 تولیدکنندهٔ جداگانه‌ای ندارد | شناسهٔ قدیمی و رزروشدهٔ ARP برای رابط VPN |
| [hidden-mac-neighbors](./hidden-mac-neighbors/) | `HIDDEN_MAC_NEIGHBORS` | بالا | بررسی فعال | ورودی‌های ARP با نشانی MAC صفر یا broadcast |
| [sysfs-vpn-leak](./sysfs-vpn-leak/) | `SYSFS_VPN_LEAK` | بالا | بررسی فعال | دسترسی به رابط VPN از طریق sysfs و proc/sys |
| [getifaddrs-vpn](./getifaddrs-vpn/) | `GETIFADDRS_VPN` | بالا | بررسی فعال | نام‌های ثابت شبیه VPN در `getifaddrs()` |
| [sysclassnet-vpn](./sysclassnet-vpn/) | `SYSCLASSNET_VPN` | بالا | بررسی فعال | رابط‌های ثابت VPN در /sys/class/net |
| [rtm-getlink-vpn](./rtm-getlink-vpn/) | `RTM_GETLINK_VPN` | بالا | بررسی فعال | رابط VPN در Netlink RTM_GETLINK |
| [proc-if-inet6-vpn](./proc-if-inet6-vpn/) | `PROC_IF_INET6_VPN` | بالا | بررسی فعال | رابط VPN در /proc/net/if_inet6 |
| [proc-net-dev-vpn](./proc-net-dev-vpn/) | `PROC_NET_DEV_VPN` | بالا | بررسی فعال | شمارنده‌های رابط VPN در /proc/net/dev |
| [ifindexname-vpn](./ifindexname-vpn/) | `IFINDEXNAME_VPN` | بالا | بررسی فعال | نام شبیه VPN بازگردانده‌شده از `if_indextoname()` |

## مسیرها و پشتهٔ شبکه

| صفحه | شناسه | نقش | وضعیت | موضوع مقاله |
|---|---|---|---|---|
| [route-table](./route-table/) | `ROUTE_TABLE` | ترکیبی | بررسی فعال | جدول اصلی مسیریابی و مسیر پیش‌فرض |
| [host-route](./host-route/) | `HOST_ROUTE` | متوسط | بررسی فعال | مسیر میزبان عمومی /32 یا /128 از رابط فیزیکی |
| [route-vpn-interface](./route-vpn-interface/) | `ROUTE_VPN_INTERFACE` | بالا | بررسی فعال | مسیرهای قدیمی از طریق نام‌های ثابت رابط VPN |
| [sysctl-forwarding](./sysctl-forwarding/) | `SYSCTL_FORWARDING` | متوسط | بررسی فعال | فعال‌بودن هدایت IPv4 |
| [sysctl-rp-filter](./sysctl-rp-filter/) | `SYSCTL_RP_FILTER` | متوسط | بررسی فعال | غیرفعال‌بودن سراسری فیلتر مسیر معکوس |
| [vpn-policy-rules](./vpn-policy-rules/) | `VPN_POLICY_RULES` | بالا | بررسی فعال | مسیرهای قدیمی و غیراستاندارد IPv4 روی رابط VPN |
| [vpn-qdisc](./vpn-qdisc/) | `VPN_QDISC` | متوسط | بررسی فعال | شمارنده‌های قدیمی ترافیک tun0/wg0 زیر نام qdisc |
| [tcp-mss-low](./tcp-mss-low/) | `TCP_MSS_LOW` | بالا | بررسی فعال | MSS پایین TCP در یک اتصال محلی |
| [bpf-map-accessible](./bpf-map-accessible/) | `BPF_MAP_ACCESSIBLE` | بالا | بررسی فعال | دسترسی به نگاشت BPF شاخص رابط در netd |
| [proc-ipv6-route-vpn](./proc-ipv6-route-vpn/) | `PROC_IPV6_ROUTE_VPN` | بالا | بررسی فعال | رابط VPN در /proc/net/ipv6_route |
| [vpn-policy-rules-netlink](./vpn-policy-rules-netlink/) | `VPN_POLICY_RULES_NETLINK` | بالا | بررسی فعال | قواعد مشکوک policy از طریق RTM_GETRULE |
| [fib-trie-denied](./fib-trie-denied/) | `FIB_TRIE_DENIED` | متوسط | بررسی فعال | رد یا ناموفق‌شدن دسترسی به `/proc/net/fib_trie` |
| [deep-vpn-qdisc](./deep-vpn-qdisc/) | `DEEP_VPN_QDISC` | رجیستری/سازگاری | شناسه برای سازگاری حفظ شده است؛ در 2.10.0 تولیدکنندهٔ جداگانه‌ای ندارد | شناسهٔ رزروشدهٔ عمیق qdisc |
| [deep-bpf-map-accessible](./deep-bpf-map-accessible/) | `DEEP_BPF_MAP_ACCESSIBLE` | رجیستری/سازگاری | شناسه برای سازگاری حفظ شده است؛ در 2.10.0 تولیدکنندهٔ جداگانه‌ای ندارد | شناسهٔ عمیق رزروشده برای دسترسی به نگاشت BPF |
| [route-count](./route-count/) | `ROUTE_COUNT` | پایین | بررسی فعال | شمار اطلاعاتی مسیرها و رابط‌ها |
| [trim-oracle](./trim-oracle/) | `TRIM_ORACLE` | متوسط | بررسی فعال | ناسازگاری شمار رابط‌ها میان if_indextoname و RTM_GETLINK |
| [pmtu-mss-combined](./pmtu-mss-combined/) | `PMTU_MSS_COMBINED` | پایین | بررسی فعال | MSS از TCP_INFO روی اتصال محلی 127.0.0.1:443 |
| [udp-pmtu-ok](./udp-pmtu-ok/) | `UDP_PMTU_OK` | پایین | بررسی فعال | ارسال موفق 1500 بایت UDP به 127.0.0.1:53 |
| [udp-pmtu-fail](./udp-pmtu-fail/) | `UDP_PMTU_FAIL` | متوسط | بررسی فعال | شکست ارسال دیتاگرام 1500 بایتی UDP به loopback |
| [normal-pmtu](./normal-pmtu/) | `NORMAL_PMTU` | پایین | بررسی فعال | MTU نخستین رابط غیرتونلی |
| [timing-oracle](./timing-oracle/) | `TIMING_ORACLE` | پایین | بررسی فعال | زمان‌بندی socket/sendto روی ARM64 از طریق CNTVCT_EL0 |
| [backpressure](./backpressure/) | `BACKPRESSURE` | پایین | بررسی فعال | سیل UDP روی loopback: پنجاه‌هزار بستهٔ 1400 بایتی |
| [gso-failed](./gso-failed/) | `GSO_FAILED` | پایین | بررسی فعال | نپذیرفتن `UDP_SEGMENT` توسط `setsockopt()` |
| [gso-send-failed](./gso-send-failed/) | `GSO_SEND_FAILED` | پایین | بررسی فعال | پذیرفته‌شدن `UDP_SEGMENT` و شکست ارسال 4800 بایت |
| [gso-ok](./gso-ok/) | `GSO_OK` | رجیستری/سازگاری | تولیدکنندهٔ بومی وجود دارد، اما تجزیه‌گر فعلی رابط کاربری این ردیف را حذف می‌کند | پذیرفته‌شدن UDP GSO و موفقیت ارسال روی loopback |
| [hardware-timestamp](./hardware-timestamp/) | `HW_TIMESTAMP` | پایین | بررسی فعال | پیکربندی موفق `SIOCSHWTSTAMP` روی loopback |
| [traceroute-denied](./traceroute-denied/) | `TRACEROUTE_DENIED` | متوسط | بررسی فعال | بازگشت EACCES از ارسال UDP روی loopback با TTL=1 |

## آثار VPN و سوکت‌ها

| صفحه | شناسه | نقش | وضعیت | موضوع مقاله |
|---|---|---|---|---|
| [vpn-property](./vpn-property/) | `VPN_PROPERTY` | بالا | بررسی فعال | ویژگی‌های سیستمی قدیمی VPN/DNS |
| [dns-property](./dns-property/) | `DNS_PROPERTY` | رجیستری/سازگاری | شناسه برای سازگاری حفظ شده است؛ در 2.10.0 تولیدکنندهٔ جداگانه‌ای ندارد | شناسهٔ رزروشدهٔ `dns_prop` |
| [vpn-file](./vpn-file/) | `VPN_FILE` | رجیستری/سازگاری | شناسه برای سازگاری حفظ شده است؛ در 2.10.0 تولیدکنندهٔ جداگانه‌ای ندارد | شناسهٔ عمومی رزروشده برای فایل‌های VPN |
| [tcp-vpn-port](./tcp-vpn-port/) | `TCP_VPN_PORT` | رجیستری/سازگاری | شناسه برای سازگاری حفظ شده است؛ در 2.10.0 تولیدکنندهٔ جداگانه‌ای ندارد | شناسهٔ قدیمی رزروشده برای درگاه‌های TCP مربوط به VPN |
| [udp-vpn-port](./udp-vpn-port/) | `UDP_VPN_PORT` | رجیستری/سازگاری | شناسه برای سازگاری حفظ شده است؛ در 2.10.0 تولیدکنندهٔ جداگانه‌ای ندارد | شناسهٔ قدیمی رزروشده برای درگاه‌های UDP مربوط به VPN |
| [established-vpn-socket](./established-vpn-socket/) | `ESTABLISHED_VPN_SOCKET` | متوسط | بررسی فعال | اتصال برقرارشدهٔ TCP به درگاه معمول VPN |
| [so-bindtodevice](./so-bindtodevice/) | `SO_BINDTODEVICE` | متوسط | بررسی فعال | هویت قدیمی سوکت زیر نام تاریخی SO_BINDTODEVICE |
| [loopback-port-conflict](./loopback-port-conflict/) | `LOOPBACK_PORT_CONFLICT` | بالا | بررسی فعال | پورت‌های TCP اشغال‌شده روی 127.0.0.1 |
| [ip-recverr](./ip-recverr/) | `IP_RECVERR` | رجیستری/سازگاری | شناسه برای سازگاری حفظ شده است؛ در 2.10.0 تولیدکنندهٔ جداگانه‌ای ندارد | شناسهٔ مثبت رزروشدهٔ `IP_RECVERR` |
| [inet-diag-denied](./inet-diag-denied/) | `INET_DIAG_DENIED` | متوسط | بررسی فعال | دردسترس‌نبودن `NETLINK_SOCK_DIAG` برای برنامه |
| [bindtodevice-leak](./bindtodevice-leak/) | `BINDTODEVICE_LEAK` | بالا | بررسی فعال | تأیید وجود رابط VPN با SO_BINDTODEVICE |
| [getsockname-leak](./getsockname-leak/) | `GETSOCKNAME_LEAK` | بالا | بررسی فعال | دریافت فوری نشانی خصوصی IPv4 توسط سوکت UDP بدون bind |
| [udp-port-conflict-physical](./udp-port-conflict-physical/) | `UDP_PORT_CONFLICT_PHYSICAL` | بالا | بررسی فعال | پورت‌های UDP مرتبط با VPN و اشغال‌شده روی نشانی فیزیکی IPv4 |

## هوک‌های فرایند و یکپارچگی

| صفحه | شناسه | نقش | وضعیت | موضوع مقاله |
|---|---|---|---|---|
| [hook-markers](./hook-markers/) | `HOOK_MARKERS` | متوسط | بررسی فعال | نشانگرهای نام‌دار تزریق در `/proc/self/maps` |
| [rwx-memory-regions](./rwx-memory-regions/) | `RWX_MEMORY_REGIONS` | پایین | بررسی فعال | ناحیه‌های بزرگ حافظه با مجوز RWX |
| [library-integrity](./library-integrity/) | `LIBRARY_INTEGRITY` | متوسط | بررسی فعال | مبدأ نمادهای کلیدی libc |
| [vpnhide](./vpnhide/) | `VPNHIDE` | ترکیبی | بررسی فعال | آثار VPNHide و اوراکل‌های رگرسیون |
| [lsposed](./lsposed/) | `LSPOSED` | متوسط | بررسی فعال | آثار فایلی پشته‌ای شبیه LSPosed/Vector |
| [hook-property](./hook-property/) | `HOOK_PROPERTY` | بالا | بررسی فعال | propertyهای سیستمی هوک LSPosed/Magisk/Zygote |

## روت و وضعیت سامانه

| صفحه | شناسه | نقش | وضعیت | موضوع مقاله |
|---|---|---|---|---|
| [root-indicators](./root-indicators/) | `ROOT_INDICATORS` | ساختاری | بررسی فعال | خلاصهٔ نشانگرهای بومی روت |
| [root-su-binary](./root-su-binary/) | `ROOT_SU_BINARY` | متوسط | بررسی فعال | فایل su در مسیرهای شناخته‌شده |
| [root-property](./root-property/) | `ROOT_PROPERTY` | متوسط | بررسی فعال | propertyهای مشکوک روت/اشکال‌زدایی |
| [root-management](./root-management/) | `ROOT_MANAGEMENT` | متوسط | بررسی فعال | فایل‌ها و پوشه‌های مدیر روت |
| [root-system-rw](./root-system-rw/) | `ROOT_SYSTEM_RW` | متوسط | بررسی فعال | دسترسی نوشتن به /system |
| [root-suspicious-mount](./root-suspicious-mount/) | `ROOT_SUSPICIOUS_MOUNT` | متوسط | بررسی فعال | سطرهای mount حاوی Magisk/core-only و نشانگرهای روت |
| [root-overlay-mount](./root-overlay-mount/) | `ROOT_OVERLAY_MOUNT` | متوسط | بررسی فعال | mount از نوع overlay روی /system یا /vendor |
| [root-selinux](./root-selinux/) | `ROOT_SELINUX` | متوسط | بررسی فعال | حالت permissive در SELinux یا دردسترس‌نبودن فایل enforce |
| [root-uid](./root-uid/) | `ROOT_UID` | متوسط | بررسی فعال | برابر بودن UID/EUID/GID فرایند با صفر |
| [root-magisk-property](./root-magisk-property/) | `ROOT_MAGISK_PROPERTY` | متوسط | بررسی فعال | propertyهای سیستمی مخصوص Magisk |

## شبیه‌سازی، پروفایل‌ها و جداسازی

| صفحه | شناسه | نقش | وضعیت | موضوع مقاله |
|---|---|---|---|---|
| [emulator-indicators](./emulator-indicators/) | `EMULATOR_INDICATORS` | ساختاری | بررسی فعال | خلاصهٔ نشانگرهای شبیه‌ساز |
| [emulator-qemu-property](./emulator-qemu-property/) | `EMULATOR_QEMU_PROPERTY` | متوسط | بررسی فعال | propertyهای سیستمی QEMU |
| [emulator-qemu-pipe](./emulator-qemu-pipe/) | `EMULATOR_QEMU_PIPE` | متوسط | بررسی فعال | دستگاه‌ها و سوکت‌های QEMU/Genymotion |
| [emulator-goldfish](./emulator-goldfish/) | `EMULATOR_GOLDFISH` | متوسط | بررسی فعال | Goldfish/Ranchu در ویژگی‌های hardware و board |
| [emulator-qemu-driver](./emulator-qemu-driver/) | `EMULATOR_QEMU_DRIVER` | متوسط | بررسی فعال | Goldfish در `/proc/tty/drivers` |
| [emulator-bluestacks](./emulator-bluestacks/) | `EMULATOR_BLUESTACKS` | متوسط | بررسی فعال | فایل‌های BlueStacks |
| [emulator-build-profile](./emulator-build-profile/) | `EMULATOR_BUILD` | متوسط | بررسی فعال | هیوریستیک‌های Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT |
| [isolation-profile](./isolation-profile/) | `ISOLATION_PROFILE` | ساختاری | بررسی فعال | خلاصهٔ جداسازی کاربر/پروفایل Android |
| [isolation-clone](./isolation-clone/) | `ISOLATION_CLONE` | متوسط | بررسی فعال | userId مربوط به clone/dual-app در OEM |
| [isolation-secondary-user](./isolation-secondary-user/) | `ISOLATION_SECONDARY_USER` | متوسط | بررسی فعال | اجرا خارج از کاربر اصلی |
| [isolation-work-profile](./isolation-work-profile/) | `ISOLATION_WORK_PROFILE` | متوسط | بررسی فعال | RKNHardering مالک پروفایل است |

## سیگنال‌های سطح سرویس

| صفحه | شناسه | نقش | وضعیت | موضوع مقاله |
|---|---|---|---|---|
| [native-library](./native-library/) | `NATIVE_LIBRARY` | دسترس‌پذیری | بررسی فعال | بارگذاری کتابخانهٔ بررسی‌های بومی |
| [syscall-unavailable](./syscall-unavailable/) | `SYSCALL_UNAVAILABLE` | دسترس‌پذیری | بررسی فعال | پروب بومی syscall/سوکت در دسترس نیست |
| [general-diagnostics](./general-diagnostics/) | `GENERAL_DIAGNOSTICS` | ساختاری | بررسی فعال | آشکارساز عمیق بومی هیچ سطری برنگرداند |
| [unknown-signals](./unknown-signals/) | `UNKNOWN` | ساختاری | بررسی فعال | kind بومی ناشناخته یا نگاشت‌نشده |

## منابع رسمی دریافت اجزای روت

- [نسخه‌های VPNHide](https://github.com/okhsunrog/vpnhide/releases/latest) و [نقشهٔ پوشش آن](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- [نسخه‌های VPNHide Next](https://github.com/soranerai/vpnhide_next/releases/latest)، یک fork آزمایشی با هوک‌های تهاجمی‌تر هسته.
- [نسخه‌های Vector](https://github.com/JingMatrix/Vector/releases/latest) برای لایهٔ framework/Xposed.
- [نسخه‌های Magisk](https://github.com/topjohnwu/Magisk/releases/latest)، [نسخه‌های KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest) و [نسخه‌های APatch](https://github.com/bmax121/APatch/releases/latest).

فایل‌های APK و ZIP را فقط از مخزن رسمی یا صفحهٔ رسمی release بگیرید، امضا یا hash را بررسی کنید، اسکریپت نصب ناشناخته را با روت اجرا نکنید و چند backend بومی را که همان توابع هسته را intercept می‌کنند هم‌زمان نصب نکنید.

[بازگشت به نمایهٔ زبان](../)
