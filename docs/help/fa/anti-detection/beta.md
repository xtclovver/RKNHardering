---
title: بررسی‌های Beta — شرط‌ها، Quorum و راهکارهای مقابله
permalink: /help/fa/anti-detection/beta/
---

# بررسی‌های Beta — شرط‌ها، Quorum و راهکارهای مقابله

حالت Beta در RKNHardering باید صریحاً فعال شود. این حالت هر رد دسترسی یا ردیف غیرعادی را به `DETECTED` تبدیل نمی‌کند: `PERMISSION_DENIED`، `UNSUPPORTED`، raceها، نتایج malformed یا کوتاه‌شده و تغییر epoch شبکه سرکوب یا کم‌اهمیت می‌شوند. مشاهدهٔ مثبت باید با منبع، domain و گروه استقلال ثبت‌شده مطابقت داشته باشد.

فقط دو بررسی می‌توانند به سیگنال سخت مستقل تبدیل شوند: **`beta.vpn_binder`** با مرجعیت `BINDER_SERVICE` و **`beta.tun_fd`** با مرجعیت `KERNEL_QUERY`. هر دو به دست‌کم دو نمونهٔ موفق، طبقه‌بندی یکسان و epoch پایدار نیاز دارند. سایر بررسی‌های beta یافتهٔ بازبینی می‌سازند یا در quorum گروه‌های مستقل شرکت می‌کنند.

## بدون روت

راهبردهای اصلی همان‌اند: دروازهٔ خارجی VPN محلی را حذف می‌کند؛ کاربر مالک زمینهٔ پروفایل را حذف می‌کند؛ غیرفعال‌کردن proxy یا صفحهٔ کنترل socketهای محلی را می‌بندد؛ و APK اصلی خارج از کانتینر مجازی ناسازگاری‌های sandbox و هوک را حذف می‌کند. برای «اصلاح» permission denial، Shizuku یا روت ندهید. این کار دسترسی پروب را گسترش می‌دهد و ممکن است سیگنال‌های واقعی بیشتری آشکار کند.

## با روت

لایهٔ beta در تشخیص هوک‌های ناقص بسیار مؤثر است. framework باید Binder را سازگار پالایش کند، backend هسته باید مسیرهای netlink خام، socket و TUN-FD را پوشش دهد و فرایند هدف نباید تزریق Xposed یا Zygisk دریافت کند. پروب‌های سراسری روت یا Shizuku فقط وقتی صریحاً انتخاب شوند اجرا می‌شوند. در اعتبارسنجی کنترل‌شدهٔ حفاظت خودتان مفیدند، اما برنامه نباید privilege غیرضروری را دائماً نگه دارد.

## جدول کامل شناسه‌های Beta

| شناسهٔ Beta | مشاهده | Domain / گروه مستقل | بدون روت | با روت | آنچه باقی می‌ماند |
|---|---|---|---|---|---|
| `beta.vpn_binder` | درخواست Binder به سرویس یا وضعیت VPN در Android. **پس از تکرار پایدار، مرجعیت سخت دارد.** | `VPN_OR_PROXY` / `android_vpn_service` | از دروازهٔ خارجی استفاده کنید. | در `system_server` پالایش کنید؛ target را خارج از دامنهٔ Xposed نگه دارید. | مدل‌های Binder و بومی باید با هم سازگار باشند. |
| `beta.user_profile` | کاربر/پروفایل فعلی از طریق APIهای کاربر Android. | `ISOLATED_PROFILE` / `android_user_manager` | از کاربر مالک استفاده کنید. | فقط UID درست را هدف بگیرید؛ `UserManager` را خراب نکنید. | سیگنال واقعی پروفایل باقی می‌ماند. |
| `beta.foreground_user` | کاربر foreground و سازگاری آن با زمینهٔ فرایند. | `ISOLATED_PROFILE` / `android_user_manager` | از کاربر مالک استفاده کنید. | فقط UID درست را هدف بگیرید؛ `UserManager` را خراب نکنید. | سیگنال واقعی پروفایل باقی می‌ماند. |
| `beta.connectivity_binder` | مقایسهٔ پاسخ‌های Binder مربوط به connectivity با مدل عمومی. | `NETWORK_PATH_DIVERGENCE` / `android_connectivity` | از دروازهٔ خارجی استفاده کنید. | در `system_server` پالایش کنید؛ target را خارج از دامنهٔ Xposed نگه دارید. | مدل‌های Binder و بومی باید با هم سازگار باشند. |
| `beta.netd_netid` | netd/network ID مسیر فعال. | `NETWORK_PATH_DIVERGENCE` / `netd` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.socket_identity` | mark، netId و هویت socket. | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.inet_diag_cookie` | cookie مربوط به INET_DIAG و هویت socket. | `NETWORK_PATH_DIVERGENCE` / `socket_diag` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.route_lookup` | lookup منفرد route برای مقصد کنترل. | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.policy_rules` | قواعد policy routing برای UID یا netId. | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.rtnl_address` | dump نشانی RTNL در IPv4/IPv6. | `NETWORK_PATH_DIVERGENCE` / `kernel_link` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.extended_rtnetlink` | زمینهٔ گستردهٔ rtnetlink/netd برای مسیریابی. | `NETWORK_PATH_DIVERGENCE` / `kernel_routing` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.interface_driver` | driver، kind و جزئیات رابط شبکه. | `VPN_OR_PROXY` / `kernel_link` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.interface_traffic` | شمارنده‌های رابط و خروجی واقعی ترافیک. | `NETWORK_PATH_DIVERGENCE` / `active_egress` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.wireguard_genl` | وضعیت generic-netlink مربوط به WireGuard. | `VPN_OR_PROXY` / `kernel_vpn` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.ovpn_genl` | وضعیت OpenVPN DCO/generic-netlink. | `VPN_OR_PROXY` / `kernel_vpn` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.xfrm` | stateها و policyهای XFRM/IPsec. | `VPN_OR_PROXY` / `kernel_ipsec` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.unix_diag` | socketهای Unix-domain مربوط به صفحهٔ کنترل محلی. | `VPN_OR_PROXY` / `local_control_plane` | proxy یا daemon کنترل را غیرفعال کنید. | مسدودسازی مختص UID یا namespace اعمال کنید. | listener یا Unix socket ممکن است همچنان قابل مشاهده باشد. |
| `beta.unix_peer_identity` | credential و هویت peer در Unix socket. | `VPN_OR_PROXY` / `local_control_plane` | proxy یا daemon کنترل را غیرفعال کنید. | مسدودسازی مختص UID یا namespace اعمال کنید. | listener یا Unix socket ممکن است همچنان قابل مشاهده باشد. |
| `beta.tun_fd` | پرس‌وجوی هسته از file descriptor مربوط به TUN. **پس از تکرار پایدار، مرجعیت سخت دارد.** | `VPN_OR_PROXY` / `process_fd` | با دروازهٔ خارجی، `VpnService` محلی را حذف کنید. | از پالایش هسته استفاده کنید؛ هوک userspace کافی نیست. | فقط پس از دست‌کم دو نمونهٔ پایدار و یکسان شاهد سخت است. |
| `beta.bpf_netd` | mapهای BPF/netd و policy ترافیک. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.cgroup_bpf` | اتصال و policy مربوط به cgroup BPF. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.netfilter_path` | مسیر netfilter یا وضعیت redirect. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.original_destination` | مقصد اصلی پس از redirect شفاف. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.direct_syscall_consistency` | مقایسهٔ APIهای libc با syscallهای مستقیم. | `HOOK_OR_TAMPERING` / `hook_consistency` | از تزریق داخل فرایند پرهیز کنید. | از backend هسته استفاده و target را خارج از Zygisk/Xposed نگه دارید. | مسیر جایگزین هوک ناقص را آشکار می‌کند. |
| `beta.io_uring_consistency` | مقایسهٔ مسیر جایگزین io_uring با API هوک‌شده. | `HOOK_OR_TAMPERING` / `alternate_syscall_path` | از تزریق داخل فرایند پرهیز کنید. | از backend هسته استفاده و target را خارج از Zygisk/Xposed نگه دارید. | مسیر جایگزین هوک ناقص را آشکار می‌کند. |
| `beta.fd_identity` | نوع و هویت file descriptorهای فرایند. | `HOOK_OR_TAMPERING` / `process_fd` | از تزریق داخل فرایند پرهیز کنید. | از backend هسته استفاده و target را خارج از Zygisk/Xposed نگه دارید. | مسیر جایگزین هوک ناقص را آشکار می‌کند. |
| `beta.sandbox_identity.process` | هویت فرایند در کانتینر مجازی. | `APP_VIRTUALIZATION` / `process_identity` | APK اصلی را در sandbox عادی اجرا کنید. | از کانتینر مجازی یا APK بسته‌بندی‌شده استفاده نکنید. | روت کانتینر را به پروفایل عادی تبدیل نمی‌کند. |
| `beta.sandbox_identity.filesystem` | چیدمان filesystem و هویت sandbox. | `APP_VIRTUALIZATION` / `filesystem_identity` | APK اصلی را در sandbox عادی اجرا کنید. | از کانتینر مجازی یا APK بسته‌بندی‌شده استفاده نکنید. | روت کانتینر را به پروفایل عادی تبدیل نمی‌کند. |
| `beta.sandbox_identity.namespace` | هویت namespace مربوط به sandbox یا لایهٔ مجازی‌سازی. | `APP_VIRTUALIZATION` / `namespace_identity` | APK اصلی را در sandbox عادی اجرا کنید. | از کانتینر مجازی یا APK بسته‌بندی‌شده استفاده نکنید. | روت کانتینر را به پروفایل عادی تبدیل نمی‌کند. |
| `beta.fscrypt_identity` | هویت fscrypt و فضای ذخیره‌سازی کاربر. | `APP_VIRTUALIZATION` / `filesystem_identity` | APK اصلی را در sandbox عادی اجرا کنید. | از کانتینر مجازی یا APK بسته‌بندی‌شده استفاده نکنید. | روت کانتینر را به پروفایل عادی تبدیل نمی‌کند. |
| `beta.linker_integrity` | یکپارچگی linker/loader و هوک‌ها. | `HOOK_OR_TAMPERING` / `loader_integrity` | از تزریق داخل فرایند پرهیز کنید. | از backend هسته استفاده و target را خارج از Zygisk/Xposed نگه دارید. | مسیر جایگزین هوک ناقص را آشکار می‌کند. |
| `beta.dns_netid` | netId و مسیر resolver مربوط به DNS. | `NETWORK_PATH_DIVERGENCE` / `dns_path` | مسیر واقعی، DNS و TLS را هم‌راستا کنید؛ از دروازهٔ خارجی استفاده کنید. | روت جای مسیر سمت سرور را نمی‌گیرد؛ MITM را حذف کنید. | epoch شبکه و نویز مهم‌اند؛ زمینهٔ سرور به‌تنهایی همیشه شاهد سخت نیست. |
| `beta.native_dns_resolver` | مقایسهٔ resolver بومی با DNS مربوط به framework. | `NETWORK_PATH_DIVERGENCE` / `dns_path` | مسیر واقعی، DNS و TLS را هم‌راستا کنید؛ از دروازهٔ خارجی استفاده کنید. | روت جای مسیر سمت سرور را نمی‌گیرد؛ MITM را حذف کنید. | epoch شبکه و نویز مهم‌اند؛ زمینهٔ سرور به‌تنهایی همیشه شاهد سخت نیست. |
| `beta.proxy_selector` | سازگاری `ProxySelector` در Java با proxy سیستم. | `VPN_OR_PROXY` / `android_proxy` | proxy یا daemon کنترل را غیرفعال کنید. | مسدودسازی مختص UID یا namespace اعمال کنید. | listener یا Unix socket ممکن است همچنان قابل مشاهده باشد. |
| `beta.transport_matrix` | ماتریس HTTP/DNS/UDP روی endpointهای canary. | `NETWORK_PATH_DIVERGENCE` / `active_egress` | مسیر واقعی، DNS و TLS را هم‌راستا کنید؛ از دروازهٔ خارجی استفاده کنید. | روت جای مسیر سمت سرور را نمی‌گیرد؛ MITM را حذف کنید. | epoch شبکه و نویز مهم‌اند؛ زمینهٔ سرور به‌تنهایی همیشه شاهد سخت نیست. |
| `beta.tls_interception` | رهگیری TLS و مسیر certificate. | `VPN_OR_PROXY` / `tls_path` | مسیر واقعی، DNS و TLS را هم‌راستا کنید؛ از دروازهٔ خارجی استفاده کنید. | روت جای مسیر سمت سرور را نمی‌گیرد؛ MITM را حذف کنید. | epoch شبکه و نویز مهم‌اند؛ زمینهٔ سرور به‌تنهایی همیشه شاهد سخت نیست. |
| `beta.pktinfo` | `IP_PKTINFO`/IPv6 pktinfo برای مسیر ورودی و خروجی. | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.netlink_transitions` | توالی زمانی رویدادهای شبکه در netlink. | `NETWORK_PATH_DIVERGENCE` / `network_timeline` | از دروازهٔ خارجی استفاده کنید یا VPN محلی را حذف کنید. | همان کانال را در سطح هسته پالایش کنید؛ حالت پیشرفتهٔ VPNHide Next آزمایشی است. | رد دسترسی اغلب خنثی است؛ رفتار هسته و ROM متفاوت است. |
| `beta.traceroute` | traceroute و مشاهدهٔ مسیر. | `SYSTEM_NETWORK_CONTEXT` / `path_observation` | مسیر واقعی، DNS و TLS را هم‌راستا کنید؛ از دروازهٔ خارجی استفاده کنید. | روت جای مسیر سمت سرور را نمی‌گیرد؛ MITM را حذف کنید. | epoch شبکه و نویز مهم‌اند؛ زمینهٔ سرور به‌تنهایی همیشه شاهد سخت نیست. |
| `beta.server_fingerprint` | fingerprint دوردست کانال مشاهده‌شده. | `SYSTEM_NETWORK_CONTEXT` / `server_observation` | مسیر واقعی، DNS و TLS را هم‌راستا کنید؛ از دروازهٔ خارجی استفاده کنید. | روت جای مسیر سمت سرور را نمی‌گیرد؛ MITM را حذف کنید. | epoch شبکه و نویز مهم‌اند؛ زمینهٔ سرور به‌تنهایی همیشه شاهد سخت نیست. |
| `beta.root_emulator` | ارزیابی تجمیعی beta از روت، شبیه‌ساز و یکپارچگی دستگاه. | `DEVICE_INTEGRITY` / `device_integrity` | از دستگاه فیزیکی رسمی و بدون روت استفاده کنید. | سطح روت را کمینه کنید؛ شبیه‌ساز را ناقص جعل نکنید. | وضعیت بازبینی یا quorum همچنان ممکن است. |

## تفسیر Quorum

**بررسی‌شده در پروژه:** شواهد beta مربوط به شبکه زمانی `DETECTED` می‌شوند که دست‌کم دو گروه مستقل شبکه وجود داشته باشد، یا یک گروه beta با یک منبع پایدار و مستقل شبکه همراه شود. جداسازی همراه با سیگنال شبکه نیز ممکن است detection بسازد. دست‌کاری و مجازی‌سازی برنامه به دو گروه مستقل نیاز دارند. `SYSTEM_NETWORK_CONTEXT` که traceroute و fingerprint سمت سرور را شامل می‌شود، به‌تنهایی quorum سخت نمی‌سازد.

بنابراین هدف درست «ساکت‌کردن همهٔ ردیف‌های beta» نیست، بلکه حذف تأیید مستقل است. نتیجهٔ پاک Binder کمکی نمی‌کند وقتی `tun_fd` و route lookup همچنان آلوده‌اند؛ dump پاک route همراه با اختلاف syscall مستقیم، هوک ناقص userspace را آشکار می‌کند.

## راستی‌آزمایی

دو نمونهٔ پیاپی را بدون تعویض شبکه جمع‌آوری کنید و سپس پس از force-stop تکرار کنید. اگر نتیجه در هر اجرا تغییر می‌کند، پیش از نصب ماژول پنهان‌سازی دیگر، race یا ناپایداری epoch شبکه را برطرف کنید.

پروب‌های دارای privilege را فقط در اجرای آزمایشگاهی جداگانه استفاده کنید. Shizuku یا روت را وابستگی دائمی آزمون عادی کاربر نکنید: در سیاست beta، نبود privilege محدودیت دسترس‌پذیری است، نه اثبات پاک‌بودن سیستم.

[بازگشت به نمایهٔ anti-detection](../)
