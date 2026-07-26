---
title: سیگنال‌های محلی Android — Binder، TUN، مسیرها و localhost
permalink: /help/fa/anti-detection/local-signals/
---

# سیگنال‌های محلی Android — Binder، TUN، مسیرها و localhost

بررسی‌های محلی به این پرسش پاسخ نمی‌دهند که «بسته از کجا عبور کرد؟»، بلکه می‌پرسند «Android شبکه را برای این UID چگونه توصیف می‌کند؟». حتی با خروجی مستقیم و GeoIP درست نیز این سیگنال‌ها قابل مشاهده می‌مانند.

## نقشهٔ کانال‌های محلی

| کانال | نمونه‌ها در RKNHardering | چرا یک هوک کافی نیست |
|---|---|---|
| Framework/Binder | `TRANSPORT_VPN`، `IS_VPN`، `VpnTransportInfo`، `NOT_VPN`، `LinkProperties` و callbackها | داده در `system_server` تولید می‌شود؛ هوک بومی آن را تغییر نمی‌دهد |
| libc/JNI | `NetworkInterface`، `getifaddrs()` و ioctl | هوک Java روی `ConnectivityManager` بر libc یا هسته اثری ندارد |
| netlink/هسته | `RTM_GETLINK`، `RTM_GETADDR`، routeها، policy ruleها و qdisc | syscall خام از interposition عادی Zygisk/libc عبور می‌کند |
| proc/sysfs | `/proc/net/*` و `/sys/class/net` | رفتار SELinux به ROM وابسته است؛ رد دسترسی روی همهٔ دستگاه‌ها تضمین‌شده نیست |
| PackageManager | سرویس‌گیرنده‌های VPN و اعلان‌های `VpnService` | مستقل از فعال‌بودن تونل است |
| صفحهٔ کنترل محلی | SOCKS/HTTP، gRPC مربوط به Xray و REST مربوط به Clash/sing-box | گذرواژه listener را پنهان نمی‌کند؛ اسکن می‌تواند پروتکل و درگاه را تشخیص دهد |
| dumpsys/سرویس‌های سیستم | `vpn_management` و نمونه‌های فعال `VpnService` | دسترسی برنامه‌های عادی اغلب محدود است، اما ROM و سطح privilege دسترس‌پذیری را تغییر می‌دهند |

## بدون روت

### چه کارهایی ممکن است

وقتی proxy سیستمی HTTP/SOCKS و تنظیمات PAC لازم نیستند، آن‌ها را غیرفعال کنید. `settings get global http_proxy`، propertyهای Java و تنظیمات هر شبکه را بررسی کنید. proxy سیستمی یک سیگنال مستقیم و مستقل است و هیچ کمکی به پنهان‌سازی VPN نمی‌کند.

listenerهای غیرضروری localhost را غیرفعال کنید. API کنترل در Clash/mihomo/sing-box/Xray باید یا خاموش باشد یا برای برنامه دسترس‌پذیر نباشد. secret قوی فرمان‌ها را محافظت می‌کند، اما RKNHardering همچنین SOCKS5، HTTP CONNECT و APIهای شناخته‌شدهٔ REST یا gRPC را تشخیص می‌دهد.

از محدودیت دیده‌شدن packageها در Android استفاده کنید، اما آن را بیش‌ازحد مؤثر فرض نکنید. از Android 11 به بعد، برنامه‌ها معمولاً فقط مجموعه‌ای پالایش‌شده از packageها را می‌بینند؛ بااین‌حال `QUERY_ALL_PACKAGES`، queryهای intent، UID مشترک، رابطهٔ installer و سیاست‌های OEM می‌توانند دید را گسترش دهند. مستندات رسمی [Package visibility filtering](https://developer.android.com/training/package-visibility) را ببینید.

وقتی باید همهٔ کانال‌های محلی پاک به‌نظر برسند، VPN را به یک دروازهٔ خارجی منتقل کنید. یک تغییر معماری، `VpnService`، رابط TUN، برنامهٔ VPN و daemon مربوط به localhost را هم‌زمان از دستگاه Android تحت آزمون حذف می‌کند.

### چه چیزی عموماً بدون روت حل نمی‌شود

یک APK در sandbox نمی‌تواند بدون تغییر سیستم یا هسته، dump پالایش‌شدهٔ netlink به‌ازای UID را برای برنامهٔ دیگری از هستهٔ Android بگیرد. همچنین نمی‌تواند پاسخ Binder مربوط به `NetworkCapabilities` برای برنامه‌ای دیگر را با اطمینان بازنویسی کند یا یک رابط TUN فعال را از `getifaddrs()` پنهان کند و درعین‌حال آن را برای برنامه‌های دیگر عملیاتی نگه دارد.

APK تغییر‌یافته یا «Xposed بدون روت» معادل این کار نیست. بسته‌بندی مجدد امضا و یکپارچگی برنامه را تغییر می‌دهد و تزریق فرایند مستقیماً با `HOOK_MARKERS`، `RWX_MEMORY_REGIONS`، `LIBRARY_INTEGRITY` و بررسی‌های beta مربوط به syscall مستقیم یا linker تلاقی دارد. برای RKNHardering، این وضعیت معمولاً از خود سیگنال اولیهٔ VPN بدتر است.

### پروفایل ثانویه

work profile ممکن است برنامه‌های VPN نصب‌شده در پروفایلی دیگر را پنهان کند و تنظیمات شبکهٔ جداگانه‌ای بدهد، اما Android همچنان از هسته و پشتهٔ شبکهٔ مشترک استفاده می‌کند و RKNHardering می‌تواند شناسهٔ کاربر و وضعیت پروفایل را ببیند. برای جزئیات بخش [پروفایل‌ها](../profiles/) را بخوانید.

## با روت

پوشش کامل محلی به دو لایه و در صورت نیاز به لایهٔ سوم احتیاج دارد:

1. **لایهٔ framework:** ماژول VPNHide در Vector/LSPosed که دامنه‌اش فقط `System Framework` است. این لایه اشیای Binder را پیش از serialize‌شدن در فرایند هدف پاک می‌کند.
2. **لایهٔ بومی:** دقیقاً یکی از kmod، KPM یا Zygisk. گونه‌های هسته ترجیح دارند، زیرا syscallهای خام پالایش آن‌ها را دور نمی‌زنند و فرایند هدف دست‌نخورده می‌ماند.
3. **لایهٔ درگاه/package:** پالایش `PackageManager` و مسدودسازی loopback برای UID هدف.

راهنمای جزئی نصب در بخش [VPNHide و VPNHide Next](../root-vpnhide/) آمده است.

### NetworkCapabilities و LinkProperties

VPNHide اصلی ادعا می‌کند `NetworkCapabilities`، `NetworkInfo`، `LinkProperties`، شبکهٔ فعال، فهرست شبکه‌ها و callbackها را در `system_server` پالایش می‌کند. این محل درست مداخله است: RKNHardering به‌جای بارگذاری bridge مربوط به Xposed در فرایند خودش، Parcel ازپیش‌پاک‌شده دریافت می‌کند.

دامنه را بررسی کنید. در Vector/LSPosed فقط **`System Framework`** را انتخاب کنید، نه RKNHardering. افزودن برنامهٔ هدف به دامنه، سطح هوک درون‌فرایندی ایجاد می‌کند و معماری VPNHide به آن نیاز ندارد.

### رابط‌ها، مسیرها و netlink

پس‌زمینهٔ هسته دست‌کم باید موارد زیر را پوشش دهد:

- `ioctl(SIOCGIFFLAGS/SIOCGIFNAME/SIOCGIFCONF/...)`؛
- `getifaddrs()` و `NetworkInterface`؛
- dumpهای netlink از نوع `RTM_GETLINK`، `RTM_GETADDR` و route؛
- `/proc/net/route` و نمای route مربوط به IPv6 در جایی که دسترسی مجاز است؛
- اوراکل‌های index رابط و policy ruleها، در صورت پشتیبانی پس‌زمینهٔ انتخاب‌شده.

VPNHide اصلی شکاف‌های شناخته‌شده را مستند کرده است: syscallهای خام Zygisk را دور می‌زنند؛ backendهای هستهٔ منتشرشده در ماتریس فعلی بعضی مسیرهای `/proc/net/tcp*` و `if_inet6` را پوشش نمی‌دهند؛ و KPM محدودیت‌های parity جداگانه دارد. بنابراین «ماژول فعال است» باید از طریق ردیف‌های مشخص RKNHardering راستی‌آزمایی شود، نه فقط صفحهٔ وضعیت مدیر.

VPNHide Next ادعا می‌کند حالتی گسترده‌تر برای پوشش sysfs/procfs، MTU/MSS/TCP_INFO، PMTU/GSO، BPF، qdisc، timing و رفتار link-local دارد. این ادعای پروژهٔ بیرونی است. حالت‌های Minimum، Medium و Maximum را روی همان firmware واقعی مقایسه و مسیر بازیابی را آماده نگه دارید.

### Localhost و APIها

بهترین گزینه غیرفعال‌کردن listener است. وقتی این کار ممکن نیست، مسدودسازی مختص UID اعمال کنید. VPNHide اصلی جزء جداگانهٔ `portshide` دارد که برای برنامه‌های انتخاب‌شده قاعده می‌سازد. VPNHide Next به‌جای iptables، هوک هسته‌ای `security_socket_connect` را ادعا می‌کند.

از یک نتیجهٔ `connection refused` به‌تنهایی نتیجه‌گیری نکنید: این پیام یعنی اتصال رد شده و ممکن است دقیقاً رفتار موردنظر باشد. `timeout` یعنی عملیات در زمان مقرر کامل نشده است؛ برای اسکنر، این الگوی رفتاری متفاوت است و می‌تواند به سیگنال timing تبدیل شود. طبقه‌بندی خود RKNHardering را بررسی کنید.

### مدیر بسته‌ها (PackageManager)

نقش Apps در VPNHide برای UIDهای مشاهده‌گر انتخاب‌شده، enumeration، resolve کردن intent، lookup مستقیم، اطلاعات installer و نگاشت UID را پالایش می‌کند. UIDهای سیستمی و lookup خود برنامه باید همچنان کار کنند. پس از پیکربندی، بررسی کنید launcher و installer درست کار می‌کنند و سرویس‌گیرندهٔ VPN می‌تواند خودش را ببیند.

## راستی‌آزمایی نتیجه

UID بستهٔ هدف را پیدا کنید:

```bash
adb shell cmd package list packages -U | grep 'com.notcvnt.rknhardering'
```

وضعیت خط مبنا را بررسی کنید:

```bash
adb shell dumpsys connectivity
adb shell ip -details link
adb shell ip route show table all
adb shell ip rule
adb shell settings get global http_proxy
```

برای VPNHide اصلی، وقتی backend متناظر نصب است، فقط از تشخیص‌های فقط‌خواندنی استفاده کنید:

```bash
adb shell su -c 'cat /data/system/vpnhide_config.json'
adb shell su -c 'ls -la /data/adb/modules | grep -i vpnhide'
adb shell su -c 'cat /proc/vpnhide_ctl 2>/dev/null || cat /proc/vpnhide_targets 2>/dev/null'
adb logcat -d | grep -iE 'VpnHide|Vector|LSPosed'
```

مسیر `/proc/vpnhide_*` به نسخه یا fork وابسته است. `no such file or directory` یعنی مسیر وجود ندارد یا آن نسخه رابط کنترل دیگری دارد؛ فایل را دستی ایجاد نکنید.

پس از تغییر، برنامه را force-stop کنید و دو اجرا انجام دهید. Zygisk و قواعد درگاه ممکن است به راه‌اندازی دوبارهٔ فرایند نیاز داشته باشند. لایهٔ هسته یا `system_server` اغلب می‌تواند به‌روزرسانی پیکربندی را بدون ریبوت کامل اعمال کند، اما پس از نصب ماژول، ریبوت الزامی است.

## سیگنال‌های باقی‌مانده

نمای محلی پاک GeoIP، DNS، STUN یا fingerprint سمت سرور را حذف نمی‌کند. پنهان‌سازی هسته خودکار روت را پنهان نمی‌کند. پنهان‌سازی package امضای فایل یا هوک درون‌فرایندی را تغییر نمی‌دهد. عکس آن نیز درست است: namespace پاک مربوط به روت، `TRANSPORT_VPN` را پنهان نمی‌کند.

[بازگشت به نمایهٔ anti-detection](../)
