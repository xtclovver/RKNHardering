---
title: پشتهٔ روت — VPNHide، VPNHide Next، Vector، Magisk، KernelSU و APatch
permalink: /help/fa/anti-detection/root-vpnhide/
---

# پشتهٔ روت — VPNHide، VPNHide Next، Vector، Magisk، KernelSU و APatch

این صفحه یک معماری نصب را شرح می‌دهد، نه راهکار «یک‌کلیکی». هر ماژول هسته یا boot می‌تواند حلقهٔ بوت، kernel panic، قطع شبکه یا ناسازگاری پس از به‌روزرسانی OTA ایجاد کند. پیش از شروع، image رسمی پارتیشن مربوط را ذخیره کنید و مطمئن شوید می‌دانید چگونه وارد bootloader یا recovery شوید و ماژول را غیرفعال کنید. بازکردن قفل bootloader روی بیشتر دستگاه‌ها داده‌های کاربر را پاک می‌کند.

## بدون روت

VPNHide و VPNHide Next حالت کامل بدون روت ندارند: هدف آن‌ها به مداخله در `system_server`، هسته یا فرایند Zygote نیاز دارد. بدون روت، APK فقط می‌تواند رابط کاربری، ابزار تشخیص یا configurator باشد؛ privilege لازم برای پالایش پاسخ Binder یا netlink برای UID دیگر را به‌دست نمی‌آورد.

نزدیک‌ترین معادل بدون روت از نظر نتیجه، روتر یا دروازهٔ خارجی است. این روش پاسخ‌های محلی را جعل نمی‌کند؛ VPN محلی را به‌کلی از تلفن حذف می‌کند. کاربر ثانویه، بسته‌بندی مجدد یا Xposed بدون روت پوشش مشابهی نمی‌دهد و سیگنال‌های جداسازی یا یکپارچگی اضافه می‌کند.

## با روت: انتخاب پایه

| پایه | مزیت اصلی | خطر یا محدودیت اصلی | دریافت رسمی |
|---|---|---|---|
| Magisk | راهکار روت پرکاربرد، اکوسیستم ماژول و Zygisk داخلی | آثار روت و userspace؛ مدیریت boot image به دستگاه وابسته است | [انتشارهای Magisk](https://github.com/topjohnwu/Magisk/releases/latest)، [راهنمای رسمی نصب](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md) |
| KernelSU Next | `su` در سطح هسته، App Profile و mountهای ماژول | به هسته یا LKM سازگار نیاز دارد؛ نسخهٔ manager و هسته باید هماهنگ باشند | [انتشارهای KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest)، [مستندات](https://kernelsu-next.github.io/webpage/) |
| APatch | runtime مربوط به KernelPatch و مناسب سناریوهای KPM | `boot.img` را patch می‌کند، فقط ARM64؛ image یا کلید اشتباه خطرناک است | [انتشارهای APatch](https://github.com/bmax121/APatch/releases/latest)، [راهنمای نصب روسی](https://apatch.dev/ru/install.html) |

فرمان‌های flash را میان دستگاه‌ها کپی نکنید. Magisk ممکن است از پارتیشن `boot` یا `init_boot` استفاده کند، درحالی‌که مستندات APatch مشخصاً `boot.img` می‌خواهد. دستورالعمل پروژهٔ انتخاب‌شده را دنبال و از image کارخانه‌ای دقیقاً همان build نصب‌شده روی دستگاه استفاده کنید.

### بررسی APK یا ZIP پیش از نصب

فایل دانلودشدهٔ هسته یا ماژول روت فقط به‌خاطر شباهت نامش به انتشار رسمی قابل‌اعتماد نیست. ابتدا URL صفحهٔ انتشار را حفظ و hash محلی را محاسبه کنید:

```bash
sha256sum vpnhide*.zip *.apk
unzip -l vpnhide*.zip | sed -n '1,120p'
unzip -p vpnhide*.zip module.prop 2>/dev/null
```

برای APK، از `apksigner` در Android SDK Build-Tools استفاده کنید:

```bash
apksigner verify --verbose --print-certs vpnhide.apk
```

مقدار SHA-256 را فقط با checksum منتشرشده از سوی خود پروژه مقایسه کنید. hashی که در پیام دلخواه کنار همان فایل قرار گرفته، راستی‌آزمایی مستقل نیست. ZIPی را نصب نکنید که از طریق سایت یا bot شخص ثالث SuperKey، اشتراک VPN یا secret دیگری می‌خواهد. بررسی با `unzip -l` ایمنی scriptها را ثابت نمی‌کند، اما می‌تواند پیش از نصب boot image، فایل باینری یا installer نامرتبط و غیرمنتظره را آشکار کند.

## انتخاب framework: Vector یا LSPosed قدیمی

مخزن اصلی [LSPosed/LSPosed](https://github.com/LSPosed/LSPosed) در ۲ مهٔ ۲۰۲۶ archive شد و پشتیبانی Android 8.1 تا 14 را اعلام می‌کرد. برای دستگاه‌های فعلی، نقطهٔ شروع منطقی‌تر [JingMatrix/Vector](https://github.com/JingMatrix/Vector/releases/latest) است که پشتیبانی Android 8.1 تا 17 Beta و سازگاری با Xposed API را تبلیغ می‌کند.

VPNHide فقط به دامنهٔ سیستم framework نیاز دارد. پس از نصب:

1. ماژول VPNHide یا VPNHide Next را فعال کنید.
2. **فقط `System Framework`** را انتخاب کنید.
3. `com.notcvnt.rknhardering` را به دامنه اضافه نکنید.
4. دستگاه را ریبوت کنید، زیرا `system_server` باید درحالی شروع شود که ماژول از قبل فعال است.

اگر انتشار مشخص VPNHide صریحاً به‌جای Vector به LSPosed نیاز دارد، ترکیب سازگاری را که در release note همان نسخه ذکر شده استفاده کنید. دو framework از نوع Xposed را هم‌زمان اجرا نکنید.

## VPNHide اصلی: آرایش پایدار پیشنهادی

منبع و دریافت: [okhsunrog/vpnhide](https://github.com/okhsunrog/vpnhide)، [آخرین انتشار](https://github.com/okhsunrog/vpnhide/releases/latest) و [نقشهٔ بردارهای تشخیص](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).

معماری:

- APK مربوط به VPNHide targetها را پیکربندی می‌کند؛
- Vector یا LSPosed در دامنهٔ `System Framework` پالایش Java/Binder و PackageManager را انجام می‌دهد؛
- **دقیقاً یک** backend بومی استفاده می‌شود: kmod، KPM یا Zygisk؛
- `portshide` اختیاری دسترسی loopback را مدیریت می‌کند.

### انتخاب backend بومی

روی دستگاه GKI پشتیبانی‌شده، ابتدا **kmod** را انتخاب کنید. در هسته اجرا می‌شود، حافظهٔ فرایند RKNHardering را تغییر نمی‌دهد و syscall خام نمی‌تواند پالایشش را دور بزند. VPNHide buildها را بر اساس نسل KMI مانند `android14-6.1` منتشر می‌کند؛ این نام نسل هسته را مشخص می‌کند و لزوماً معادل نسخهٔ Android نیست.

برای هسته‌های قدیمی یا غیر GKI، یا وقتی `.ko` بار نمی‌شود، از **KPM** استفاده کنید. این مسیر به runtime مربوط به KernelPatch از طریق APatch یا KPatch-Next-Module نیاز دارد. مسیر beta است و آزمون میدانی کمتری دارد.

**Zygisk** را فقط fallback بدانید. در سطح libc و داخل فرایند هدف پالایش می‌کند؛ بنابراین RKNHardering ممکن است اختلاف در `maps`، حافظهٔ RWX، linker یا هوک‌ها را ببیند و syscall خام نیز می‌تواند فیلتر را دور بزند. آن را هم‌ارز backend هسته توصیف نکنید.

**هرگز kmod و KPM را هم‌زمان نصب نکنید.** ممکن است همان توابع هسته را هوک کنند و نتیجه hang، kernel panic یا حلقهٔ بوت باشد. اگر چند ZIP مربوط به backend نصب مانده‌اند، موارد اضافه را حذف و تأیید کنید فقط یکی فعال است.

### نصب VPNHide اصلی

1. APK و ZIP پیشنهادی ماژول را فقط از [انتشار رسمی](https://github.com/okhsunrog/vpnhide/releases/latest) دانلود کنید. اگر نویسنده checksum داده است، نام فایل و SHA-256 را بررسی کنید.
2. APK را به‌صورت عادی نصب کنید.
3. ماژول را در Vector یا LSPosed با دامنهٔ `System Framework` فعال و سپس دستگاه را ریبوت کنید.
4. روت را فقط به برنامهٔ configuratorِ VPNHide بدهید، هرگز به RKNHardering ندهید.
5. در برگهٔ overview، backend بومی پیشنهادی را انتخاب و **یک** ZIP را از طریق مدیر روت نصب کنید.
6. ماژول جداگانهٔ Ports را فقط در صورت نیاز نصب کنید.
7. پس از ریبوت، `com.notcvnt.rknhardering` را به‌عنوان target در Java، Native و Ports و به‌عنوان observer در Apps انتخاب کنید و ذخیره کنید.
8. RKNHardering را force-stop کنید و دو بررسی انجام دهید.

در انتشارهای فعلی VPNHide اصلی، پیکربندی کاربر در `/data/system/vpnhide_config.json` ذخیره می‌شود. فقط پس از تهیهٔ پشتیبان و اعتبارسنجی JSON آن را دستی ویرایش کنید؛ `invalid config` یعنی خطای syntax یا schema. استفاده از رابط کاربری معمولاً امن‌تر است.

بررسی فقط‌خواندنی:

```bash
adb shell uname -r
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell su -c 'ls -la /data/adb/modules | grep -i vpnhide'
adb shell su -c 'cat /data/system/vpnhide_config.json'
adb logcat -d | grep -iE 'VpnHide|Vector|LSPosed'
```

## VPNHide Next: پوشش آزمایشی گسترده‌تر

منبع و دریافت: [soranerai/vpnhide_next](https://github.com/soranerai/vpnhide_next)، [آخرین انتشار](https://github.com/soranerai/vpnhide_next/releases/latest).

**ادعاشده توسط پروژهٔ بیرونی:** fork پوشش هسته‌ای مسدودسازی درگاه، MTU، MSS و `TCP_INFO`، مدیریت GSO و PMTU، آمار ترافیک eBPF، qdisc، timing مربوط به UDP، IPv6 link-local و پنهان‌سازی گسترده‌تر proc/sysfs را اضافه می‌کند. حالت‌های `Min`، `Medium` و `Max` شمار هوک‌های فعال را کنترل می‌کنند. README پروژه صریحاً هشدار می‌دهد پایداری روی همهٔ هسته‌ها تضمین نیست و حلقهٔ بوت یا kernel panic ممکن است رخ دهد.

انتخاب عملی:

- با `Min` شروع کنید تا پالایش پایهٔ `ioctl`، `getifaddrs`، netlink و route را راستی‌آزمایی کنید؛
- وقتی RKNHardering همچنان سیگنال‌های socket، MTU، MSS یا PMTU را می‌بیند، به `Medium` بروید؛
- `Max` را فقط روی دستگاه آزمایشگاهی با recovery سالم و پس از تأیید یافتهٔ مشخص proc، sysfs، BPF، qdisc یا timing استفاده کنید.

`Max` را «برای احتیاط» فعال نکنید. هوک‌های بیشتر هسته خطر ناسازگاری را افزایش می‌دهند و جداکردن علت regression را دشوارتر می‌کنند.

ماژول LSPosed در VPNHide Next نیز باید از طریق `System Framework` و بدون ورود به فرایند target کار کند. README مربوط به kmod، `dev_ioctl`، `sock_ioctl`، `rtnl_fill_ifinfo`، netlink نشانی‌های IPv4/IPv6 و `/proc/net/route` را نقاط پایهٔ هوک می‌داند. APK و ZIP را دقیقاً از یک انتشار نگه دارید؛ ناسازگاری پروتکل کنترل می‌تواند رفتار ناقص بسازد.

### راه‌اندازی گام‌به‌گام VPNHide Next

1. APK و ماژول هسته را فقط از [انتشار رسمی](https://github.com/soranerai/vpnhide_next/releases/latest) دانلود کنید. از kmod مربوط به VPNHide اصلی استفاده نکنید: این پروژه پروتکل کنترل متفاوتی دارد.
2. خروجی `uname -r`، build مربوط به Android و نام asset دانلودشده را ثبت کنید. اگر انتشار سازگاری با هستهٔ نصب‌شده را اعلام نکرده است، آن را روی دستگاه اصلی «برای امتحان» flash نکنید.
3. APK را نصب، آن را در Vector یا LSPosed فعال، دامنه را فقط روی `System Framework` نگه دارید و ریبوت کنید.
4. دقیقاً یک ZIP هستهٔ VPNHide Next را از طریق مدیر روت پشتیبانی‌شده نصب و دوباره ریبوت کنید.
5. در برنامه، UID یا نسخهٔ `com.notcvnt.rknhardering` را انتخاب کنید، با `Min` شروع و پیکربندی را ذخیره کنید.
6. دو اجرای یکسان انجام دهید. فقط وقتی یافتهٔ مشخص MTU، MSS، PMTU، BPF، qdisc، proc یا sysfs باقی مانده است، به‌ترتیب به `Medium` و سپس `Max` بروید.

README سطح بالا دستگاه کنترل جدیدتر `/dev/vpnhide_ctrl` را شرح می‌دهد، درحالی‌که READMEهای جدا یا buildهای قدیمی ممکن است همچنان `/proc/vpnhide_targets` و `targets.txt` را ذکر کنند. این تفاوت مستندات میان revisionها است؛ دلیل نمی‌شود فایل غایب را دستی ایجاد کنید. از رابط کاربری همان انتشار دقیق استفاده و فقط بررسی‌های فقط‌خواندنی انجام دهید:

```bash
adb shell su -c 'cat /proc/modules | grep -i vpnhide'
adb shell su -c 'ls -l /dev/vpnhide_ctrl /proc/vpnhide_targets 2>/dev/null'
adb logcat -d | grep -iE 'VPNHide Next|VpnHide|Vector|LSPosed'
```

`no such file or directory` یعنی مسیر غایب است یا آن revision رابط دیگری دارد. اگر ماژول در `/proc/modules` دیده نمی‌شود اما رابط کاربری لایهٔ بومی را سالم گزارش می‌کند، ابتدا معماری همان انتشار را بررسی کنید: KPM یا patch یکپارچهٔ هسته الزاماً شبیه LKM معمولی نیست.

## Zygisk Next و پنهان‌سازی روت موضوع‌های جدا هستند

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) API مربوط به Zygisk را برای KernelSU یا APatch فراهم می‌کند یا می‌تواند جای Zygisk داخلی Magisk را بگیرد. linker جدید و حالت‌های anonymous-memory آن برای کاهش آثار طراحی شده‌اند، اما سازگاری ماژول تضمین نیست. این ابزار backend درون‌فرایندی VPNHide را به فیلتر سطح هسته تبدیل نمی‌کند.

پنهان‌سازی روت جداگانه در [بخش یکپارچگی](../root-integrity/) توضیح داده شده است. ابتدا مطمئن شوید VPNHide درست کار می‌کند، سپس سطح روت را کمینه کنید. نصب هم‌زمان چند ماژول پنهان‌سازی عیب‌یابی را دشوار و ممکن است سیگنال تازهٔ mount یا linker ایجاد کند.

## راستی‌آزمایی هر لایه

پس از نصب، فقط به نشانگر سبز وضعیت VPNHide تکیه نکنید.

**Framework:** سیگنال‌های `DIRECT_NETWORK_CAPABILITIES`، `INDIRECT_NETWORK_CAPABILITIES` و نام یا routeهای رابط VPN در `LinkProperties` باید از RKNHardering حذف شوند.

**Native:** سیگنال‌های `INTERFACE_ENUMERATION`، `TUNTAP_TYPE`، `GETIFADDRS_VPN`، `RTM_GETLINK_VPN` و نشانگرهای route یا index رابط باید حذف شوند. وقتی Java پاک است اما یافته‌های بومی باقی مانده‌اند، مشکل backend بومی است، نه LSPosed.

**Ports:** اسکن loopback نباید دیگر SOCKS، HTTP، Xray یا Clash API را تأیید کند. بازبودن درگاه برای shell اما دسترس‌ناپذیربودن آن برای UID هدف رفتار موردانتظار است.

**Integrity:** نباید `HOOK_MARKERS`، `RWX_MEMORY_REGIONS`، `LIBRARY_INTEGRITY`، `LSPOSED` یا سیگنال‌های β مربوط به سازگاری هوک تازه‌ای ظاهر شود. اگر ظاهر شدند، دامنهٔ framework را بررسی و backend درون‌فرایندی را کنار بگذارید.

## خطرها و بازگردانی

پیش از هر تغییر هسته یا ماژول، موارد زیر را نگه دارید:

- image رسمی `boot` یا `init_boot` طبق راهنمای رسمی راهکار روت؛
- image patch‌شدهٔ فعلی که سالم کار می‌کند؛
- فهرست `/data/adb/modules` و نسخهٔ دقیق APKها و ZIPها؛
- پیکربندی VPNHide؛
- روشی برای ورود به recovery یا bootloader بدون بوت Android.

هر بار فقط یک مرحله را برگردانید: جدیدترین ماژول را از طریق manager یا safe mode غیرفعال کنید، ریبوت کنید، شبکه را بسنجید و سپس آن را حذف کنید. چند جزء را هم‌زمان حذف نکنید، وگرنه علت نامشخص می‌ماند. در حلقهٔ بوت، از سازوکار rescue رسمی مدیر روت استفاده یا image رسمی ذخیره‌شده را طبق دستورالعمل دستگاه بازیابی کنید. دربارهٔ پارتیشن‌ها بداهه‌کاری نکنید.

[بازگشت به فهرست](../)
