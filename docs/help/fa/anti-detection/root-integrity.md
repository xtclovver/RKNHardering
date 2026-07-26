---
title: روت، هوک‌ها، شبیه‌سازها و یکپارچگی فرایند
permalink: /help/fa/anti-detection/root-integrity/
---

# روت، هوک‌ها، شبیه‌سازها و یکپارچگی فرایند

پنهان‌کردن VPN با افزودن یک لایهٔ آشکار Xposed یا Zygisk به فرایند، معاملهٔ خوبی نیست. RKNHardering دسترسی روت، mountها، وضعیت SELinux، propertyهای سیستم، `su`، نشانگرهای هوک، حافظهٔ RWX، یکپارچگی linker و کتابخانه، اختلاف Java/بومی و شبیه‌سازی را جداگانه بررسی می‌کند. هدف این بخش کمینه‌کردن سطح قابل مشاهده است، نه وعدهٔ روت غیرقابل‌تشخیص.

## بدون روت

مطمئن‌ترین خط مبنا برای این بررسی‌ها، دستگاه فیزیکی با build رسمی، SELinux در حالت enforcing و—در صورت پشتیبانی روند نصب—boot state دوباره قفل‌شده است؛ بدون `su`، ماژول‌های `/data/adb`، Xposed یا APK بسته‌بندی‌شدهٔ مجدد.

تغییر `Build.MODEL` شبیه‌ساز را به دستگاه فیزیکی تبدیل نمی‌کند. RKNHardering propertyها، pipeها و driverهای QEMU، آثار Goldfish، نشانگرهای BlueStacks و نمای کلی build را بررسی می‌کند. برای خط مبنای کنترل از تلفن واقعی استفاده کنید. شبیه‌ساز همچنان برای آزمون عملکردی مفید است، اما انتظار `NATIVE_EMULATOR` یا وضعیت بازبینی را داشته باشید.

برای RKNHardering از Xposed بدون روت یا NPatch استفاده نکنید. بسته‌بندی مجدد امضا و ساختار APK را تغییر می‌دهد و تزریق زمان اجرا هوک‌های درون‌فرایندی می‌سازد. این وضعیت مستقیماً با `LIBRARY_INTEGRITY`، `HOOK_MARKERS`، `RWX_MEMORY_REGIONS`، `beta.linker_integrity` و `beta.direct_syscall_consistency` تلاقی دارد.

## با روت

### پیش از افزودن پنهان‌سازی، سطح قابل مشاهده را کم کنید

1. هرگز به RKNHardering دسترسی روت ندهید.
2. رفتار unmount یا deny را برای UID هدف در مدیر روت فعال کنید. نام قابلیت میان Magisk، KernelSU و APatch متفاوت است.
3. وقتی backend هسته موجود است، backend مربوط به VPNHide در Zygisk را برای target فعال نکنید.
4. در Vector یا LSPosed فقط `System Framework` را در دامنه نگه دارید.
5. SELinux را permissive نکنید و `/system` را قابل نوشتن نسازید.
6. جایگزینی‌های دلخواه `resetprop` اضافه نکنید. propertyهای ناسازگار از مقدار اصلی آشکارترند.
7. پس از افزودن هر ماژول، namespace مربوط به mount، فایل `maps` و سیگنال‌های بومی/کتابخانه را بررسی کنید.

### سیگنال‌های روت چه چیزی را بررسی می‌کنند

`ROOT_SU_BINARY` به‌دنبال فایل اجرایی `su` در مسیرهای رایج می‌گردد. `ROOT_MANAGEMENT` مسیرهایی مانند `/data/adb/magisk`، `/data/adb/modules`، پوشه‌های KernelSU یا APatch و آثار مشابه را پوشش می‌دهد. `ROOT_PROPERTY` و `ROOT_MAGISK_PROPERTY` propertyهای ناامن یا شاخص را می‌سنجند. `ROOT_SYSTEM_RW`، `ROOT_SUSPICIOUS_MOUNT` و `ROOT_OVERLAY_MOUNT` پارتیشن‌های سیستمی قابل نوشتن و bind/overlay mountهای غیرعادی را پوشش می‌دهند. `ROOT_SELINUX` حالت permissive یا نبود enforcing را بررسی می‌کند. `ROOT_UID` برابرشدن UID یا GID با صفر را می‌سنجد.

denylist یا namespace unmount فقط برای مسیرهایی مفید است که واقعاً از namespace مربوط به mount برنامهٔ هدف پنهان شده‌اند. این روش propertyهای سراسری هسته را تغییر نمی‌دهد، وضعیت SELinux را اصلاح نمی‌کند و کد درون‌فرایندی Zygisk را حذف نمی‌کند.

### Magisk

فقط از [مخزن رسمی](https://github.com/topjohnwu/Magisk/releases/latest) دانلود کنید. رفتار DenyList داخلی و Zygisk در نسخه‌های مختلف تغییر کرده است؛ release noteها را بخوانید. قاعده برای RKNHardering ساده است: برنامهٔ هدف نباید دسترسی روت بگیرد و نباید mountهای ماژول را ببیند. وقتی VPNHide از هسته و `system_server` استفاده می‌کند، فرایند هدف می‌تواند بدون تزریق Zygisk بماند.

### KernelSU Next

App Profile می‌تواند روت را به‌ازای برنامه محدود و تغییرات ماژول را unmount کند. منابع رسمی: [مخزن](https://github.com/KernelSU-Next/KernelSU-Next) و [مستندات](https://kernelsu-next.github.io/webpage/). بررسی کنید پروفایل روی UID درست اعمال شده باشد، به‌ویژه داخل work profile یا private profile.

### APatch

از SuperKey قوی استفاده کنید و هرگز آن را در log یا screenshot افشا نکنید. مستندات APatch به نسخهٔ پشتیبان `boot.img` اصلی نیاز دارد. backendِ KPM مربوط به VPNHide ممکن است به runtime سالم KernelPatch وابسته باشد؛ این وابستگی به معنی پنهان‌شدن خودکار آثار روت نیست.

### Zygisk Next، NoHello، SUSFS و Hide My Applist

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) API مربوط به Zygisk و حالت‌های linker، حافظه و unmount را فراهم می‌کند. [NoHello](https://github.com/MhmRdd/NoHello/releases/latest) پنهان‌سازی روت و Zygisk همراه با قواعد mount را تبلیغ می‌کند. [هستهٔ SUSFS](https://gitlab.com/simonpunk/susfs4ksu) و [ماژول userspace آن](https://github.com/sidex15/susfs4ksu-module/releases/latest) برای پنهان‌سازی mountها و مسیرها در سطح هسته طراحی شده‌اند، اما به هسته‌ای نیاز دارند که از قبل با patch سازگار SUSFS ساخته شده باشد. نصب یک ZIP روی هستهٔ عادی patch غایب هسته را اضافه نمی‌کند.

این‌ها پروژه‌های بیرونی اضافه‌اند و جزء الزامی VPNHide نیستند. ممکن است به بعضی سیگنال‌های `ROOT_*` یا mount کمک کنند، اما کد، پیکربندی و خطر سازگاری خودشان را نیز اضافه می‌کنند. در هر تکرار فقط یک جزء جدید بیفزایید. build ناشناخته از Telegram یا سایت اشتراک فایل نصب نکنید؛ مخزن، امضا یا checksum انتشار را بررسی کنید و SuperKey یا اسرار دیگر را به شخص ثالث ندهید.

SUSFS به نسخه و یکپارچه‌سازی هسته بسیار حساس است. patch هسته، ماژول userspace و مدیر روت باید متقابلاً سازگار باشند. ترکیب ناسازگار ممکن است بارگذاری نشود، mountها را خراب کند یا حلقهٔ بوت بسازد. روی دستگاه اصلی بدون مسیر بازیابی، انتخاب مناسبی برای نخستین مرحله نیست.

[Hide My Applist](https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest) و forkهای فعلی می‌توانند کانال‌های فهرست package را پالایش کنند، اما معمولاً به پردازش Xposed یا Zygisk داخل برنامهٔ انتخاب‌شده نیاز دارند. برای RKNHardering این پیش‌فرض مناسبی نیست: پنهان‌کردن `INSTALLED_APP` ممکن است `HOOK_MARKERS`، `LSPOSED`، یافته‌های linker یا RWX، یا اختلاف syscall مستقیم ایجاد کند. نقش Apps در VPNHide ترجیح دارد، زیرا از طریق `system_server`، PackageManager را پالایش می‌کند و به قرارگرفتن HMA در دامنهٔ target نیاز ندارد. HMA را آزمایش مقایسه‌ای جدا نگه دارید و روی فیلتر PackageManager سالم لایه نکنید.

### SELinux و propertyهای سیستم

`getenforce` را روی `Enforcing` نگه دارید. `Permissive` امنیت دستگاه را کاهش می‌دهد و سیگنال مستقیم است. `ro.secure`، `ro.debuggable`، `ro.build.tags`، `service.adb.root` یا propertyهای مشابه را تصادفی تغییر ندهید. هر جایگزینی باید با build fingerprint و حالت firmware از درون سازگار باشد؛ در غیر این صورت تضاد تازهٔ یکپارچگی ایجاد می‌کند.

### هوک‌ها و حافظه

`HOOK_MARKERS`، `RWX_MEMORY_REGIONS`، `LIBRARY_INTEGRITY`، `LSPOSED`، `HOOK_PROPERTY` و بررسی‌های β مربوط به linker و syscall مستقیم، اثر مداخله را می‌سنجند، نه فقط نام ماژول را. بنابراین تغییر نام APK یا package مربوط به LSPosed کافی نیست.

ترتیب ترجیحی از کمترین قابلیت مشاهده برای target:

1. روتر خارجی — هیچ روت یا هوکی روی تلفن وجود ندارد.
2. VPNHide هسته همراه با هوک `system_server` — target تزریق نمی‌شود.
3. پنهان‌سازی بومی Zygisk — اثر درون‌فرایندی باقی می‌ماند؛ فقط fallback باشد.
4. قراردادن RKNHardering در دامنهٔ Xposed یا APK بسته‌بندی‌شدهٔ مجدد — بدترین گزینه برای یکپارچگی.

## بررسی فقط‌خواندنی

```bash
adb shell id
adb shell getenforce
adb shell getprop ro.debuggable
adb shell getprop ro.secure
adb shell getprop ro.build.tags
adb shell mount | head -n 80
adb shell cat /proc/self/mountinfo | head -n 80
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
```

خروجی shell برای بررسی namespace خود برنامه کافی نیست: shell و target ممکن است mountهای متفاوتی ببینند. از نتایج RKNHardering و تشخیص‌های مدیر روت استفاده کنید. خروجی کامل `mountinfo`، `getprop` یا فهرست ماژول‌ها را بدون حذف داده‌های حساس منتشر نکنید؛ ممکن است مسیرها، داده‌های مرتبط با serial و نام ماژول‌های خصوصی را شامل شود.

خواندن‌های فقط‌روت:

```bash
adb shell su -c 'ls -la /data/adb'
adb shell su -c 'ls -la /data/adb/modules'
adb shell su -c 'cat /sys/fs/selinux/enforce'
```

بدون `su`، `permission denied` انتظار می‌رود؛ با `su` این پیام یعنی privilege کافی نیست، policy محدودیت ایجاد کرده یا namespace متفاوت است. آن را با دادن مجوز گسترده به برنامه «اصلاح» نکنید.

## راستی‌آزمایی و بازگردانی

پس از نصب جزء پنهان‌سازی، چهار گروه را مقایسه کنید: سیگنال‌های محلی VPN، سیگنال‌های روت، سیگنال‌های هوک و یکپارچگی، و پایداری شبکه. اگر نشانگرهای VPN حذف شدند اما `LIBRARY_INTEGRITY` و `RWX` ظاهر شدند، به backend هسته بروید یا target را از دامنهٔ injection خارج کنید.

برای بازگردانی، آخرین ماژول را غیرفعال، دستگاه را ریبوت، RKNHardering را force-stop و بررسی خط مبنا را تکرار کنید. اگر تلفن دیگر بوت نمی‌شود، از safe mode رسمی مدیر روت یا روند rescue استفاده کنید یا boot image رسمی ذخیره‌شده را بازگردانید. بدون دانستن مالک هر مسیر، پوشه‌های دلخواه `/data/adb` را از recovery حذف نکنید.

[بازگشت به فهرست](../)
