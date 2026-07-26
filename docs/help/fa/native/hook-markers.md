---
title: "نشانگرهای نام‌دار تزریق در `/proc/self/maps`"
permalink: /help/fa/native/hook-markers/
---

# نشانگرهای نام‌دار تزریق در `/proc/self/maps`

> **شناسه:** `HOOK_MARKERS`
> **دسته:** هوک‌ها و یکپارچگی فرایند
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** متوسط

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

تابع بومی `/proc/self/maps` فرایند جاری را می‌خواند و `frida-agent`، `frida-gadget`، `libfrida`، `libsubstrate`، `com.saurik.substrate`، `XposedBridge`، `libxposed`، `lspatch`، `LSPosed`، `libriru` و `libzygisk` را جست‌وجو می‌کند. برای تطبیق، marker و سطر کامل map ثبت می‌شود. Kotlin markerهای شناخته‌شده را با اطمینان زیاد می‌داند، اما به‌جای detected مستقیم `needsReview` را تنظیم می‌کند.

### شرط دقیق فعال‌شدن

هر سطر maps که یکی از markerهای ثابت را داشته باشد finding بازبینی می‌سازد؛ markerهای شناخته‌شده اطمینان زیاد می‌گیرند.

## معنای نتیجه

نشان می‌دهد library یا mapping با نام قابل‌شناسایی داخل فرایند بارگذاری شده است. شاهدی قوی از instrumentation است، اما لزوماً مخرب نیست؛ build آزمایشی، SDK دسترس‌پذیری/پایش یا ماژول نصب‌شده توسط کاربر نیز می‌تواند علت باشد.

**تأثیر این خط بر گزارش:** این خط به‌تنهایی حکم نهایی صادر نمی‌کند، اما `needsReview=true` را تنظیم و شاهدی با اطمینان متوسط اضافه می‌کند.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

تغییر نام فایل از فهرست رشته‌ای عبور می‌کند، اما از بررسی‌های دیگر یکپارچگی نه. mapping ناشناس یا memfd شاید marker نداشته باشد. در جهت دیگر، مسیر بی‌ضرری که یکی از این واژه‌ها را دارد از نظر نظری می‌تواند تطبیق بخورد.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

بدون روت، بهترین گزینه APK پاک از منبع قابل‌اعتماد است؛ بدون repack، LSPatch، Frida Gadget، مجازی‌سازی یا Xposed بدون روت. انتقال برنامه به «فضای دوم» فرایند را خودکار پاک نمی‌کند: container می‌تواند library خودش را inject و ناسازگاری بیشتری ایجاد کند.

### با روت

روی دستگاه روت‌شده، مگر در صورت ضرورت برنامهٔ هدف را در scopeِ Xposed/Vector نگذارید و ماژول Zygisk را داخل آن بارگذاری نکنید. برای پنهان‌سازی VPN، طراحی‌ای مناسب‌تر است که فیلتر Java در `system_server` و فیلتر بومی در هسته اجرا شود. DenyList/App Profile، NoHello، Zygisk Next، SUSFS و ابزارهای مشابه شاید بعضی آثار را کم کنند، اما هیچ‌کدام محافظت هم‌زمان در برابر maps، linker، mount و syscall خام را تضمین نمی‌کنند.

### روش راستی‌آزمایی نتیجه

برای build قابل‌اشکال‌زدایی خودتان می‌توانید maps را با `run-as` بگیرید:
```bash
adb shell run-as com.notcvnt.rknhardering cat /proc/self/maps 2>/dev/null | grep -Ei 'frida|xposed|lsposed|zygisk|riru|substrate|lspatch'
```
در build انتشار، `run-as` معمولاً دردسترس نیست. از detail خود بررسی استفاده کنید و با فهرست ماژول‌های بارگذاری‌شده مقایسه کنید.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

خروجی `/proc/self/maps` مسیرها و اطلاعات چیدمان فرایند را دارد؛ بدون حذف داده‌های حساس آن را کامل منتشر نکنید. غیرفعال‌کردن ماژول‌ها ممکن است روی برنامه‌های دیگر اثر بگذارد.

### بازگردانی

آخرین تغییر را برگردانید: ماژول یا قاعدهٔ افزوده‌شده را از مدیر معمول خودش غیرفعال کنید، reboot کنید و اسکن خط مبنا را تکرار کنید. روی وضعیت ناشناخته هوک دیگری لایه نکنید.

## سطح شواهد

**متوسط.** آرایهٔ ثابت `kSuspiciousMarkers` و `evaluateHookMarkers()` بررسی شده‌اند.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`native_signs_probe.cpp` — پیاده‌سازی پروب بومی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [آزمون‌های واحد کاتالوگ/بررسی‌کنندهٔ بومی](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [/proc/pid/maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [Vector](https://github.com/JingMatrix/Vector).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [Magisk/Zygisk](https://github.com/topjohnwu/Magisk).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `rwx-memory-regions`, `library-integrity`, `lsposed`, `hook-property`.

[بازگشت به مرجع بررسی‌های بومی](../)
