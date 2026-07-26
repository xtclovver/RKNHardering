---
title: "propertyهای سیستمی هوک LSPosed/Magisk/Zygote"
permalink: /help/fa/native/hook-property/
---

# propertyهای سیستمی هوک LSPosed/Magisk/Zygote

> **شناسه:** `HOOK_PROPERTY`
> **دسته:** هوک‌ها و یکپارچگی فرایند
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** بالا

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

`detectVpnFiles()` مقادیر `persist.sys.lspd.hook`، `ro.magisk.version` و `init.svc.zygote_restart` را می‌خواند؛ هر مقدار غیرخالی `hook_prop` تولید می‌کند. policy قدیمی این kind را با اطمینان زیاد طبقه‌بندی و `detected=true` را تنظیم می‌کند.

### شرط دقیق فعال‌شدن

یکی از سه property مرتبط با هوک غیرخالی باشد.

## معنای نتیجه

این نشانگر قدیمی با اطمینان زیاد از runtime تغییریافته یا framework روت است. نام property از مقدارش مهم‌تر است.

**تأثیر این خط بر گزارش:** این خط `detected=true` را تنظیم می‌کند و به‌عنوان یک نشانهٔ محلی با اطمینان بالا در نظر گرفته می‌شود.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

فهرست کوتاه و وابسته به نسخه است. از نظر نظری OEM می‌تواند `init.svc.zygote_restart` را استفاده کند، درحالی‌که frameworkهای جدید ممکن است هیچ‌کدام از این کلیدها را افشا نکنند.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

بدون روت، بهترین گزینه APK پاک از منبع قابل‌اعتماد است؛ بدون repack، LSPatch، Frida Gadget، مجازی‌سازی یا Xposed بدون روت. انتقال برنامه به «فضای دوم» فرایند را خودکار پاک نمی‌کند: container می‌تواند library خودش را inject و ناسازگاری بیشتری ایجاد کند.

### با روت

روی دستگاه روت‌شده، مگر در صورت ضرورت برنامهٔ هدف را در scopeِ Xposed/Vector نگذارید و ماژول Zygisk را داخل آن بارگذاری نکنید. برای پنهان‌سازی VPN، طراحی‌ای مناسب‌تر است که فیلتر Java در `system_server` و فیلتر بومی در هسته اجرا شود. DenyList/App Profile، NoHello، Zygisk Next، SUSFS و ابزارهای مشابه شاید بعضی آثار را کم کنند، اما هیچ‌کدام محافظت هم‌زمان در برابر maps، linker، mount و syscall خام را تضمین نمی‌کنند. اگر ماژول قدیمی property را می‌سازد، آن را به‌روزرسانی یا حذف کنید. قواعد گستردهٔ `resetprop` جای خارج‌کردن هدف از injection را نمی‌گیرند.

### روش راستی‌آزمایی نتیجه

```bash
adb shell getprop persist.sys.lspd.hook
adb shell getprop ro.magisk.version
adb shell getprop init.svc.zygote_restart
```
هر رشتهٔ غیرخالی شرط فعال‌شدن را برآورده می‌کند.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

spoof کردن propertyهای سرویس zygote می‌تواند شروع برنامه‌ها را مختل و تشخیص crash را پیچیده کند.

### بازگردانی

قواعد مشخص `resetprop` یا ماژول قدیمی را حذف و reboot کنید.

## سطح شواهد

**زیاد.** `hookPropNames` بررسی شده است؛ kind در مجموعهٔ اطمینان زیاد legacy قرار دارد.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`native_signs_probe.cpp` — پیاده‌سازی پروب بومی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [Magisk](https://github.com/topjohnwu/Magisk).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [Vector](https://github.com/JingMatrix/Vector).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `lsposed`, `hook-markers`, `root-magisk-property`.

[بازگشت به مرجع بررسی‌های بومی](../)
