---
title: "propertyهای مشکوک روت/اشکال‌زدایی"
permalink: /help/fa/native/root-property/
---

# propertyهای مشکوک روت/اشکال‌زدایی

> **شناسه:** `ROOT_PROPERTY`
> **دسته:** روت و وضعیت سامانه
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** متوسط

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

پروب زوج‌های دقیق `ro.debuggable=1`، `ro.secure=0`، `ro.build.selinux=0`، `service.adb.root=1` و `ro.build.tags=test-keys` را بررسی می‌کند. فقط تطبیق دقیق `root_prop` تولید می‌کند و بررسی‌کننده آن را finding بازبینی با اطمینان متوسط می‌داند.

### شرط دقیق فعال‌شدن

حداقل یکی از propertyهای ثابت دقیقاً مقدار مشکوک خود را داشته باشد.

## معنای نتیجه

این سیگنال معمولاً بیش از آنکه مدیر روت خاصی را نشان دهد، ROM اشکال‌زدایی/engineering یا image بوت تغییریافته را نشان می‌دهد. `test-keys` به‌ویژه در ROMهای سفارشی جامعه رایج است.

**تأثیر این خط بر گزارش:** این خط به‌تنهایی حکم نهایی صادر نمی‌کند، اما `needsReview=true` را تنظیم و شاهدی با اطمینان متوسط اضافه می‌کند.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

پیکربندی روت production ممکن است این propertyها را تغییر ندهد. در جهت دیگر، build از نوع AOSP userdebug می‌تواند بدون اعطای `su` به‌طور مشروع بررسی را فعال کند.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

وقتی خط مبنای پاک لازم است، از build رسمی user سازنده استفاده کنید. factory reset میان‌افزار را جایگزین یا propertyهای `ro.*` را تغییر نمی‌دهد. `build.prop` دلخواه دانلود نکنید؛ باید دقیقاً با image نصب‌شده سازگار باشد.

### با روت

`resetprop` می‌تواند مقدار قابل‌مشاهده را تغییر دهد، اما ناسازگاری با وضعیت بوت، fingerprint ساخت و mountها ممکن است به نشانگرهای جداگانه تبدیل شود. spoof را فقط آزمایش آزمایشگاهی بدانید، نه مدرک پاک‌بودن دستگاه. SELinux با یک property منفرد «اصلاح» نمی‌شود.

### روش راستی‌آزمایی نتیجه

```bash
adb shell getprop ro.debuggable
adb shell getprop ro.secure
adb shell getprop ro.build.selinux
adb shell getprop service.adb.root
adb shell getprop ro.build.tags
```
مقادیر را با detail مقایسه کنید؛ namespaceِ property ممکن است پس از جایگزینی در سطح روت متفاوت باشد.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

تغییر propertyهای آغاز بوت یا image بوت ممکن است boot loop ایجاد کند. fingerprint نادرست می‌تواند OTA، سرویس‌های Play و سازگاری را خراب کند.

### بازگردانی

فقط قاعدهٔ `resetprop` ساخته‌شده را حذف و دستگاه را دوباره راه‌اندازی کنید. اگر image بوت تغییر کرده، image اصلی همان build را بازیابی کنید.

## سطح شواهد

**متوسط.** آرایهٔ `kRootProps` بررسی شده است؛ بررسی‌کننده اطمینان متوسط می‌دهد.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`native_signs_probe.cpp` — پیاده‌سازی پروب بومی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [Android build variants](https://source.android.com/docs/setup/build/building).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [Magisk resetprop documentation](https://topjohnwu.github.io/Magisk/tools.html#resetprop).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `root-magisk-property`, `emulator-build-profile`, `root-selinux`.

[بازگشت به مرجع بررسی‌های بومی](../)
