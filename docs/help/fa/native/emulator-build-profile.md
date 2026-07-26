---
title: "هیوریستیک‌های Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT"
permalink: /help/fa/native/emulator-build-profile/
---

# هیوریستیک‌های Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT

> **شناسه:** `EMULATOR_BUILD`
> **دسته:** شبیه‌سازی، پروفایل‌ها و جداسازی
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** متوسط

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

Kotlin fingerprint را وقتی با `generic` یا `unknown` آغاز شود یا شامل `vbox`، `emulator` یا `test-keys` باشد علامت می‌زند؛ model را وقتی `google_sdk`، `Emulator` یا `Android SDK built for` داشته باشد؛ hardware را برای مقادیر دقیق `goldfish`، `ranchu` یا `vbox86`؛ product را برای `sdk_gphone*`، `vbox86p`، `emulator`، `sdk` یا `google_sdk`؛ و manufacturer را برای مقدار دقیق `Genymotion`. هر مورد یک finding بازبینی با اطمینان متوسط تولید می‌کند.

### شرط دقیق فعال‌شدن

هرگونه تطبیق با الگوهای فهرست‌شدهٔ build.

## معنای نتیجه

این هیوریستیک گسترده است؛ بنابراین `test-keys` ممکن است به‌جای شبیه‌ساز، میان‌افزار سفارشی روی دستگاه فیزیکی را نشان دهد. نتیجه را با نشانگرهای QEMU و nodeهای دستگاه ترکیب کنید.

**تأثیر این خط بر گزارش:** این خط به‌تنهایی حکم نهایی صادر نمی‌کند، اما `needsReview=true` را تنظیم و شاهدی با اطمینان متوسط اضافه می‌کند.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

فیلدهای build به‌آسانی spoof می‌شوند و میان OEMها متفاوت‌اند. GSI تولیدی یا برد توسعه ممکن است به‌طور مشروع generic به‌نظر برسد.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

برای پرهیز از این دسته نشانه‌ها، از دستگاه فیزیکی با build تولیدی استفاده کنید. ویژگی‌های QEMU، نشانگرهای goldfish/ranchu، دستگاه‌های ویژه و fingerprint ساخت بخشی از محیط‌اند؛ یک برنامهٔ عادی نمی‌تواند بدون تغییر سیستمی آن‌ها را سازگار عوض کند. تلفن ابری یا clone سازنده را نیز محیطی جدا بدانید و با خط مبنای دستگاه فیزیکی مقایسه کنید. برای دستگاه فیزیکی با ROM سفارشی، تنها خط مبنای پاک یک build تولیدی رسمی است؛ factory reset fingerprint را تغییر نمی‌دهد.

### با روت

جعل چند مقدار `getprop` شبیه‌ساز را به دستگاه فیزیکی تبدیل نمی‌کند: driverها، nodeهای `/dev`، پروفایل سخت‌افزار، ABI و رفتار هسته باقی می‌مانند. ماژول‌های روت برای spoof ممکن است یک نشانگر را حذف کنند و هم‌زمان ناسازگاری هوک، property یا library بسازند. این کار برای آزمایش توسعه قابل‌قبول است، اما نتیجهٔ معتبر RKNHardering باید روی دستگاه واقعی گرفته شود. تغییر سازگار fingerprint، model، product و hardware دشوار است؛ spoof ناقص در لایه‌های دیگر آشکار می‌ماند و ممکن است Play Integrity را خراب کند.

### روش راستی‌آزمایی نتیجه

```bash
adb shell getprop ro.build.fingerprint
adb shell getprop ro.product.model
adb shell getprop ro.hardware
adb shell getprop ro.product.name
adb shell getprop ro.product.manufacturer
```
زیررشته‌های دقیق استفاده‌شده در پیاده‌سازی را بررسی کنید.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

fingerprint نامعتبر می‌تواند OTA یا سرویس‌های Play را مختل کند؛ spoof مقادیر hardware یا product ممکن است HAL ناسازگار را انتخاب کند.

### بازگردانی

ماژول spoof را حذف کنید و propertyهای build را از image اصلی بازگردانید.

## سطح شواهد

**متوسط.** `collectBuildEmulatorFacts()` بررسی شده است؛ همهٔ سطرهای تولیدی finding بازبینی با اطمینان متوسط‌اند.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [آزمون‌های واحد کاتالوگ/بررسی‌کنندهٔ بومی](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [Android Build API](https://developer.android.com/reference/android/os/Build).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `emulator-qemu-property`, `emulator-goldfish`, `root-property`.

[بازگشت به مرجع بررسی‌های بومی](../)
