---
title: "بارگذاری کتابخانهٔ بررسی‌های بومی"
permalink: /help/fa/native/native-library/
---

# بارگذاری کتابخانهٔ بررسی‌های بومی

> **شناسه:** `NATIVE_LIBRARY`
> **دسته:** سیگنال‌های سرویس
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** دسترس‌پذیری

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

پیش از اجرای هر پروب JNI، `NativeSignsBridge` کتابخانهٔ بومی را بارگذاری می‌کند. اگر `System.loadLibrary` شکست بخورد، هم `NativeSignsChecker` و هم تشخیص‌گر عمیق VPN خطی با شناسهٔ `NATIVE_LIBRARY` برمی‌گردانند که در صورت وجود متن استثنا را نیز شامل می‌شود. پس از این شکست، بررسی‌های رابط، route، روت و هوک تکمیل‌شده محسوب نمی‌شوند.

### شرط دقیق فعال‌شدن

بارگذاری `.so` شکست بخورد، ABI ناسازگار باشد، کتابخانه غایب باشد، خطای linker یا فضای نام رخ دهد، یا استثنای JNI ایجاد شود. بارگذاری موفق خط مثبت جداگانه‌ای تولید نمی‌کند.

## معنای نتیجه

این نه نشانهٔ پاک‌بودن دستگاه است و نه نشانهٔ VPN. معنی آن این است که بخش قابل‌توجهی از پوشش بومی دردسترس نیست و نتیجهٔ کلی باید ناقص در نظر گرفته شود.

**تأثیر این خط بر گزارش:** این سیگنال یعنی اجرای پروب ممکن نبوده است. نباید `unavailable` را مدرکی برای نبود VPN دانست.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

علت‌های ممکن شامل APK آسیب‌دیده، split APK فاقد ABI لازم، ناسازگاری فرایند ۳۲/۶۴ بیتی، دخالت packer، خطای build یا محدودیت محیط است. این شکست به‌ویژه پس از بسته‌بندی مجدد محتمل است.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

APK رسمی همان نسخه را دوباره نصب کنید؛ آن را استخراج و دوباره امضا نکنید. تأیید کنید دستگاه از ABI build پشتیبانی می‌کند و نصب بدون تعارض split کامل شده است. برای توسعه، APK را با task استاندارد Gradle بسازید و ورودی‌های `lib/*` داخل آن را بررسی کنید.

### با روت

ابتدا ماژول‌هایی را غیرفعال کنید که فضای نام linker، Zygote یا بارگذاری کتابخانه را برای RKNHardering تغییر می‌دهند. برای پنهان‌کردن VPN عمداً JNI را خراب نکنید: برنامه دردسترس‌نبودن بررسی را آشکارا گزارش می‌کند و آن را پاک تلقی نمی‌کند.

### روش راستی‌آزمایی نتیجه

```bash
adb shell pm path com.notcvnt.rknhardering
adb shell dumpsys package com.notcvnt.rknhardering | grep -E 'primaryCpuAbi|secondaryCpuAbi'
adb logcat -c
adb shell am force-stop com.notcvnt.rknhardering
# سپس برنامه را باز کنید و در logcat به‌دنبال UnsatisfiedLinkError یا dlopen بگردید:
adb logcat | grep -Ei 'rknhardering|UnsatisfiedLinkError|dlopen|linker'
```
برای build محلی، فرمان `unzip -l app-release.apk | grep '/lib/'` را نیز اجرا کنید.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

اگر `adb install -r` با امضای ناسازگار استفاده شود یا ابتدا برنامه حذف شود، نصب مجدد ممکن است دادهٔ محلی را پاک کند. گزارش‌های export‌شده و تنظیمات را ذخیره کنید.

### بازگردانی

APK با امضای اصلی را بازیابی کنید و فقط تغییراتی را برگردانید که بر بارگذاری اثر داشته‌اند. اگر مشکل پس از نصب ماژول روت ظاهر شد، همان ماژول مشخص را غیرفعال و دستگاه را ریبوت کنید.

## سطح شواهد

**دردسترس‌بودن.** شاخه‌های `libraryUnavailableResult()` در هر دو بررسی‌کنندهٔ Kotlin و ثبت متدهای JNI راستی‌آزمایی شده‌اند. این سیگنال پوشش بررسی را توصیف می‌کند، نه وضعیت شبکه را.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsBridge.kt` — بارگذاری JNI و پل بومی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/probe/NativeSignsBridge.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`VpnNativeDetectorChecker.kt` — حکم و اطمینان بررسی عمیق VPN](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`native_signs_probe.cpp` — پیاده‌سازی پروب بومی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [Android ABI management](https://developer.android.com/ndk/guides/abis).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `general-diagnostics`, `syscall-unavailable`, `library-integrity`.

[بازگشت به مرجع بررسی‌های بومی](../)
