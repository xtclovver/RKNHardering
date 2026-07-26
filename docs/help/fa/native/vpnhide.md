---
title: "آثار VPNHide و اوراکل‌های رگرسیون"
permalink: /help/fa/native/vpnhide/
---

# آثار VPNHide و اوراکل‌های رگرسیون

> **شناسه:** `VPNHIDE`
> **دسته:** هوک‌ها و یکپارچگی فرایند
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** ترکیبی

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

یک شناسه دو منبع متفاوت را ترکیب می‌کند. تابع قدیمی `detectVpnFiles()` مسیرهای `/data/local/tmp/vpnhide`، `/data/data/com.vpnhide`، `/data/local/tmp/.vpnhide` و `/data/data/com.vpn.hide` را بررسی می‌کند؛ مسیر منطبق یافتهٔ `vpnhide` با اطمینان بالا می‌سازد. تشخیص‌گر عمیق نیز نتایج دو پروب رگرسیون را به همین شناسه هدایت می‌کند: سازگاری SIOCGIFINDEX/SIOCGIFNAME و انتهای بافر SIOCGIFCONF. نتایج oracle و tail-vpn اطمینان بالا، tail-oracle اطمینان متوسط، clean صرفاً اطلاع‌رسان و unavailable خطا هستند.

### شرط دقیق فعال‌شدن

اطمینان بالا: یک مسیر قدیمی قابل‌دسترسی باشد، index پایدار رابط بدون نام معکوس وجود داشته باشد، یا نامی شبیه VPN در انتهای بافر SIOCGIFCONF دیده شود. اطمینان متوسط: انتهای کهنه اما ظاهراً معتبر و غیر-VPN باقی مانده باشد. نتایج clean و unavailable تشخیص محسوب نمی‌شوند.

## معنای نتیجه

این سیگنال می‌تواند نشان‌دهندهٔ اثر مستقیم فایل یا پالایش ناقص رابط باشد. عنوان به‌تنهایی علت را مشخص نمی‌کند؛ جزئیات و شناسهٔ بررسی را ببینید.

**تأثیر این خط بر گزارش:** همین شناسه هم برای خلاصه‌های اطلاعاتی و هم برای خطوط مشکوک استفاده می‌شود. نتیجه به جزئیات همان خط و شاخهٔ بررسی‌کننده بستگی دارد.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

نام مسیرهای قدیمی با مسیرهای فعلی همهٔ نسخه‌های VPNHide مطابقت ندارد. اوراکل‌های رگرسیون خطاهای پیاده‌سازی مشخصی را می‌آزمایند و ممکن است دورزدنی متفاوت را نبینند.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

VPNHide معمولاً بدون روت نصب نمی‌شود، پس این مسیرها باید غایب باشند. اگر سیگنال oracle بدون VPNHide ظاهر شد، ممکن است پالایش‌گر دیگری یا باگ ROM مسئول باشد؛ آزمون را با خط مبنای پاک تکرار کنید. برای خارج‌کردن خود VPN از تلفن بدون روت، از دروازهٔ خارجی استفاده کنید.

### با روت

فقط از [انتشار رسمی VPNHide](https://github.com/okhsunrog/vpnhide/releases/latest) نصب کنید. `System Framework` و دقیقاً یک پس‌زمینهٔ بومی را پیکربندی کنید. پس از هر به‌روزرسانی، هر دو شناسهٔ رگرسیون را اجرا کنید: نبود `tun0` کافی نیست اگر index یا tail کهنه باقی مانده باشد. kmod و KPM را با هم فعال نکنید.

### روش راستی‌آزمایی نتیجه

```bash
# بررسی فقط‌خواندنی مسیرهای قابل دسترس:
adb shell 'for p in /data/local/tmp/vpnhide /data/data/com.vpnhide /data/local/tmp/.vpnhide /data/data/com.vpn.hide; do [ -e "$p" ] && echo "$p"; done'
# منبع پروب رگرسیون:
rg -n 'vpnhide_ifindex|vpnhide_ifconf' app/src/main/cpp/vpnhide_regression_probe.cpp
```
در رابط کاربری، شناسه‌های `native.vpnhide.ifindex_consistency` و `native.vpnhide.ifconf_tail` را از هم تفکیک کنید.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

پس‌زمینهٔ هسته ممکن است حلقهٔ بوت یا kernel panic ایجاد کند؛ اجرای هم‌زمان چند پس‌زمینه خطر ویژه‌ای دارد. حذف دادهٔ بسته تنظیمات را پاک می‌کند.

### بازگردانی

پیش از نصب، از تصویر boot/init_boot و فهرست ماژول‌ها نسخهٔ پشتیبان بگیرید. اگر حلقهٔ بوت رخ داد، جدیدترین ماژول را از safe mode مدیر غیرفعال یا یک تصویر سالم شناخته‌شده را بازیابی کنید.

## سطح شواهد

**ترکیبی.** فهرست مسیرهای قدیمی، پروب رگرسیون C++ و سیاست اطمینان `VpnNativeDetectorChecker` راستی‌آزمایی شده‌اند.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`native_signs_probe.cpp` — پیاده‌سازی پروب بومی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- راستی‌آزمایی‌شده با کد پروژه: [`vpnhide_regression_probe.cpp` — پروب‌های سازگاری و اوراکل](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/vpnhide_regression_probe.cpp).
- راستی‌آزمایی‌شده با کد پروژه: [`VpnNativeDetectorChecker.kt` — حکم و اطمینان بررسی عمیق VPN](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [VPNHide](https://github.com/okhsunrog/vpnhide).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [VPNHide releases](https://github.com/okhsunrog/vpnhide/releases/latest).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [VPNHide detection vectors](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [VPNHide Next](https://github.com/soranerai/vpnhide_next).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `ifindexname-vpn`, `trim-oracle`, `jvm-native-mismatch`, `lsposed`.

[بازگشت به مرجع بررسی‌های بومی](../)
