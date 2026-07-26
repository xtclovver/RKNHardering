---
title: "مسیر میزبان عمومی /32 یا /128 از رابط فیزیکی"
permalink: /help/fa/native/host-route/
---

# مسیر میزبان عمومی /32 یا /128 از رابط فیزیکی

> **شناسه:** `HOST_ROUTE`
> **دسته:** مسیرها و پشتهٔ شبکه
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** متوسط

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

`isVpnServerHostRouteCandidate()` فقط سطرهای netlink را در نظر می‌گیرد که default route نیستند، prefix برابر `/32` یا `/128` دارند، نوع `unicast` و scopeِ `global` یا `link` دارند، در جدول local شمارهٔ 255 نیستند و از protocol هسته استفاده نمی‌کنند. مقصد باید عمومی و قابل‌مسیریابی باشد و رابط از نوع فیزیکی استاندارد. چنین مسیری شبیه pin کردن نشانی سرور VPN بیرون تونل است، اما سرویس‌های carrier و سیستم نیز می‌توانند آن را بسازند.

### شرط دقیق فعال‌شدن

مسیر میزبان عمومی مطابق شرط، `needsReview=true` را با اطمینان متوسط تنظیم می‌کند. `detected` false می‌ماند.

## معنای نتیجه

این فقط candidate است، نه مدرک. در Android معمول، سوکت سرور `VpnService` اغلب با `protect()` یا fwmark و بدون host route جدا از VPN خارج می‌شود؛ پس سیگنال برای VPNهای روت/هسته یا clientهای غیراستاندارد مرتبط‌تر است.

**تأثیر این خط بر گزارش:** این خط به‌تنهایی حکم نهایی صادر نمی‌کند، اما `needsReview=true` را تنظیم و شاهدی با اطمینان متوسط اضافه می‌کند.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

CDN، captive portal، IMS اپراتور، سرویس امنیتی OEM یا تنظیم static شبکه می‌تواند به‌طور مشروع routeِ /32 بسازد. بدون همبستگی با فرایند یا سوکت، نمی‌توان نشانی را endpointِ VPN دانست.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

ابتدا مالک route را از زمان ظاهرشدن آن پیدا کنید: snapshot پیش از شروع VPN، پس از شروع و پس از غیرفعال‌شدن را مقایسه کنید. اگر client route را می‌سازد، از `VpnService.protect()` استاندارد یا split-route خودش استفاده کنید؛ route را دستی حذف نکنید. دروازهٔ خارجی host route محلی را از تلفن حذف می‌کند.

### با روت

backend هسته می‌تواند این شکل route را پنهان کند، اما فیلتر مبتنی بر شکل ممکن است /32 مشروع را نیز حذف کند. VPNHide بالادستی منطق host-route را عمدتاً برای VPNهای desktop-style یا روت مستند می‌کند. تأیید کنید ترافیک هدف واقعاً از شبکهٔ فیزیکی می‌رود و سوکت سرور دوباره داخل تونل route نمی‌شود.

### روش راستی‌آزمایی نتیجه

```bash
adb shell ip -4 route show table all | grep -E '(^| )/32| scope link'
adb shell ip -6 route show table all | grep '/128'
```
سه وضعیت بگیرید: VPN خاموش، VPN روشن و client متوقف. نشانی را بدون redaction در issue منتشر نکنید.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

حذف host route ممکن است اتصال VPN را داخل تونل خودش بفرستد و قطع کند. فیلتر بیش‌ازحد گسترده می‌تواند سرویس‌های اپراتور را مختل کند.

### بازگردانی

client VPN یا شبکه را دوباره اجرا کنید تا route بازسازی شود. هوک روت را از مدیرش غیرفعال و reboot کنید.

## سطح شواهد

**متوسط.** شروط سخت allowlist در `isVpnServerHostRouteCandidate()` و آزمون‌های واحد host-route بررسی شده‌اند. سیگنال عمداً فقط برای بازبینی است.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`native_signs_probe.cpp` — پیاده‌سازی پروب بومی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- راستی‌آزمایی‌شده با کد پروژه: [آزمون‌های واحد کاتالوگ/بررسی‌کنندهٔ بومی](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [VpnService.protect()](https://developer.android.com/reference/android/net/VpnService).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [VPNHide host-route notes](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `route-table`, `vpn-policy-rules-netlink`, `established-vpn-socket`.

[بازگشت به مرجع بررسی‌های بومی](../)
