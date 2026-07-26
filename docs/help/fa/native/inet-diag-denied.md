---
title: "دردسترس‌نبودن `NETLINK_SOCK_DIAG` برای برنامه"
permalink: /help/fa/native/inet-diag-denied/
---

# دردسترس‌نبودن `NETLINK_SOCK_DIAG` برای برنامه

> **شناسه:** `INET_DIAG_DENIED`
> **دسته:** آثار VPN و سوکت‌ها
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** متوسط

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

پروب فقط `socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)` را فراخوانی می‌کند. اگر ساخت سوکت `EACCES` یا `EPERM` برگرداند، `inet_diag_denied` تولید می‌شود؛ سوکت موفق بلافاصله و بدون dump بسته می‌شود. این نوع یافتهٔ بازبینی با اطمینان متوسط می‌سازد.

### شرط دقیق فعال‌شدن

هسته یا SELinux از ساخت سوکت `NETLINK_SOCK_DIAG` جلوگیری کند.

## معنای نتیجه

این وضعیت sandbox یا ROM را توصیف می‌کند. رد دسترسی VPN را ثابت نمی‌کند؛ بلکه مانع خواندن تشخیص سوکت‌ها می‌شود. از خط برای توضیح پوشش دردسترس‌نبوده استفاده کنید.

**تأثیر این خط بر گزارش:** این خط به‌تنهایی حکم نهایی صادر نمی‌کند، اما `needsReview=true` را تنظیم و شاهدی با اطمینان متوسط اضافه می‌کند.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

پروب بررسی نمی‌کند پس از ساخت سوکت امکان ارسال درخواست `SOCK_DIAG` وجود دارد یا نه و سیاست‌ها را بر اساس خانوادهٔ پروتکل جدا نمی‌کند. رد دسترسی ممکن است روی Android اصلی انتظار برود.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

برای دورزدن محدودیت تلاش نکنید. با خط مبنای همان میان‌افزار مقایسه کنید و به یاد داشته باشید سایر بررسی‌های سوکت مستقل عمل می‌کنند.

### با روت

`NET_ADMIN` یا `NET_RAW` ندهید و sepolicy مربوط به RKNHardering را گسترش ندهید. هنگام توسعهٔ ROM، policy حداقلی را در دامنهٔ آزمایشی اختصاصی بیازمایید، نه در دامنهٔ تولیدی `untrusted_app`.

### روش راستی‌آزمایی نتیجه

```bash
adb shell 'cat /proc/net/netlink 2>/dev/null | head'
adb logcat -d | grep -Ei 'avc: denied.*sock_diag|NETLINK_SOCK_DIAG' | tail -30
```
نتیجهٔ دقیق فقط از دامنهٔ برنامه قابل مشاهده است.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

اجازه‌دادن inet_diag به برنامه‌های عادی می‌تواند سوکت‌های UIDهای دیگر را افشا و حریم خصوصی را تضعیف کند.

### بازگردانی

تغییر capability یا sepolicy را حذف و دستگاه را ریبوت کنید. تأیید کنید SELinux در حالت enforcing است.

## سطح شواهد

**متوسط.** تنها شاخهٔ `EACCES`/`EPERM` و مسیر اطمینان متوسط در بررسی‌کننده راستی‌آزمایی شده‌اند.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`native_signs_probe.cpp` — پیاده‌سازی پروب بومی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- راستی‌آزمایی‌شده با کد پروژه: [`VpnNativeDetectorChecker.kt` — حکم و اطمینان بررسی عمیق VPN](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [sock_diag kernel documentation](https://www.kernel.org/doc/html/latest/networking/diagnostic.html).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [SELinux در AOSP](https://source.android.com/docs/security/features/selinux).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `established-vpn-socket`, `syscall-unavailable`, `fib-trie-denied`.

[بازگشت به مرجع بررسی‌های بومی](../)
