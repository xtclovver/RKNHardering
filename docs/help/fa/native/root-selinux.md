---
title: "حالت permissive در SELinux یا دردسترس‌نبودن فایل enforce"
permalink: /help/fa/native/root-selinux/
---

# حالت permissive در SELinux یا دردسترس‌نبودن فایل enforce

> **شناسه:** `ROOT_SELINUX`
> **دسته:** روت و وضعیت سامانه
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** متوسط

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

C++ فایل `/sys/fs/selinux/enforce` را می‌خواند. مقدار `0`، `selinux|permissive` را با اطمینان زیاد تولید می‌کند. اگر فایل اصلاً باز نشود، `selinux|absent` تولید می‌شود و Kotlin آن را finding بازبینی با اطمینان کم می‌داند.

### شرط دقیق فعال‌شدن

یا `enforce=0` باشد، یا بازکردن فایل enforce ممکن نباشد.

## معنای نتیجه

حالت permissive یک تغییر امنیتی عمده است. `absent` مبهم است: ممکن است مسیر توسط SELinux یا namespace پنهان شده، داخل container وجود نداشته یا برای برنامهٔ عادی غیرقابل‌دسترسی باشد.

**تأثیر این خط بر گزارش:** این خط به‌تنهایی حکم نهایی صادر نمی‌کند، اما `needsReview=true` را تنظیم و شاهدی با اطمینان متوسط اضافه می‌کند.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

بررسی کل policy را تحلیل نمی‌کند. enforcing بودن به معنای استانداردبودن policy نیست؛ ماژول روت می‌تواند مجوزهای اضافه کند. نبود فایل معادل permissive نیست.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

اگر خط مبنای پاک لازم است، میان‌افزاری نصب نکنید که SELinux را permissive شروع می‌کند. روی ROM تولیدی SELinux را enforcing نگه دارید. اگر فایل فقط برای برنامه غایب است، به‌جای تضعیف policy سیگنال‌های مجاور را ارزیابی کنید.

### با روت

هرگز برای VPNHide یا ماژول دیگر SELinux را permissive نکنید. denial مشخص AVC را با محدودترین قاعده حل کنید یا استفاده از ماژول ناسازگار را متوقف کنید. جایگزینی مقدار قابل‌مشاهدهٔ `enforce` بدون enforcement واقعی فقط حس امنیت کاذب می‌سازد.

### روش راستی‌آزمایی نتیجه

```bash
adb shell getenforce
adb shell cat /sys/fs/selinux/enforce 2>/dev/null
adb logcat -d | grep 'avc: denied' | tail -50
```
نتیجهٔ `getenforce` در shell و خواندن توسط UID برنامه ممکن است از نظر دسترس‌پذیری متفاوت باشد، نه از نظر حالت واقعی هسته.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

حالت permissive اجرای SELinux را غیرفعال و اثر compromise را بیشتر می‌کند. sepolicy نادرست ممکن است boot loop ایجاد کند.

### بازگردانی

حالت enforcing را بازگردانید و جدیدترین قاعدهٔ گستردهٔ sepolicy را حذف کنید. اگر دستگاه دیگر بوت نمی‌شود، image بوت را بازیابی یا ماژول را از safe mode غیرفعال کنید.

## سطح شواهد

**متوسط.** دو شاخهٔ `nativeDetectRoot()` بررسی شده‌اند؛ اطمینان میان permissive و absent متفاوت است.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`native_signs_probe.cpp` — پیاده‌سازی پروب بومی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [SELinux در AOSP](https://source.android.com/docs/security/features/selinux).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `root-property`, `root-system-rw`, `syscall-unavailable`.

[بازگشت به مرجع بررسی‌های بومی](../)
