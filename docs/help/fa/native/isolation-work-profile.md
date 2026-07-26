---
title: "RKNHardering مالک پروفایل است"
permalink: /help/fa/native/isolation-work-profile/
---

# RKNHardering مالک پروفایل است

> **شناسه:** `ISOLATION_WORK_PROFILE`
> **دسته:** شبیه‌سازی، پروفایل‌ها و جداسازی
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** متوسط

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

بررسی‌کننده `DevicePolicyManager` را می‌گیرد و `isProfileOwnerApp(context.packageName)` را فراخوانی می‌کند. سیگنال فقط وقتی ظاهر می‌شود که خود packageِ RKNHardering به‌عنوان profile owner ثبت شده باشد. این از پرسش «آیا برنامه داخل work profile اجرا می‌شود» محدودتر است؛ برنامهٔ عادی در پروفایل مدیریت‌شده بدون نقش DPC ممکن است این سطر را نسازد.

### شرط دقیق فعال‌شدن

`isProfileOwnerApp()` برای packageِ RKNHardering مقدار true برگرداند.

## معنای نتیجه

finding بازبینی با اطمینان متوسط نقش بسیار مشخص DPC/profile-owner را نشان می‌دهد، نه صرفاً وجود work profile روی دستگاه.

**تأثیر این خط بر گزارش:** این خط به‌تنهایی حکم نهایی صادر نمی‌کند، اما `needsReview=true` را تنظیم و شاهدی با اطمینان متوسط اضافه می‌کند.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

نام سیگنال از پیاده‌سازی گسترده‌تر است. برای برنامهٔ عادی در Shelter یا Insular، سیگنال secondary-user مبتنی بر user ID محتمل‌تر است.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

اگر پروفایل بخشی از آزمون نیست، برنامه را زیر کاربر اصلی (`user 0`) نصب و اجرا کنید. پیش از حذف work profile، Private Space یا پروفایل clone از داده‌های آن export بگیرید؛ حذف پروفایل برنامه‌ها و storage آن را پاک می‌کند. Shelter و Insular برای پروفایل مدیریت‌شده مفیدند، اما وجود کاربر جداگانهٔ Android را پنهان نمی‌کنند. اگر RKNHardering تصادفاً به‌عنوان DPC تعیین شده، پس از export داده مدیریت پروفایل را از Shelter، Insular یا Settings بردارید.

### با روت

spoof کردن user ID، مسیر `/data/user/<id>` یا پاسخ‌های `DevicePolicyManager` با روت وضعیت ناسازگار می‌سازد و ممکن است پروفایل را خراب کند. اجرای برنامه زیر کاربر درست امن‌تر از mask کردن پروفایل است. هوک‌های درون فرایند هدف برای یک بررسی می‌توانند علاوه بر آن `HOOK_MARKERS`، `RWX_MEMORY_REGIONS` و `LIBRARY_INTEGRITY` را فعال کنند. هوک کردن فقط `DevicePolicyManager` برای این سطر، user ID واقعی و وضعیت مدیریت را در APIهای دیگر قابل‌مشاهده می‌گذارد.

### روش راستی‌آزمایی نتیجه

```bash
adb shell dpm list-owners
adb shell dumpsys device_policy | grep -A8 -B2 -i 'profile owner'
```
ممکن است فرمان‌ها به shell نیاز داشته باشند؛ detail خود برنامه منبع نهایی است.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

برداشتن profile owner معمولاً work profile و داده‌هایش را حذف می‌کند. ابتدا همهٔ داده‌های مهم را export کنید.

### بازگردانی

پروفایل مدیریت‌شده را با DPC قابل‌اعتماد دوباره بسازید و داده را بازیابی کنید.

## سطح شواهد

**متوسط.** فراخوانی دقیق `isProfileOwnerApp` بررسی شده است؛ این مستند برداشت بیش‌ازحد گستردهٔ قبلی را اصلاح می‌کند.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [آزمون‌های واحد کاتالوگ/بررسی‌کنندهٔ بومی](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [DevicePolicyManager.isProfileOwnerApp](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#isProfileOwnerApp%28java.lang.String%29).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [پروفایل‌های مدیریت‌شده در AOSP](https://source.android.com/docs/devices/admin/managed-profiles).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `isolation-secondary-user`, `isolation-profile`.

[بازگشت به مرجع بررسی‌های بومی](../)
