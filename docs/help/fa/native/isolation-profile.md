---
title: "خلاصهٔ جداسازی کاربر/پروفایل Android"
permalink: /help/fa/native/isolation-profile/
---

# خلاصهٔ جداسازی کاربر/پروفایل Android

> **شناسه:** `ISOLATION_PROFILE`
> **دسته:** شبیه‌سازی، پروفایل‌ها و جداسازی
> **وضعیت در RKNHardering 2.10.0:** بررسی فعال
> **نقش در حکم نهایی:** سرویسی

این صفحه پیاده‌سازی واقعی RKNHardering 2.10.0 را توضیح می‌دهد. در آن مشخص شده است چه اقدام‌هایی بدون روت ممکن‌اند، چه چیزهایی به روت نیاز دارند و کدام راهکار فقط یک سیگنال را کاهش می‌دهد، بی‌آن‌که VPN را به‌طور کامل پنهان کند.

## چه چیزی بررسی می‌شود و چرا

این شناسهٔ چتری است. بررسی‌کنندهٔ فعلی user ID را از `/data/user/<id>/` استخراج و جداگانه `DevicePolicyManager.isProfileOwnerApp()` را فراخوانی می‌کند؛ سطرهای مثبت `ISOLATION_CLONE`، `ISOLATION_SECONDARY_USER` یا `ISOLATION_WORK_PROFILE` می‌گیرند. تولیدکنندهٔ جداگانه‌ای برای `ISOLATION_PROFILE` وجود ندارد.

### شرط دقیق فعال‌شدن

خود شناسه فعال نمی‌شود؛ سه سیگنال فرزند را ببینید.

## معنای نتیجه

پروفایل به‌عنوان مدرک VPN در نظر گرفته نمی‌شود، اما package visibility، UIDها، رفتار VPN هر پروفایل و دسترسی داده را تغییر می‌دهد. بنابراین «فضای دوم» bypass شفاف نیست.

**تأثیر این خط بر گزارش:** این یک شناسهٔ چتری یا پشتیبان است. گروهی از خطوط را به مستندات پیوند می‌دهد، اما همیشه تولیدکنندهٔ مثبت مستقلی ندارد.

## محدودیت‌ها و مثبت‌های کاذب احتمالی

Private Space و cloneهای OEM نوع کاربر متفاوت دارند؛ پیاده‌سازی فعلی عمدتاً user ID عددی و اینکه خود برنامه profile owner است یا نه را می‌بیند.

این خط باید همراه با سیگنال‌های مجاور ارزیابی شود. پاک‌بودن نتیجهٔ یک API به‌تنهایی Java Binder، libc، netlink خام/فراخوانی مستقیم سامانه، procfs/sysfs، سوکت‌های محلی و نشانه‌های سمت سرور را هم‌زمان پوشش نمی‌دهد.

## توصیه‌ها برای این بردار

### بدون روت

اگر پروفایل بخشی از آزمون نیست، برنامه را زیر کاربر اصلی (`user 0`) نصب و اجرا کنید. پیش از حذف work profile، Private Space یا پروفایل clone از داده‌های آن export بگیرید؛ حذف پروفایل برنامه‌ها و storage آن را پاک می‌کند. Shelter و Insular برای پروفایل مدیریت‌شده مفیدند، اما وجود کاربر جداگانهٔ Android را پنهان نمی‌کنند.

### با روت

spoof کردن user ID، مسیر `/data/user/<id>` یا پاسخ‌های `DevicePolicyManager` با روت وضعیت ناسازگار می‌سازد و ممکن است پروفایل را خراب کند. اجرای برنامه زیر کاربر درست امن‌تر از mask کردن پروفایل است. هوک‌های درون فرایند هدف برای یک بررسی می‌توانند علاوه بر آن `HOOK_MARKERS`، `RWX_MEMORY_REGIONS` و `LIBRARY_INTEGRITY` را فعال کنند.

### روش راستی‌آزمایی نتیجه

```bash
adb shell pm list users
adb shell am get-current-user
adb shell dumpsys user | head -160
```
user ID را با مسیر `dataDir` در detail مقایسه کنید.

پس از هر تغییر، RKNHardering و سرویس‌گیرندهٔ VPN را به‌اجبار متوقف کنید، هر دو را دوباره اجرا کنید و اسکن کامل را تکرار کنید. Zygisk، Xposed و ماژول‌های هسته معمولاً به راه‌اندازی مجدد دستگاه نیاز دارند. فقط همین خط را مقایسه نکنید؛ سیگنال‌های مجاور را نیز بررسی کنید، زیرا یک هوک ناقص اغلب میان APIها ناسازگاری ایجاد می‌کند.

## مجوزهای لازم و خطرها

خود پروب با مجوزهای معمول برنامه اجرا می‌شود و روت درخواست نمی‌کند. دستورهای ADB زیر فقط برای جهت‌یابی تشخیصی‌اند: `adb shell` با UID دیگری اجرا می‌شود و ممکن است نسبت به فرایند برنامه اطلاعات بیشتر یا کمتری ببیند. آزمون تعیین‌کننده، اجرای دوبارهٔ بررسی درون برنامه پس از توقف اجباری است.

### خطرها

حذف پروفایل برنامه‌ها و داده‌هایش را پاک می‌کند. پیش از آزمایش داده را export کنید.

### بازگردانی

پروفایل را از جریان عادی DPC یا Settings دوباره بسازید و داده را از backup بازیابی کنید.

## سطح شواهد

**سرویسی.** `evaluateIsolation()` و نبود انتساب مستقیم شناسهٔ چتری بررسی شده‌اند.

وضعیت یک راهکار شخص ثالث خودبه‌خود به این دستگاه تعمیم پیدا نمی‌کند. ادعای سازندهٔ ماژول فقط فرضیهٔ آغازین است؛ تأیید واقعی به نتیجه‌ای تکرارپذیر از RKNHardering روی همان نسخهٔ Android، میان‌افزار و هسته نیاز دارد.

## منابع و تاریخ آخرین راستی‌آزمایی

- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignsChecker.kt` — منطق اصلی حکم بومی/قدیمی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalCatalog.kt` — نگاشت دسته، slug و خط خروجی](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- راستی‌آزمایی‌شده با کد پروژه: [`NativeSignalId.kt` — رجیستری کامل شناسه‌ها](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- راستی‌آزمایی‌شده با کد پروژه: [آزمون‌های واحد کاتالوگ/بررسی‌کنندهٔ بومی](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [پروفایل‌های مدیریت‌شده در AOSP](https://source.android.com/docs/devices/admin/managed-profiles).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [AOSP Private Space](https://source.android.com/docs/security/features/private-space).
- مستندات اولیهٔ خارجی یا پروژهٔ رسمی: [Application Sandbox](https://source.android.com/docs/security/app-sandbox).
- آخرین بررسی پیاده‌سازی و پیوندها: **19 ژوئیهٔ 2026**.

سیگنال‌های مرتبط: `isolation-clone`, `isolation-secondary-user`, `isolation-work-profile`.

[بازگشت به مرجع بررسی‌های بومی](../)
