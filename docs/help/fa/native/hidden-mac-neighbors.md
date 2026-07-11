---
title: "سیگنال بومی: hidden-mac-neighbors"
permalink: /help/fa/native/hidden-mac-neighbors/
---

# سیگنال بومی: hidden-mac-neighbors

## چه چیزی و چرا بررسی می‌شود

RKNHardering بردار پایدار `hidden-mac-neighbors` را با مقایسهٔ وضعیت قابل‌مشاهدهٔ هسته، فرایند، رابط، مسیر، ویژگی، فایل یا سوکت با رفتار مورد انتظار Android بررسی می‌کند.

## نتیجه چه معنایی دارد

Detected یا review یعنی این بردار داده‌ای برای بررسی داده است. clean یا unavailable فقط همین بردار را توصیف می‌کند و نبود VPN یا تغییرات را ثابت نمی‌کند.

## محدودیت‌ها و مثبت کاذب احتمالی

سازنده، نسخهٔ Android، SELinux، وضعیت گذرای شبکه و نمایهٔ کاری می‌توانند نتیجه را تغییر دهند. هر خط را همراه دسته و حکم نهایی ارزیابی کنید.

## توصیه‌های همین بردار

نام، نوع، MTU و نشانی رابط را با اجرای پاک همان دستگاه مقایسه کنید. گزارش جامعه در issue #48 دربارهٔ TUN/MTU تضمین نیست.

## مجوزهای لازم و خطرها

خود بررسی مجوز اضافه نمی‌خواهد. تغییرات روت، هسته، hook، firewall یا profile خطر بیشتری از تشخیص دارند.

## سطح شواهد

**بررسی‌شده توسط پروژه:** بردار در RKNHardering پیاده‌سازی و با آزمون‌های checker/catalog پوشش داده شده است. ادعاهای بیرونی و گزارش جامعه تضمین نیستند.

## منابع و تاریخ آخرین بررسی

- Community reported / сообщено сообществом: [issue #48](https://github.com/xtclovver/RKNHardering/issues/48) and [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense).
- Project verified / проверено проектом: RKNHardering source and tests.
- Last verified / последняя проверка / آخرین بررسی / 最后核验: 2026-07-11.

[بازگشت به راهنمای نشانه‌های بومی](../)
