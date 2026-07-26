---
title: کاربران ثانویه، Work Profile، Private Space و نسخه‌های clone برنامه
permalink: /help/fa/anti-detection/profiles/
---

# کاربران ثانویه، Work Profile، Private Space و نسخه‌های clone برنامه

پروفایل داده‌ها و packageها را به‌خوبی جدا می‌کند، اما برای پنهان‌کردن اصل وجود جداسازی مناسب نیست. Android یک work profile را به‌صورت کاربری جدا پیاده‌سازی می‌کند: UID با فرمول `100000 * userId + appId` محاسبه می‌شود، داده‌ها جداگانه ذخیره می‌شوند و APIهای سیستم کاربر و پروفایل فعلی را می‌شناسند. RKNHardering این وضعیت را صریحاً بررسی می‌کند.

منابع رسمی: [AOSP Work profiles](https://source.android.com/docs/devices/admin/managed-profiles) و [AOSP Private space](https://source.android.com/docs/security/features/private-space).

## RKNHardering چه مواردی را از هم تفکیک می‌کند

سیگنال‌های بومی پایدار:

- `ISOLATION_PROFILE` — زمینهٔ عمومی پروفایل؛
- `ISOLATION_CLONE` — بازه‌های شاخص کاربر clone، از جمله شناسه‌های شبیه MIUI؛
- `ISOLATION_SECONDARY_USER` — هر `userId > 0`؛
- `ISOLATION_WORK_PROFILE` — نشانگرهای managed profile یا profile owner.

لایهٔ β همچنین `beta.user_profile`، `beta.foreground_user`، هویت فرایند/filesystem/namespace مربوط به sandbox و هویت fscrypt را اضافه می‌کند. هرکدام به‌تنهایی معمولاً به بازبینی منتهی می‌شوند، اما ترکیب پروفایل با اختلاف مستقل شبکه می‌تواند quorumِ β بسازد.

## بدون روت

### Work profileها: Shelter و Insular

[Shelter](https://gitea.angry.im/PeterCxy/Shelter) و [Insular](https://gitlab.com/secure-system/Insular) از سازوکار رسمی managed profile استفاده می‌کنند. آن‌ها می‌توانند:

- نسخه‌ای جدا از RKNHardering یا سرویس‌گیرندهٔ VPN نصب کنند؛
- داده‌ها و حساب‌های برنامه را جدا کنند؛
- packageهایی را که فقط در پروفایلی دیگر نصب شده‌اند از برنامه پنهان کنند؛
- روی ROMهای پشتیبانی‌شده تنظیمات VPN جداگانه به‌ازای پروفایل بدهند.

بااین‌حال شبکه و هستهٔ دستگاه مشترک می‌ماند و شناسهٔ کاربر قابل مشاهده است. بنابراین پروفایل برای آرایش مشخص دیده‌شدن packageها مفید است، اما جای پنهان‌سازی Binder یا هسته را نمی‌گیرد.

پاک‌ترین آرایش بدون روت این است که RKNHardering زیر کاربر مالک بماند و VPN به روتر خارجی منتقل شود. در این حالت نیازی به پروفایل نیست و سیگنال جداسازی نیز ساخته نمی‌شود.

وقتی RKNHardering داخل work profile اجرا می‌شود و VPN فقط در پروفایل مالک وجود دارد، برنامه ممکن است مسیر مستقیم بگیرد و packageِ VPN را نبیند. هزینهٔ این روش `userId > 0` صریح، وضعیت work profile و احتمال اختلاف میان سیاست‌های شبکه است. آن را آزمایش بدانید، نه عبور تضمین‌شده.

### Private Space در Android 15 و جدیدتر

Private Space یک پروفایل خصوصی جداگانه است. وقتی فضا قفل باشد، پروفایل متوقف و برنامه‌هایش پنهان می‌شوند؛ وقتی باز شود، یک نسخهٔ عادی و جدا از برنامه در زمینهٔ کاربری دیگر است. بررسی نمی‌تواند داخل فضای قفل‌شده اجرا شود و پس از بازکردن نیز هویت پروفایل باقی می‌ماند.

Private Space برای پنهان‌کردن برنامه‌ها از enumeration معمول packageها مؤثر است، اما مدل TUN یا شبکهٔ سیستمی را خودکار تغییر نمی‌دهد. اگر VPN در سطح دستگاه داخل پروفایل اصلی اجرا شود، برنامه‌ای در Private Space ممکن است همچنان نشانگرهای مشترک شبکه را ببیند.

### Dual Apps و Second Space سازنده‌ها

Xiaomi/MIUI، Samsung Dual Messenger، Huawei PrivateSpace و پیاده‌سازی‌های دیگر OEM از مدل‌های کاربر و پروفایل متفاوتی استفاده می‌کنند. کد بومی فعلی RKNHardering بازه‌های clone مانند user 999 و کاربران 950 تا 959 را جداگانه تشخیص می‌دهد. تغییر نام برچسب launcher یا alias بسته این واقعیت را تغییر نمی‌دهد.

### بررسی پروفایل‌ها

```bash
adb shell pm list users
adb shell am get-current-user
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell dumpsys user
```

خروجی `dumpsys user` ممکن است اطلاعات شخصی حساب یا پروفایل داشته باشد؛ آن را بدون حذف داده‌های حساس کامل منتشر نکنید. برای بررسی یک کاربر مشخص:

```bash
adb shell cmd package list packages --user 0 | grep com.notcvnt.rknhardering
```

فقط برای بررسی فقط‌خواندنی، `0` را با شناسه‌ای که `pm list users` گزارش کرده جایگزین کنید. حذف پروفایل می‌تواند همهٔ داده‌های ذخیره‌شدهٔ داخل آن را نابود کند.

## با روت

روت به‌خودی‌خود پروفایل را نامرئی نمی‌کند. فقط کمک می‌کند VPNHide به‌درستی روی UID هر نسخه از برنامه اعمال شود.

VPNHide اصلی نام packageها را از طریق `packages.list` یا `pm list packages -U` به UID resolve می‌کند؛ نسخه‌های فعلی باید user و app ID را در نظر بگیرند. VPNHide Next اعلام می‌کند work profileها را کاملاً پشتیبانی می‌کند. پس از ذخیرهٔ targetها، بررسی کنید فهرست کنترل هسته UID دقیق همان نسخه‌ای از RKNHardering را دارد که اجرا می‌شود.

نمونهٔ یافتن UID:

```bash
adb shell cmd package list packages -U --user 0 | grep com.notcvnt.rknhardering
adb shell cmd package list packages -U --user 10 | grep com.notcvnt.rknhardering
```

UID را بدون بررسی دوباره، میان نصب‌های مجدد یا ریبوت‌ها دستی کپی نکنید. app ID معمولاً پایدار است، اما بخش مربوط به پروفایل یا کاربر تفاوت دارد.

هوک framework که فقط از app ID استفاده می‌کند ممکن است روی همهٔ پروفایل‌ها اعمال شود؛ backend مبتنی بر UID کامل باید هر نسخه را جداگانه اضافه کند. README و تشخیص‌های همان نسخهٔ دقیق را دنبال کنید.

ماژول پنهان‌سازی روت نیز باید unmount را برای UID نسخهٔ داخل پروفایل انجام دهد، نه فقط نمونهٔ کاربر مالک. در غیر این صورت ممکن است برنامهٔ اصلی پاک به‌نظر برسد، اما نسخهٔ work profile همچنان `/data/adb` یا آثار mount را ببیند.

## آرایش‌های عملی

### سناریوی ۱: پیکربندی پاک بدون روت

- RKNHardering زیر کاربر مالک اجرا می‌شود.
- VPN روی روتر خارجی اجرا می‌شود.
- هیچ برنامهٔ VPN، proxy سیستمی یا controller محلی روی تلفن وجود ندارد.

این آرایش سیگنال‌های محلی و جداسازی را کمینه می‌کند. سیگنال‌های سمت سرور مانند GeoIP، CDN، DNS و RTT باقی می‌مانند.

### سناریوی ۲: جداسازی package بدون روت

- سرویس‌گیرندهٔ VPN فقط در work profile وجود دارد.
- RKNHardering فقط زیر کاربر مالک وجود دارد.
- بررسی کنید ROM، VPN را فقط روی همان پروفایل اعمال می‌کند یا روی کل دستگاه.

این روش می‌تواند دیده‌شدن package و `VpnService` محلی را از زمینهٔ مالک حذف کند، اما رفتار OEMها متفاوت است. `dumpsys connectivity` را در هر دو پروفایل ثبت و مسیر خروج را راستی‌آزمایی کنید.

### سناریوی ۳: RKNHardering داخل پروفایل

- RKNHardering در work profile، private profile یا کاربر ثانویه اجرا می‌شود.
- VPN زیر کاربر مالک یا روی روتر اجرا می‌شود.

خود پروفایل به سیگنال تبدیل می‌شود. این آرایش فقط برای مطالعهٔ حساسیت به `ISOLATION_*` و quorumِ β مفید است.

### سناریوی ۴: روت همراه با VPNHide برای چند کاربر

- target را برای هر نسخهٔ نصب‌شده به VPNHide اضافه کنید.
- دامنهٔ framework را به `System Framework` محدود کنید.
- backend هسته را طوری تنظیم کنید که UIDهای کامل را پالایش کند.
- نقش‌های Ports و Apps را جداگانه راستی‌آزمایی کنید.

این کار نمای محلی شبکه را پوشش می‌دهد، اما `ISOLATION_*` همچنان واقعیت را گزارش می‌کند. تلاش نکنید `UserManager` را سراسری خراب کنید؛ این کار می‌تواند launcher، package manager و سیاست‌های دستگاه را مختل کند.

## خطرها و بازگردانی

حذف work profile یا Private Space، برنامه‌ها، کلیدها، حساب‌ها و فایل‌های محلی داخل آن را پاک می‌کند. پیش از حذف، داده‌های لازم را از مسیرهای پشتیبانی‌شده export کنید. Shelter و Insular دستورالعمل جمع‌آوری خودشان را دارند؛ به‌جای حذف اجباری device policy controller همان دستورالعمل‌ها را دنبال کنید.

بدون نسخهٔ پشتیبان روی دستگاه اصلی با `pm create-user` یا `pm remove-user` کاربر سیستمی نسازید یا حذف نکنید. فرمان‌های این راهنما فقط برای خواندن وضعیت‌اند.

[بازگشت به فهرست](../)
