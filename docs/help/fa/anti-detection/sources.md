---
title: منابع، دریافت‌ها و وضعیت ادعاها
permalink: /help/fa/anti-detection/sources/
---

# منابع، دریافت‌ها و وضعیت ادعاها

پیوندهای اصلی و وضعیت فعلی پروژه‌ها آخرین بار در **۱۹ ژوئیهٔ ۲۰۲۶** دستی بررسی شدند. همیشه از `releases/latest` در مخزن رسمی دریافت کنید و از APK یا ZIP بسته‌بندی‌شدهٔ مجدد در chatها استفاده نکنید. وقتی پروژه checksum مربوط به SHA-256 یا امضا منتشر می‌کند، پیش از نصب آن را بررسی کنید.

## RKNHardering — راستی‌آزمایی‌شده در پروژه

- [پروژهٔ اصلی RKNHardering](https://github.com/xtclovver/RKNHardering)
- [معماری و بررسی‌های فعلی در README](https://github.com/xtclovver/RKNHardering/blob/main/README.md)
- منابع محلی در این نسخه: `DirectSignsChecker`، `IndirectSignsChecker`، `BypassChecker`، `NativeSignsChecker`، `VpnNativeDetectorChecker`، `BetaCheckRegistry`، `BetaEvidencePolicy`، `VerdictEngine`، `NativeSignalId` و `EvidenceSource`.
- [یادداشت پژوهشی دربارهٔ بررسی‌های β](https://github.com/xtclovver/RKNHardering/blob/main/docs/beta-checks-research.md)

همهٔ شمارش‌ها و شناسه‌های دقیق این راهنما از کد محلی استخراج شده‌اند، نه از فهرست شخص ثالث.

## Android و AOSP — محدودیت‌های معماری

- [`VpnService`](https://developer.android.com/reference/android/net/VpnService) — ساخت رابط مجازی، `protect()` و شبکه‌های زیرین.
- [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder) — برنامه‌های مجاز و غیرمجاز، routeها، DNS، MTU و پیکربندی proxy.
- [فیلتر دید بسته‌ها](https://developer.android.com/training/package-visibility) — محدودیت‌های Android 11 و جدیدتر برای مشاهدهٔ بسته‌ها.
- [Work profile در AOSP](https://source.android.com/docs/devices/admin/managed-profiles) — شناسهٔ کاربر، UID و دادهٔ پروفایل جداگانه.
- [Private Space در AOSP](https://source.android.com/docs/security/features/private-space) — پروفایل خصوصی و حالت قفل‌شده یا متوقف.
- [Sandbox برنامه در AOSP](https://source.android.com/docs/security/app-sandbox) — جداسازی مبتنی بر UID.

## VPNHide upstream — ادعاهای بیرونی؛ روی دستگاه بررسی شوند

- [مخزن](https://github.com/okhsunrog/vpnhide)
- [آخرین release](https://github.com/okhsunrog/vpnhide/releases/latest)
- [نقشهٔ کامل بردارهای تشخیص](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)
- [README مربوط به kmod](https://github.com/okhsunrog/vpnhide/blob/main/kmod/README.md)
- [README مربوط به KPM](https://github.com/okhsunrog/vpnhide/blob/main/kmod/kpm/README.md)
- [README مربوط به Zygisk](https://github.com/okhsunrog/vpnhide/blob/main/zygisk/README.md)
- [README مربوط به LSPosed/application](https://github.com/okhsunrog/vpnhide/blob/main/lsposed/README.md)
- [README مربوط به portshide](https://github.com/okhsunrog/vpnhide/blob/main/portshide/README.md)

محدودیت‌های مهم مستندشده توسط پروژه: سیگنال‌های سمت سرور خارج از دامنهٔ آن‌اند؛ syscall خام از Zygisk عبور می‌کند؛ backendهای هسته و Zygisk نباید روی هم انباشته شوند؛ و برخی موارد procfs و parity مربوط به KPM همچنان مشروط‌اند.

## VPNHide Next — fork آزمایشی گسترده‌تر

- [مخزن](https://github.com/soranerai/vpnhide_next)
- [آخرین release](https://github.com/soranerai/vpnhide_next/releases/latest)
- [README مربوط به LSPosed/system_server](https://github.com/soranerai/vpnhide_next/blob/main/lsposed/README.md)
- [README مربوط به ماژول هسته](https://github.com/soranerai/vpnhide_next/blob/main/kmod/README.md)

پروژه پوشش تکمیلی برای MTU، MSS، `TCP_INFO`، PMTU، GSO، BPF، qdisc، timing، sysfs، procfs و بردارهای پروفایل را ادعا می‌کند. README آن جداگانه دربارهٔ ناپایداری، boot loop و kernel panic هشدار می‌دهد. این راهنما آن قابلیت‌ها را به‌عنوان ادعاهای بیرونی علامت‌گذاری می‌کند.

## روت و frameworkها

- [Magisk](https://github.com/topjohnwu/Magisk)، [releaseها](https://github.com/topjohnwu/Magisk/releases/latest)، [install.md](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md)
- [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next)، [releaseها](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest)، [مستندات](https://kernelsu-next.github.io/webpage/)
- [APatch](https://github.com/bmax121/APatch)، [releaseها](https://github.com/bmax121/APatch/releases/latest)، [راهنمای نصب روسی](https://apatch.dev/ru/install.html)
- [Vector](https://github.com/JingMatrix/Vector)، [releaseها](https://github.com/JingMatrix/Vector/releases/latest)
- [LSPosed آرشیوشده](https://github.com/LSPosed/LSPosed)
- [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext)، [releaseها](https://github.com/Dr-TSNG/ZygiskNext/releases/latest)
- [NoHello](https://github.com/MhmRdd/NoHello)، [releaseها](https://github.com/MhmRdd/NoHello/releases/latest)
- [هستهٔ SUSFS](https://gitlab.com/simonpunk/susfs4ksu)، [ماژول userspace مربوط به SUSFS](https://github.com/sidex15/susfs4ksu-module)، [releaseها](https://github.com/sidex15/susfs4ksu-module/releases/latest)
- [Hide My Applist](https://github.com/Dr-TSNG/Hide-My-Applist)، [releaseها](https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest)

NoHello، Zygisk Next، SUSFS و HMA الزامی نیستند و کارکردشان در برابر RKNHardering تضمین نمی‌شود. فقط به‌عنوان گزینه‌هایی برای پژوهش سطح روت فهرست شده‌اند. به‌ویژه HMA را با VPNHide Apps اشتباه نگیرید: HMA معمولاً در زمینهٔ برنامهٔ انتخاب‌شده عمل می‌کند، درحالی‌که VPNHide، PackageManager را از طریق `system_server` فیلتر می‌کند.

## پروفایل‌ها و cloneها

- [Shelter](https://gitea.angry.im/PeterCxy/Shelter)
- [Insular](https://gitlab.com/secure-system/Insular)
- [managed profile در AOSP](https://source.android.com/docs/devices/admin/managed-profiles)
- [Private Space در AOSP](https://source.android.com/docs/security/features/private-space)

حذف پروفایل داده‌های آن را پاک می‌کند. پیش از آزمایش نسخهٔ پشتیبان جداگانه بگیرید.

## سرویس‌گیرنده‌های VPN و مسیریابی

- [sing-box برای Android](https://sing-box.sagernet.org/clients/android/)
- [قواعد route در sing-box](https://sing-box.sagernet.org/configuration/route/rule/)
- [DNS در sing-box](https://sing-box.sagernet.org/configuration/dns/)
- [پیکربندی عمومی Mihomo](https://wiki.metacubex.one/en/config/general/)
- [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense)
- [راهنمای جامعه برای Sub-Store](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md)
- [راهنمای جامعه برای S-UI](https://github.com/jinndi/RKNHardering-defense/blob/main/S-UI.md)

مواد `RKNHardering-defense` به‌عنوان گزارش‌های جامعه علامت‌گذاری شده‌اند. نمونه‌های مفیدی برای split routing و دروازهٔ خارجی‌اند، اما پنهان‌شدن همهٔ بردارهای محلی و β در نسخهٔ 2.10.0 را ثابت نمی‌کنند.

## چرا این راهنما به «APKهای universal bypass» تصادفی پیوند نمی‌دهد

برنامه‌ای که بدون دلیل روشن غیرفعال‌کردن Play Protect، اعطای Accessibility یا Device Admin، بارگذاری SuperKey، واردکردن اشتراک خصوصی یا نصب ZIP هستهٔ بدون امضا را می‌خواهد، خطر نامتناسبی ایجاد می‌کند. منبع، تاریخچهٔ مخزن، امضا یا hash مربوط به release و مجوزهای درخواستی را بررسی کنید. کلیدهای روت، اسرار VPN یا logهای دارای token را هرگز به سازندگان buildهای تأییدنشده ندهید.

[بازگشت به فهرست مطالب](../)
