---
title: مسیر شبکه — GeoIP، DNS، CDN، STUN و تماس‌ها
permalink: /help/fa/anti-detection/network-path/
---

# مسیر شبکه — GeoIP، DNS، CDN، STUN و تماس‌ها

این بخش حتی با پیکربندی بی‌نقص VPNHide اهمیت دارد. هوک‌های هسته و framework می‌توانند پاسخ‌های محلی Android را تغییر دهند، اما سرورهای دور همچنان نشانی واقعی، ASN، تأخیر و دردسترس‌بودن transport را می‌بینند.

## RKNHardering چه چیزی را بررسی می‌کند

**بررسی‌شده در پروژه:** لایهٔ شبکه شامل `GEO_IP`، اجماع IP میان سرویس‌های روسی و غیرروسی، مقایسهٔ DNS، `CdnPullingChecker`، STUN، transport تماس Telegram و WhatsApp، پروب‌های شبکهٔ underlying، مثلث‌بندی RTT، جعل ICMP و دردسترس‌بودن دامنه‌ها است. بعضی نتایج صرفاً تشخیصی‌اند، اما اختلاف میان کانال‌های مستقل می‌تواند در حکم نهایی `DETECTED` نقش داشته باشد.

نشانگرهای اصلی عبارت‌اند از:

- کشور خارجی، طبقه‌بندی hosting/datacenter یا تشخیص proxy/VPN برای IP عمومی؛
- گزارش IPهای معیار متفاوت از سوی گروه‌های روسی و غیرروسی؛
- مسیرهای متفاوت IPv4 و IPv6؛
- resolve متفاوت DNS روی VPN و شبکهٔ underlying؛
- مشاهدهٔ مسیری متفاوت توسط CDN یا redirector؛
- آشکارشدن خروجی UDP جداگانه توسط STUN؛
- حضور فیزیکی دستگاه در روسیه همراه با خروجی شبکهٔ خارجی، یا برعکس؛
- بازگرداندن نشانی متفاوت از اتصالی که به شبکهٔ underlying bind شده است؛
- گزارش IP عمومی متفاوت از سوی proxy محلی نسبت به مسیر مستقیم.

## بدون روت

### گزینهٔ A: روتر خارجی یا دروازهٔ اختصاصی

این پاک‌ترین آرایش بدون روت است. VPN یا proxy روی روتر اجرا می‌شود و تلفن به یک شبکهٔ عادی Wi‑Fi متصل است. Android هیچ `VpnService` محلی یا اثر TUN ندارد. در نتیجه RKNHardering فقط مسیر خارجی شبکه را می‌بیند و همان مسیر باید از درون سازگار باشد.

**گزارش‌شده توسط جامعه:** پروژهٔ [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense) پیکربندی‌هایی برای روتر ارائه می‌کند و جداگانه هشدار می‌دهد که TUN در سطح روتر به‌تنهایی مسئلهٔ CDN pulling را حل نمی‌کند. مواد آمادهٔ آن شامل [Sub-Store](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md) و [S-UI](https://github.com/jinndi/RKNHardering-defense/blob/main/S-UI.md) است. آن‌ها را نمونهٔ مسیریابی بدانید، نه اثبات عبور نسخهٔ فعلی برنامه.

در عمل سه مورد را بررسی کنید: HTTP(S)، DNS و UDP باید از همان مسیر موردانتظار خارج شوند؛ IPv6 باید به همان شکل پیکربندی یا برای پروفایل آزمایشگاهی مشخص عمداً غیرفعال شود؛ و تلفن نباید مسیر پشتیبان موبایل را حفظ کند که ناگهان به شبکهٔ underlying تبدیل شود.

### گزینهٔ B: split tunneling به‌ازای برنامه

Android به‌طور رسمی allowlist و denylist برنامه‌ها را از طریق `VpnService.Builder.addAllowedApplication()` و `addDisallowedApplication()` پشتیبانی می‌کند. در sing-box برای Android می‌توان این رفتار را از مسیر **Settings → Profile Override → Per-app Proxy** پیکربندی کرد. مستندات قاعدهٔ route: [sing-box route rule](https://sing-box.sagernet.org/configuration/route/rule/).

ایدهٔ پایه در syntax فعلی sing-box شبیه نمونهٔ زیر است:

```json
{
  "route": {
    "rules": [
      {
        "package_name": ["com.notcvnt.rknhardering"],
        "action": "route",
        "outbound": "direct"
      }
    ]
  }
}
```

این پیکربندی کامل و آمادهٔ استفاده نیست: tag مربوط به `direct`، قواعد DNS و نسخهٔ schema باید با نصب شما هماهنگ باشند. پیش از جایگزینی پروفایل سالم، پیکربندی را با بررسی‌کنندهٔ داخلی سرویس‌گیرنده اعتبارسنجی و نسخهٔ پشتیبان نگه دارید.

**محدودیت:** `TUN_ACTIVE_PROBE` فعلی عمداً وضعیتی را تشخیص می‌دهد که رابط TUN وجود دارد اما `vpnActive` برای RKNHardering برابر false است. بنابراین bypass به‌ازای برنامه ممکن است IP خارجی را حذف کند و هم‌زمان تأیید کند که package صریحاً مستثنا شده است. برای نتیجهٔ پاک بدون روت، معمولاً این روش با دروازهٔ خارجی همراه می‌شود، نه با `VpnService` محلی.

### DNS باید همان مسیر را دنبال کند

HTTP را مستقیم رها نکنید درحالی‌که DNS از VPN عبور می‌کند، یا برعکس. RKNHardering رفتار resolve را با نتایج شبکه مقایسه می‌کند. برای برنامهٔ مستثناشده، از DNS شبکهٔ underlying یا resolver جداگانه‌ای استفاده کنید که از همان outbound خارج می‌شود. فقط برای مسیریابی DNS، proxy سیستمی HTTP تنظیم نکنید؛ این کار سیگنال مستقل `SYSTEM_PROXY` می‌سازد.

در پیکربندی sing-box، قاعدهٔ DNS باید از قاعدهٔ ترافیک جدا باشد، اما هر دو باید به مسیر موردنظر یکسان برسند. نمونهٔ بزرگ جامعه در [SUB-STORE.md](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md) موجود است؛ آن را بدون بررسی tagها، rule setها و packageهای مورداعتماد خودتان کامل کپی نکنید.

### STUN، تماس‌ها و UDP

ممکن است proxy فقط-TCP روی HTTP پاک به‌نظر برسد، درحالی‌که UDP و STUN مستقیم خارج می‌شوند. اصلاح را بر اساس رفتار موردنظر انتخاب کنید:

- وقتی برنامه باید از مسیر مستقیم استفاده کند، HTTP، DNS و UDP همگی باید مستقیم باشند؛
- وقتی یک خروجی proxy یا VPN لازم است، سرویس‌گیرنده باید واقعاً UDP را پشتیبانی کند و بی‌صدا به مسیر مستقیم fallback نکند؛
- مسدودکردن STUN پاسخ را حذف می‌کند، اما «بدون پاسخ» همیشه معادل نتیجهٔ پاک نیست: RKNHardering می‌تواند `unsupported`، `no signal` یا وضعیت بازبینی گزارش کند؛
- مسدودکردن endpointهای تماس ممکن است Telegram یا WhatsApp را خراب کند. این کار را فقط در پروفایل آزمایشی با روند بازگردانی روشن انجام دهید.

### موقعیت جغرافیایی و roaming

جعل GPS را راهبرد اصلی در نظر نگیرید. بررسی از MCC/MNC، SIM، زمینهٔ سلولی و Wi‑Fi و داده‌های سمت سرور استفاده می‌کند؛ جعل ناسازگار تناقض‌های بیشتری می‌سازد. پیکربندی سالم باید جفت موقعیت–خروجی مشاهده‌شده را توضیح دهد. roaming با مسیریابی از کشور مبدأ می‌تواند مشروع باشد و کد زمینهٔ جداگانهٔ `HOME_ROUTED_ROAMING` را حفظ می‌کند.

## با روت

روت جای مراحل بالا را نمی‌گیرد. فقط پس از سازگارشدن مسیر شبکه می‌تواند واقعیت محلی وجود VPN را پنهان کند.

توالی عملی:

1. مسیریابی package را در سرویس‌گیرندهٔ VPN یا دروازه پیکربندی کنید.
2. HTTP، DNS و UDP را از همان خروجی موردنظر عبور دهید.
3. نشانگرهای Binder و بومی را با VPNHide یا VPNHide Next ببندید.
4. دسترسی UID هدف به APIهای کنترل localhost را مسدود کنید.
5. تأیید کنید اثر روت یا هوک به علت تازه‌ای برای بازبینی تبدیل نشده است.

وقتی قرار است RKNHardering مستقیم خارج شود، پنهان‌سازی هسته یا framework دقیقاً به این دلیل لازم است که TUN محلی همچنان وجود دارد. وقتی قرار است RKNHardering داخل تونل بماند، محدودیت معماری VPNHide اصلی را در نظر بگیرید: جایگزینی شبکهٔ فعال VPN با شبکهٔ فیزیکی در split tunneling منسجم‌تر است. خود پروژه صریحاً سیگنال‌های سمت سرور را خارج از دامنهٔ پنهان‌سازی محلی می‌داند. [VPNHide detection vectors](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) را ببینید.

برای localhost، بهترین گزینه این است که API اصلاً expose نشود. وقتی برنامه‌ای دیگر به آن نیاز دارد، `portshide` در VPNHide یا مسدودسازی هسته‌ای VPNHide Next باید روی UID مربوط به RKNHardering اعمال شود. گذرواژهٔ Clash API برای امنیت مفید است، اما درگاه باز یا خود پروتکل را پنهان نمی‌کند؛ RKNHardering loopback و endpointهای شناخته‌شدهٔ REST را اسکن می‌کند.

## پیکربندی صفحهٔ کنترل

`external-controller` در Mihomo/Clash و APIهای sing-box/Xray نباید بدون نیاز مشخص روی `0.0.0.0` گوش دهند. برای تلفن آزمایشگاهی، گزینه‌های امن‌تر عبارت‌اند از:

- controller یا API را غیرفعال کنید؛
- اگر هم سرویس‌گیرنده و هم panel پشتیبانی می‌کنند، آن را به Unix socket متصل کنید؛
- روی loopback با secret قوی نگه دارید و علاوه بر آن، دسترسی UID هدف را در سطح روت مسدود کنید؛
- جابه‌جایی از درگاه‌های رایج مانند `9090`، `9091`، `9097` یا `19090` را تنها لایهٔ محافظت ندانید: تغییر درگاه مانع اسکن کامل نمی‌شود.

مستندات رسمی Mihomo: [general configuration](https://wiki.metacubex.one/en/config/general/). مستندات رسمی sing-box: [configuration](https://sing-box.sagernet.org/configuration/).

## راستی‌آزمایی نتیجه

ابتدا بدون فرمان‌های مختص روت، خط مبنای شبکه را ثبت کنید:

```bash
adb shell dumpsys connectivity
adb shell ip addr
adb shell ip route
adb shell ip rule
adb shell settings get global http_proxy
adb shell pm list users
```

در Android ممکن است SELinux بخش‌هایی از `/proc` را محدود کند؛ `permission denied` یعنی مجوز کافی نیست، نه اینکه route یا socket وجود ندارد. فقط برای تشخیص، SELinux را permissive نکنید: امنیت را تضعیف می‌کند و سیگنال مستقیم `ROOT_SELINUX` می‌سازد.

پس از تغییر، برنامه را دوباره اجرا کنید:

```bash
adb shell am force-stop com.notcvnt.rknhardering
adb shell monkey -p com.notcvnt.rknhardering 1
```

دست‌کم دو بررسی روی همان شبکه انجام دهید. سپس جابه‌جایی Wi‑Fi و دادهٔ موبایل را جداگانه تکرار کنید: تغییر epoch شبکه باید علت تغییر نتیجه باشد و نباید با «موفقیت تصادفی» اشتباه گرفته شود.

## سیگنال‌های باقی‌مانده

حتی با IP عمومی درست، طبقه‌بندی hosting یا proxy، ASN مربوط به datacenter، RTT، رفتار CDN و fingerprint سمت سرور ممکن است باقی بمانند. حتی پشت روتر خارجی، RKNHardering می‌تواند به‌درستی خروجی خارجی را مشاهده کند. برعکس، پنهان‌سازی محلی split DNS یا نشت IPv6 را اصلاح نمی‌کند.

[بازگشت به فهرست](../)
