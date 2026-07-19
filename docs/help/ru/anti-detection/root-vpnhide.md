---
title: Root-стек — VPNHide, VPNHide Next, Vector, Magisk, KernelSU и APatch
permalink: /help/ru/anti-detection/root-vpnhide/
---

# Root-стек — VPNHide, VPNHide Next, Vector, Magisk, KernelSU и APatch

Эта страница описывает установочную архитектуру, а не обещает «одну кнопку». Любой kernel/boot модуль способен вызвать bootloop, kernel panic, потерю сети или несовместимость после OTA. Перед началом сохраните стоковый образ нужного раздела и убедитесь, что умеете загрузиться в bootloader/recovery и отключить модуль. Разблокировка bootloader на большинстве устройств стирает пользовательские данные.

## Без root

У VPNHide/VPNHide Next нет полноценного non-root режима: их задача требует вмешательства в `system_server`, ядро или процесс zygote. APK без root может быть только интерфейсом, диагностикой или конфигуратором; он не получает права фильтровать Binder/netlink для чужого UID.

Non-root эквивалент по результату — внешний роутер/шлюз. Он не «подменяет» ответы, а устраняет сам локальный VPN с телефона. Второе пространство и repack/rootless Xposed не дают сопоставимого покрытия и добавляют isolation/integrity сигналы.

## С root: выбор основы

| Основа | Сильная сторона | Основной риск/ограничение | Официальная загрузка |
|---|---|---|---|
| Magisk | Наиболее распространённый root, модули, встроенный Zygisk | Root/userspace следы, boot image зависит от устройства | [Magisk releases](https://github.com/topjohnwu/Magisk/releases/latest), [официальная установка](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md) |
| KernelSU Next | Kernel-based `su`, App Profile, module mount | Требуется совместимое ядро/LKM; версия manager и kernel должны совпадать | [KernelSU Next releases](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest), [документация](https://kernelsu-next.github.io/webpage/) |
| APatch | KernelPatch runtime, подходит KPM-сценариям | Патчит `boot.img`, только ARM64; неправильный образ/ключ опасны | [APatch releases](https://github.com/bmax121/APatch/releases/latest), [русская инструкция](https://apatch.dev/ru/install.html) |

Не переносите команды прошивки между устройствами. У Magisk раздел может быть `boot` или `init_boot`, а APatch в своей документации требует именно `boot.img`. Используйте инструкцию выбранного проекта и заводской образ именно вашей сборки.

### Проверка APK/ZIP до установки

Скачанный kernel/root-модуль нельзя считать безопасным только потому, что имя похоже на официальный release. Сначала сохраните URL страницы release и локально посчитайте хэш:

```bash
sha256sum vpnhide*.zip *.apk
unzip -l vpnhide*.zip | sed -n '1,120p'
unzip -p vpnhide*.zip module.prop 2>/dev/null
```

Для APK используйте `apksigner` из Android SDK Build-Tools:

```bash
apksigner verify --verbose --print-certs vpnhide.apk
```

Сравнивайте SHA-256 только с хэшем, опубликованным самим проектом. Хэш из случайного сообщения рядом с тем же файлом не является независимой проверкой. Не устанавливайте ZIP, который просит SuperKey, VPN-подписку или иной секрет через сторонний сайт/бот. Просмотр `unzip -l` не доказывает безопасность скриптов, но позволяет вовремя заметить неожиданный boot image, бинарники или посторонний установщик.

## Выбор framework: Vector или старый LSPosed

Оригинальный [LSPosed/LSPosed](https://github.com/LSPosed/LSPosed) архивирован 2 мая 2026 года и заявлял поддержку Android 8.1–14. Для современных устройств разумнее начинать с [JingMatrix/Vector](https://github.com/JingMatrix/Vector/releases/latest), который заявляет Android 8.1–17 Beta и совместимость Xposed API.

VPNHide требует от framework только системный scope. После установки:

1. Включите модуль VPNHide/VPNHide Next.
2. Выберите **только `System Framework`**.
3. Не добавляйте `com.notcvnt.rknhardering` в scope.
4. Перезагрузите устройство, потому что `system_server` должен стартовать уже с активным модулем.

Если конкретная версия VPNHide документированно требует LSPosed, а не Vector, используйте совместимую связку из её release notes. Не смешивайте два Xposed framework одновременно.

## VPNHide upstream: рекомендуемая стабильная схема

Исходник и загрузка: [okhsunrog/vpnhide](https://github.com/okhsunrog/vpnhide), [последний release](https://github.com/okhsunrog/vpnhide/releases/latest), [карта векторов](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).

Архитектура:

- APK VPNHide — конфигурация целей;
- Vector/LSPosed в `System Framework` — Java/Binder и PackageManager;
- **ровно один** native-бэкенд: kmod, KPM или Zygisk;
- опциональный `portshide` — loopback.

### Как выбрать native-бэкенд

**kmod** выбирайте первым на поддерживаемом GKI. Он работает в ядре, не трогает память RKNHardering и не обходится raw syscall. VPNHide публикует сборки по поколению KMI, например `android14-6.1`; это поколение ядра, а не обязательно версия Android.

**KPM** нужен для старых/non-GKI ядер или когда `.ko` не загружается. Он требует KernelPatch runtime: APatch либо KPatch-Next-Module. Это beta-путь с меньшим объёмом полевых тестов.

**Zygisk** — fallback. Он работает на уровне libc внутри целевого процесса, поэтому RKNHardering может увидеть `maps`, RWX/linker/hook расхождения, а raw syscall способен пройти мимо фильтра. Не называйте его эквивалентом kernel-бэкенда.

**Никогда не ставьте kmod и KPM одновременно.** Они могут хукать одни и те же функции ядра. Результат — зависание, kernel panic или bootloop. Если в системе осталось несколько backend ZIP, удалите лишние и убедитесь, что активен один.

### Установка upstream

1. Скачайте APK и рекомендованный module ZIP только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). Сверьте имя файла и SHA-256, если автор опубликовал checksum.
2. Установите APK обычным способом.
3. В Vector/LSPosed активируйте модуль и scope `System Framework`, затем перезагрузитесь.
4. Выдайте root только приложению-конфигуратору VPNHide, не RKNHardering.
5. На вкладке обзора выберите рекомендованный native backend и установите **один** ZIP через ваш root manager.
6. При необходимости установите отдельный Ports-модуль.
7. После перезагрузки выберите `com.notcvnt.rknhardering` как цель Java/Native/Ports и observer для Apps, затем сохраните.
8. Force-stop RKNHardering и выполните две проверки.

Для актуальных версий пользовательская конфигурация upstream хранится в `/data/system/vpnhide_config.json`. Ручное редактирование допускается только после резервной копии и проверки JSON; `invalid config` означает ошибку синтаксиса или схемы. Обычно безопаснее использовать UI.

Read-only проверка:

```bash
adb shell uname -r
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell su -c 'ls -la /data/adb/modules | grep -i vpnhide'
adb shell su -c 'cat /data/system/vpnhide_config.json'
adb logcat -d | grep -iE 'VpnHide|Vector|LSPosed'
```

## VPNHide Next: расширенное экспериментальное покрытие

Исходник и загрузка: [soranerai/vpnhide_next](https://github.com/soranerai/vpnhide_next), [последний release](https://github.com/soranerai/vpnhide_next/releases/latest).

Заявлено внешним проектом: форк добавляет kernel-блокировку портов, MTU/MSS/TCP_INFO, GSO/PMTU, eBPF traffic stats, qdisc, UDP timing, IPv6 link-local и более полное proc/sysfs сокрытие. Режимы `Мин`, `Сред`, `Макс` переключают объём хуков. README проекта прямо предупреждает, что стабильность на всех ядрах не гарантируется и возможны bootloop/kernel panic.

Практический выбор:

- `Мин` — сначала для проверки базовых `ioctl/getifaddrs/netlink/routes`;
- `Сред` — если RKNHardering продолжает видеть socket/MTU/MSS/PMTU признаки;
- `Макс` — только в лаборатории с рабочим recovery, когда конкретные proc/sysfs/BPF/qdisc/timing строки подтверждены.

Не включайте `Макс` «на всякий случай». Чем больше kernel hooks, тем выше риск несовместимости и тем сложнее понять причину регрессии.

VPNHide Next LSPosed-модуль также должен работать через `System Framework`, без присутствия в процессе цели. Его kmod README описывает `dev_ioctl`, `sock_ioctl`, `rtnl_fill_ifinfo`, IPv4/IPv6 address netlink и `/proc/net/route` как базовые hook points. Сохраняйте точную версию APK и ZIP одной сборки: несовпадение control protocol способно дать частичную работу.

### Пошаговый старт VPNHide Next

1. Скачайте APK и kernel module только из [официального release](https://github.com/soranerai/vpnhide_next/releases/latest). Не берите kmod от upstream VPNHide: это другой проект и другой control protocol.
2. Запишите `uname -r`, Android build и название скачанного asset. Если release не заявляет совместимость с вашим ядром, не прошивайте его «для проверки» на основном устройстве.
3. Установите APK, включите его в Vector/LSPosed и оставьте в scope только `System Framework`; перезагрузитесь.
4. Установите ровно один kernel ZIP VPNHide Next через поддерживаемый root manager и снова перезагрузитесь.
5. В приложении выберите UID/копию `com.notcvnt.rknhardering`, начните с режима `Мин` и сохраните конфигурацию.
6. Выполните два одинаковых прогона. Переходите на `Сред`, а затем на `Макс` только когда конкретная строка MTU/MSS/PMTU/BPF/qdisc/proc/sysfs остаётся положительной.

README верхнего уровня описывает новое control device `/dev/vpnhide_ctrl`, тогда как отдельные README/старые сборки могут ещё упоминать `/proc/vpnhide_targets` и `targets.txt`. Это признак различий между ревизиями документации, а не повод создавать отсутствующий файл вручную. Для диагностики используйте UI конкретного release и read-only проверку:

```bash
adb shell su -c 'cat /proc/modules | grep -i vpnhide'
adb shell su -c 'ls -l /dev/vpnhide_ctrl /proc/vpnhide_targets 2>/dev/null'
adb logcat -d | grep -iE 'VPNHide Next|VpnHide|Vector|LSPosed'
```

`no such file or directory` означает, что путь отсутствует или эта ревизия использует другой интерфейс. Если модуль не виден в `/proc/modules`, а UI сообщает о рабочем native-слое, сначала сверяйтесь с архитектурой конкретного release: KPM/встроенный kernel patch не обязан выглядеть как обычный LKM.

## Zygisk Next и root-hiding — отдельная задача

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) нужен KernelSU/APatch для Zygisk API или может заменять встроенный Magisk Zygisk. Его современный linker/anonymous memory режим заявлен как уменьшение следов, но совместимость модулей не гарантируется. Он не превращает process-local VPNHide backend в kernel-level фильтр.

Root hiding рассматривается отдельно в [разделе о целостности](../root-integrity/). Сначала добейтесь правильной работы VPNHide, затем минимизируйте root surface. Одновременная установка нескольких hide-модулей затрудняет диагностику и может создавать новые mount/linker сигналы.

## Проверка по слоям

После установки не смотрите только на зелёный статус VPNHide.

**Framework:** в RKNHardering должны исчезнуть `DIRECT_NETWORK_CAPABILITIES`, `INDIRECT_NETWORK_CAPABILITIES`, VPN interface name/routes из `LinkProperties`.

**Native:** должны исчезнуть `INTERFACE_ENUMERATION`, `TUNTAP_TYPE`, `GETIFADDRS_VPN`, `RTM_GETLINK_VPN`, route/ifindex признаки. Если Java чистый, а native остаётся — проблема native backend, не LSPosed.

**Ports:** loopback скан не должен подтверждать SOCKS/HTTP/Xray/Clash API. Если порт открыт для shell, но недоступен UID цели, это ожидаемо.

**Integrity:** не должны появиться новые `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `LIBRARY_INTEGRITY`, `LSPOSED` или β hook-consistency сигналы. Если они появились, проверьте scope и откажитесь от process-local backend.

## Риски и откат

Перед каждым kernel/module изменением сохраните:

- стоковый boot/init_boot по официальной инструкции вашего root-решения;
- текущий рабочий patched image;
- список `/data/adb/modules` и версии APK/ZIP;
- конфиг VPNHide;
- способ войти в recovery/bootloader без загруженной Android.

Откат выполняйте последовательно: отключите последний модуль в manager/safe mode, перезагрузитесь, проверьте сеть, затем удаляйте. Не удаляйте несколько компонентов сразу: иначе причина останется неизвестной. При bootloop используйте официальный rescue-механизм вашего root manager или восстановите сохранённый стоковый образ по инструкции устройства. Не импровизируйте с разделами.

[Назад к оглавлению](../)
