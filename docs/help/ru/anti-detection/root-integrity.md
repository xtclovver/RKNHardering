---
title: Root, хуки, эмуляторы и целостность процесса
permalink: /help/ru/anti-detection/root-integrity/
---

# Root, хуки, эмуляторы и целостность процесса

Скрыть VPN и одновременно добавить в процесс заметный Xposed/Zygisk слой — плохой обмен. RKNHardering отдельно проверяет root, mounts, SELinux, свойства, `su`, hook-маркеры, RWX, linker/library integrity, Java/native расхождения и эмулятор. Цель этого раздела — минимизировать поверхность, а не обещать недетектируемый root.

## Без root

Самая надёжная конфигурация для этих проверок — физическое устройство со стоковой enforcing-прошивкой, заблокированным после штатной установки состоянием загрузки там, где это возможно, без `su`, `/data/adb` модулей, Xposed и repacked APK.

Эмулятор не станет физическим устройством от подмены `Build.MODEL`. RKNHardering проверяет qemu properties/pipes/drivers, goldfish, BlueStacks и build-профиль. Для контрольной линии используйте реальный телефон. Эмулятор полезен для функциональных тестов, но ожидайте `NATIVE_EMULATOR`/review.

Не используйте rootless Xposed/NPatch для RKNHardering. Репаковка меняет подпись и структуру APK, а runtime injection создаёт process-local hooks. Это прямо пересекается с `LIBRARY_INTEGRITY`, `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `beta.linker_integrity` и `beta.direct_syscall_consistency`.

## С root

### Сначала уменьшите поверхность, затем добавляйте hide

1. Никогда не выдавайте root RKNHardering.
2. В root manager включите unmount/deny для целевого UID. Название функции зависит от Magisk/KernelSU/APatch.
3. Не включайте VPNHide Zygisk backend для цели, если доступен kernel backend.
4. В Vector/LSPosed scope оставьте только `System Framework`.
5. Не переводите SELinux в permissive и не делайте `/system` writable.
6. Не добавляйте случайные `resetprop` подмены. Несогласованные свойства заметнее исходного значения.
7. После каждого модуля проверяйте mount namespace, `maps` и native/library сигналы.

### Что проверяют root-сигналы

`ROOT_SU_BINARY` ищет исполняемый `su` по типовым путям. `ROOT_MANAGEMENT` — `/data/adb/magisk`, `/data/adb/modules`, KernelSU/APatch каталоги и похожие следы. `ROOT_PROPERTY` и `ROOT_MAGISK_PROPERTY` — небезопасные/характерные properties. `ROOT_SYSTEM_RW`, `ROOT_SUSPICIOUS_MOUNT`, `ROOT_OVERLAY_MOUNT` — writable system и необычные bind/overlay mounts. `ROOT_SELINUX` — permissive/отсутствие enforcing. `ROOT_UID` — UID/GID 0.

DenyList/unmount помогает только тем путям, которые действительно скрыты в mount namespace цели. Он не меняет глобальные свойства ядра, не исправляет SELinux и не убирает process-local Zygisk код.

### Magisk

Скачивайте только из [официального репозитория](https://github.com/topjohnwu/Magisk/releases/latest). Встроенная DenyList и Zygisk менялись между версиями; сверяйтесь с release notes. Для RKNHardering логика проста: цель не должна получать root и не должна видеть module mounts. Если VPNHide работает kernel+system_server, target process можно держать без Zygisk-инъекции.

### KernelSU Next

App Profile позволяет ограничить root для каждого приложения и выполнить unmount module changes. Официальные источники: [репозиторий](https://github.com/KernelSU-Next/KernelSU-Next) и [документация](https://kernelsu-next.github.io/webpage/). Убедитесь, что профиль применён к правильному UID, особенно в work/private profile.

### APatch

Используйте сильный SuperKey и не храните его в логах/скриншотах. APatch документация требует резервную копию исходного `boot.img`. KPM backend VPNHide может зависеть от корректного KernelPatch runtime; это не означает, что root-следы автоматически скрыты.

### Zygisk Next, NoHello, SUSFS и Hide My Applist

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) предоставляет Zygisk API и режимы linker/memory/unmount. [NoHello](https://github.com/MhmRdd/NoHello/releases/latest) заявляет root/Zygisk hiding и mount rules. [SUSFS core](https://gitlab.com/simonpunk/susfs4ksu) и [пользовательский модуль](https://github.com/sidex15/susfs4ksu-module/releases/latest) предназначены для kernel-level сокрытия mounts/paths, но требуют ядро, уже собранное с совместимым SUSFS patch. Установка одного ZIP поверх обычного ядра не добавляет недостающий kernel patch.

Это дополнительные внешние проекты, а не обязательная часть VPNHide. Они могут помочь против отдельных `ROOT_*`/mount сигналов, но также добавляют собственный код, настройки и риск несовместимости. Устанавливайте только один новый компонент за итерацию. Не используйте неизвестные сборки из Telegram/файлообменников; проверяйте репозиторий, release signature/checksum и не передавайте SuperKey/секреты третьим лицам.

SUSFS особенно чувствителен к версии ядра и интеграции. Kernel patch, userspace module и root manager должны быть совместимы между собой. Несовместимая связка может не загрузиться, сломать mounts или вызвать bootloop. На основном устройстве без recovery-пути она не является разумным первым шагом.

[Hide My Applist](https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest) и его актуальные форки умеют фильтровать package-list каналы, но обычно требуют Xposed/Zygisk-обработку выбранного приложения. Для RKNHardering это плохой вариант по умолчанию: скрыв `INSTALLED_APP`, можно получить `HOOK_MARKERS`, `LSPOSED`, linker/RWX или direct-syscall mismatch. Роль Apps в VPNHide, работающая через `system_server`, предпочтительнее, потому что не требует помещать HMA в scope цели. HMA оставляйте отдельным сравнительным экспериментом, а не ставьте поверх уже работающего PackageManager-фильтра.

### SELinux и системные свойства

Оставляйте `getenforce` равным `Enforcing`. `Permissive` ослабляет устройство и является прямым сигналом. Не меняйте `ro.secure`, `ro.debuggable`, `ro.build.tags`, `service.adb.root` и подобные свойства наугад: подмена должна быть внутренне согласована с build fingerprint и режимом прошивки, иначе появляется новый integrity конфликт.

### Hooks и память

`HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `LIBRARY_INTEGRITY`, `LSPOSED`, `HOOK_PROPERTY`, β linker/direct-syscall проверки ищут не название модуля, а последствия вмешательства. Поэтому переименование APK/пакета LSPosed недостаточно.

Предпочтение по невидимости для цели:

1. Внешний роутер — нет root/hook на телефоне.
2. Kernel VPNHide + system_server hook — цель не инъецирована.
3. Zygisk native hide — process-local след, только fallback.
4. Xposed scope на RKNHardering/repacked APK — наихудший вариант для integrity.

## Read-only проверка

```bash
adb shell id
adb shell getenforce
adb shell getprop ro.debuggable
adb shell getprop ro.secure
adb shell getprop ro.build.tags
adb shell mount | head -n 80
adb shell cat /proc/self/mountinfo | head -n 80
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
```

Для namespace именно приложения shell-вывод недостаточен: shell и target могут видеть разные mounts. Ориентируйтесь на результаты RKNHardering и диагностику root manager. Не прикладывайте публично полный `mountinfo`, `getprop` и module list без очистки: там могут быть пути, серийные данные и имена приватных модулей.

Root-only чтение:

```bash
adb shell su -c 'ls -la /data/adb'
adb shell su -c 'ls -la /data/adb/modules'
adb shell su -c 'cat /sys/fs/selinux/enforce'
```

`permission denied` без `su` ожидаем; с `su` он означает недостаточные права/политику или другой namespace. Не исправляйте это выдачей широких прав приложению.

## Проверка и откат

После установки hide-компонента сравните четыре группы: VPN local signals, root signals, hook/integrity signals, стабильность сети. Если VPN исчез, но появились `LIBRARY_INTEGRITY` и `RWX`, переходите на kernel backend или убирайте target из scope.

Откат: отключите последний module, перезагрузитесь, force-stop RKNHardering и повторите контроль. Если телефон не загружается, используйте официальный module safe mode/root rescue или сохранённый stock boot image. Не удаляйте вручную случайные каталоги `/data/adb` из recovery без понимания, какой manager ими владеет.

[Назад к оглавлению](../)
