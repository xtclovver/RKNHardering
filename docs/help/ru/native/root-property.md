---
title: "Подозрительные системные свойства root/debug"
permalink: /help/ru/native/root-property/
---

# Подозрительные системные свойства root/debug

> **ID:** `ROOT_PROPERTY`
> **Категория:** Root и состояние системы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проверяются точные пары: `ro.debuggable=1`, `ro.secure=0`, `ro.build.selinux=0`, `service.adb.root=1`, `ro.build.tags=test-keys`. Только полное совпадение создаёт `root_prop`; checker оценивает его как medium review.

### Точное условие срабатывания

Хотя бы одна фиксированная property имеет подозрительное точное значение.

## Что означает результат

Сигнал чаще характеризует debug/engineering ROM или изменённый boot image, а не конкретный root manager. `test-keys` особенно часто встречается в пользовательских кастомных прошивках.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Production root может не менять эти свойства. С другой стороны, AOSP userdebug без выданного su всё равно закономерно сработает.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Перейдите на официальную user-сборку производителя, если нужен чистый baseline. Сброс настроек не заменяет прошивку и не изменяет `ro.*`. Не скачивайте случайный `build.prop` — он должен соответствовать вашему образу.

### С root

`resetprop` может изменить видимое значение, но несогласованность с boot state, fingerprint и mount может стать отдельным признаком. Используйте spoofing только как лабораторный тест, не как доказательство чистоты. SELinux нельзя «исправлять» одной строкой property.

### Как проверить результат

```bash
adb shell getprop ro.debuggable
adb shell getprop ro.secure
adb shell getprop ro.build.selinux
adb shell getprop service.adb.root
adb shell getprop ro.build.tags
```
Сравните со значением в detail; property namespace может различаться после root-подмены.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Изменение early-boot properties и boot image может привести к bootloop. Неверный fingerprint ломает OTA, Play services и совместимость.

### Откат

Удалите только созданное вами правило resetprop и перезагрузитесь. При изменённом boot восстановите исходный образ той же сборки.

## Уровень доказательности

**Средняя.** Проверено по `kRootProps`; checker задаёт medium confidence.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Android build variants](https://source.android.com/docs/setup/build/building).
- Внешняя первичная документация или официальный проект: [Magisk resetprop documentation](https://topjohnwu.github.io/Magisk/tools.html#resetprop).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `root-magisk-property`, `emulator-build-profile`, `root-selinux`.

[К справочнику Native signs](../)
