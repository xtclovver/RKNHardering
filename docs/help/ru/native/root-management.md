---
title: "Каталоги и файлы root-менеджеров"
permalink: /help/ru/native/root-management/
---

# Каталоги и файлы root-менеджеров

> **ID:** `ROOT_MANAGEMENT`
> **Категория:** Root и состояние системы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`nativeDetectRoot()` проверяет `/data/adb/magisk`, `/data/adb/modules`, `/data/adb/ksu`, `/data/adb/ksud`, старые Superuser/SuperSU APK/каталоги, `daemonsu`, init.d-скрипт и `/dev/com.koushikdutta.superuser.daemon`. Доступный путь создаёт high-confidence review.

### Точное условие срабатывания

`access(F_OK)` успешно для любого пути из фиксированного списка.

## Что означает результат

Это сильный артефакт установленного или не полностью удалённого root-стека. Он не доказывает, что модуль активен сейчас.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Современный manager может хранить данные иначе; SELinux/mount namespace может закрыть путь. `/data/adb/modules` может существовать из-за старой установки без активного su.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Если root не нужен, надёжное исправление — вернуть устройство к штатному состоянию официальным способом: удалить root через его менеджер либо прошить заводские boot/init_boot и системные разделы именно от установленной сборки. Разблокированный загрузчик, кастомное ядро и оставшиеся каталоги могут продолжить выдавать модификацию даже после удаления менеджера. Перед восстановлением сделайте резервную копию; повторная блокировка загрузчика на изменённой прошивке способна привести к потере данных или неработоспособности устройства. После штатного unroot проверьте остатки только чтением. Не удаляйте `/data/adb` вслепую: там могут находиться данные модулей и recovery-механизм.

### С root

С root можно лишь уменьшать наблюдаемую поверхность, а не доказать отсутствие root. Ограничьте выдачу `su` минимальным числом приложений, не давайте её RKNHardering, отключите ненужные модули и не переводите SELinux в permissive. App Profile/DenyList и mount-изоляция проверяются на конкретной прошивке. SUSFS и сходные решения относятся к экспериментальным: они требуют совместимого ядра и могут сами добавлять следы. Для эталонного теста всё равно нужен отдельный стоковый телефон. Изоляция path для целевого UID должна быть согласована с `/proc/self/mounts` и overlay. Если путь скрыт, но mount остаётся, сработает соседняя проверка.

### Как проверить результат

```bash
adb shell 'for p in /data/adb/magisk /data/adb/modules /data/adb/ksu /data/adb/ksud /system/app/Superuser.apk /system/app/SuperSU.apk /system/app/SuperSU /system/xbin/daemonsu /system/etc/init.d/99SuperSUDaemon /dev/com.koushikdutta.superuser.daemon; do [ -e "$p" ] && echo "$p"; done'
```
Некоторые `/data/adb` пути shell не прочитает без root.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление module directory вручную может лишить safe-mode/rollback или оставить mount в полусостоянии. Используйте UI root manager.

### Откат

Если тестировали hiding-модуль, отключите его штатно. Для полного удаления выполните официальный uninstall и восстановление boot image.

## Уровень доказательности

**Средняя.** Проверено по `kRootMgmtPaths`; все найденные строки получают high confidence review.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Magisk](https://github.com/topjohnwu/Magisk).
- Внешняя первичная документация или официальный проект: [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next).
- Внешняя первичная документация или официальный проект: [APatch](https://github.com/bmax121/APatch).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `root-su-binary`, `root-suspicious-mount`, `root-overlay-mount`.

[К справочнику Native signs](../)
