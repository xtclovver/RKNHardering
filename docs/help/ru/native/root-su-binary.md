---
title: "Файл su в известных путях"
permalink: /help/ru/native/root-su-binary/
---

# Файл su в известных путях

> **ID:** `ROOT_SU_BINARY`
> **Категория:** Root и состояние системы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

C++ вызывает `access(F_OK)` для 12 путей: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su`, `/data/local/su`, `/data/local/bin/su`, `/data/local/xbin/su`, `/system/sd/xbin/su`, `/system/bin/failsafe/su`, `/vendor/bin/su`, `/product/bin/su`, `/apex/com.android.runtime/bin/su`. Найденный путь получает high confidence, но категория выставляет review, а не самостоятельный detected.

### Точное условие срабатывания

Любой из фиксированных путей доступен для проверки существования из UID приложения.

## Что означает результат

Это сильный локальный root-артефакт. Наличие файла не доказывает, что RKNHardering может выполнить `su`, а отсутствие не исключает kernel-based root или нестандартный путь.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Mount namespace может скрыть путь только от части UID. Старые ROM, инженерные сборки и остатки неудачного unroot могут оставить неработающий `su`.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Если root не нужен, надёжное исправление — вернуть устройство к штатному состоянию официальным способом: удалить root через его менеджер либо прошить заводские boot/init_boot и системные разделы именно от установленной сборки. Разблокированный загрузчик, кастомное ядро и оставшиеся каталоги могут продолжить выдавать модификацию даже после удаления менеджера. Перед восстановлением сделайте резервную копию; повторная блокировка загрузчика на изменённой прошивке способна привести к потере данных или неработоспособности устройства. Если root уже удалён, не стирайте файл вручную с read-only раздела: сначала определите, из какого образа или модуля он появился, и восстановите раздел штатно.

### С root

С root можно лишь уменьшать наблюдаемую поверхность, а не доказать отсутствие root. Ограничьте выдачу `su` минимальным числом приложений, не давайте её RKNHardering, отключите ненужные модули и не переводите SELinux в permissive. App Profile/DenyList и mount-изоляция проверяются на конкретной прошивке. SUSFS и сходные решения относятся к экспериментальным: они требуют совместимого ядра и могут сами добавлять следы. Для эталонного теста всё равно нужен отдельный стоковый телефон. Простое переименование `su` не закрывает mounts, management paths, properties и UID. Ограничьте видимость через официальный App Profile/DenyList вашего root-решения и проверьте именно app UID.

### Как проверить результат

```bash
adb shell 'for p in /system/bin/su /system/xbin/su /sbin/su /su/bin/su /data/local/su /data/local/bin/su /data/local/xbin/su /system/sd/xbin/su /system/bin/failsafe/su /vendor/bin/su /product/bin/su /apex/com.android.runtime/bin/su; do [ -e "$p" ] && ls -l "$p"; done'
```
Пустой вывод shell не гарантирует, что app namespace такой же.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление бинарника из системного раздела может нарушить OTA или загрузку. Не выполняйте `rm` до backup образа и понимания mount source.

### Откат

Верните сохранённый boot/system image либо переустановите root через официальный менеджер, если файл был частью его штатной установки.

## Уровень доказательности

**Средняя.** Проверено по точному массиву `kSuPaths`; Kotlin присваивает high confidence и `needsReview=true`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Magisk official install](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md).
- Внешняя первичная документация или официальный проект: [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next).
- Внешняя первичная документация или официальный проект: [APatch](https://github.com/bmax121/APatch).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `root-management`, `root-suspicious-mount`, `root-uid`.

[К справочнику Native signs](../)
