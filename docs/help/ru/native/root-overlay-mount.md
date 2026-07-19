---
title: "Overlay mount поверх /system или /vendor"
permalink: /help/ru/native/root-overlay-mount/
---

# Overlay mount поверх /system или /vendor

> **ID:** `ROOT_OVERLAY_MOUNT`
> **Категория:** Root и состояние системы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

C++ создаёт `overlay_mount` для строки `/proc/self/mounts`, содержащей `overlay` и `/system` либо `/vendor`. Но Kotlin намеренно отбрасывает строку, если detail не содержит high-confidence root marker (`magisk`, `zygisk`, `lsposed`, `riru`, `kernelsu`, `apatch`, `/data/adb`, `core-only`). Только подтверждённый marker становится high review.

### Точное условие срабатывания

Overlay над system/vendor плюс root-marker в той же detail-строке.

## Что означает результат

Сигнал отличает обычное использование overlayfs от root/systemless mount. Сам overlay без marker текущим checker не показывается.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Формат mount string зависит от ядра и root manager. Marker может быть скрыт, а overlay останется; такая строка будет пропущена текущей Kotlin-фильтрацией.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Если root не нужен, надёжное исправление — вернуть устройство к штатному состоянию официальным способом: удалить root через его менеджер либо прошить заводские boot/init_boot и системные разделы именно от установленной сборки. Разблокированный загрузчик, кастомное ядро и оставшиеся каталоги могут продолжить выдавать модификацию даже после удаления менеджера. Перед восстановлением сделайте резервную копию; повторная блокировка загрузчика на изменённой прошивке способна привести к потере данных или неработоспособности устройства.

### С root

С root можно лишь уменьшать наблюдаемую поверхность, а не доказать отсутствие root. Ограничьте выдачу `su` минимальным числом приложений, не давайте её RKNHardering, отключите ненужные модули и не переводите SELinux в permissive. App Profile/DenyList и mount-изоляция проверяются на конкретной прошивке. SUSFS и сходные решения относятся к экспериментальным: они требуют совместимого ядра и могут сами добавлять следы. Для эталонного теста всё равно нужен отдельный стоковый телефон. Не отключайте overlayfs, если на нём держатся модули, до подготовки boot rollback. Минимизация числа модулей уменьшает overlay surface.

### Как проверить результат

```bash
adb shell cat /proc/self/mounts | grep -E 'overlay.*(/system|/vendor)|(/system|/vendor).*overlay'
```
Сверьте всю строку с marker из встроенного detail.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Unmount или изменение overlay lower/upper/workdir может привести к crash системных сервисов и bootloop.

### Откат

Отключите виновный модуль через safe mode root manager либо восстановите рабочий boot image. Не удаляйте upperdir до загрузки чистого состояния.

## Уровень доказательности

**Средняя.** Проверено по C++ условию overlay/system/vendor и Kotlin-фильтру high-confidence marker.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [overlayfs documentation](https://docs.kernel.org/filesystems/overlayfs.html).
- Внешняя первичная документация или официальный проект: [Magisk modules](https://github.com/topjohnwu/Magisk).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `root-suspicious-mount`, `root-system-rw`, `root-management`.

[К справочнику Native signs](../)
