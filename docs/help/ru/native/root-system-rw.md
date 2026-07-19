---
title: "Доступность /system для записи"
permalink: /help/ru/native/root-system-rw/
---

# Доступность /system для записи

> **ID:** `ROOT_SYSTEM_RW`
> **Категория:** Root и состояние системы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба вызывает `access("/system", W_OK)` из UID приложения. Успех создаёт `system_rw|/system is writable` и high-confidence review.

### Точное условие срабатывания

Процесс приложения считает `/system` доступным для записи.

## Что означает результат

На современном production Android `/system` обычно read-only и защищён verified boot. Запись для обычного UID — сильная аномалия окружения, permissive sandbox или виртуализатора.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

`access(W_OK)` проверяет effective permission и mount flags, но не выполняет реальную запись. Странный контейнер может вернуть неточный результат. Root процесса RKNHardering также закономерно даст срабатывание.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Используйте штатную прошивку и не запускайте приложение в контейнере, который выдаёт расширенные filesystem-права. Factory reset не исправляет изменённый system image.

### С root

Не выдавайте RKNHardering root и не делайте global remount rw. Systemless modules должны оставлять app view read-only. Если `/system` rw из-за отладочного remount, верните ro и перезагрузитесь.

### Как проверить результат

```bash
adb shell mount | grep -E ' /system( |/)| / '
adb shell test -w /system; echo $?
```
Код `0` означает writable для shell, но app UID может отличаться.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Remount системных разделов и запись нарушают AVB, OTA и могут привести к boot failure. Не проверяйте реальной записью файла.

### Откат

Перезагрузитесь после снятия remount. Если system изменён, восстановите заводской образ и verified boot metadata согласно инструкции устройства.

## Уровень доказательности

**Средняя.** Проверено по единственному `access(W_OK)` условию; checker назначает high confidence review.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `root-overlay-mount`, `root-suspicious-mount`, `root-selinux`.

[К справочнику Native signs](../)
