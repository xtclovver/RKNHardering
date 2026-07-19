---
title: "OEM clone/dual-app userId"
permalink: /help/ru/native/isolation-clone/
---

# OEM clone/dual-app userId

> **ID:** `ISOLATION_CLONE`
> **Категория:** Эмуляция, профили и изоляция
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Из dataDir извлекается userId. Значение `999` или диапазон `950..959` считается clone/dual-app контейнером (в коде отмечен MIUI dual-app range) и создаёт medium review.

### Точное условие срабатывания

Путь приложения соответствует `/data/user/999/` либо `/data/user/950..959/`.

## Что означает результат

Сигнал показывает фактический Android user, а не наличие конкретного приложения-клонировщика. Он объясняет отдельные UID, package visibility и сетевые настройки.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

OEM может использовать другой userId, а указанный диапазон может теоретически принадлежать другому типу пользователя. DataDir-парсер не читает `UserManager` type.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Если профиль не является частью теста, установите и запустите приложение в основном пользователе (`user 0`). Перед удалением work/private/clone-профиля экспортируйте его данные: удаление профиля стирает приложения и их хранилище. Shelter и Insular удобны для управляемого профиля, но не скрывают сам факт отдельного Android user. В настройках OEM отключите Dual Apps/Second Space именно для RKNHardering и переустановите его в owner user.

### С root

Root-подмена userId, пути `/data/user/<id>` или ответов `DevicePolicyManager` создаёт несогласованное состояние и может повредить профиль. Надёжнее не маскировать профиль, а выбрать корректного пользователя для запуска. Хуки в целевом процессе ради одной проверки могут дополнительно вызвать `HOOK_MARKERS`, `RWX_MEMORY_REGIONS` и `LIBRARY_INTEGRITY`.

### Как проверить результат

```bash
adb shell pm list users
adb shell dumpsys package com.notcvnt.rknhardering | grep -E 'userId=|dataDir='
```
На новых Android package dump может скрывать часть путей.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление клона стирает его отдельные данные. Не переносите dataDir вручную между UID.

### Откат

Включите OEM clone снова и восстановите экспортированные данные через штатный механизм приложения.

## Уровень доказательности

**Средняя.** Проверено по `CLONE_USER_IDS={999}` и диапазону `950..959`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Android multi-user](https://source.android.com/docs/devices/admin/multi-user).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `isolation-secondary-user`, `isolation-work-profile`.

[К справочнику Native signs](../)
