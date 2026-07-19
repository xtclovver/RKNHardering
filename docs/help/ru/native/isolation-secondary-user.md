---
title: "Запуск не в основном пользователе"
permalink: /help/ru/native/isolation-secondary-user/
---

# Запуск не в основном пользователе

> **ID:** `ISOLATION_SECONDARY_USER`
> **Категория:** Эмуляция, профили и изоляция
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Если извлечённый userId не равен 0 и не попал в clone-набор, checker создаёт `ISOLATION_SECONDARY_USER` с medium review.

### Точное условие срабатывания

DataDir вида `/data/user/<id>/`, где `<id> != 0` и не 999/950..959.

## Что означает результат

Показывает отдельного Android user. Это нормальный режим multi-user, но он меняет набор приложений, VPN и сетевые политики относительно owner.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Путь `/data/user_de/` и vendor-особенности могут не распознаться regex. Private/work profiles также могут попасть сюда, если имеют nonzero userId.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Если профиль не является частью теста, установите и запустите приложение в основном пользователе (`user 0`). Перед удалением work/private/clone-профиля экспортируйте его данные: удаление профиля стирает приложения и их хранилище. Shelter и Insular удобны для управляемого профиля, но не скрывают сам факт отдельного Android user.

### С root

Root-подмена userId, пути `/data/user/<id>` или ответов `DevicePolicyManager` создаёт несогласованное состояние и может повредить профиль. Надёжнее не маскировать профиль, а выбрать корректного пользователя для запуска. Хуки в целевом процессе ради одной проверки могут дополнительно вызвать `HOOK_MARKERS`, `RWX_MEMORY_REGIONS` и `LIBRARY_INTEGRITY`.

### Как проверить результат

```bash
adb shell pm list users
adb shell am get-current-user
adb shell cmd user list
```
Убедитесь, в каком user установлен пакет: `adb shell pm list packages --user 0 | grep rknhardering`.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление secondary user стирает все его данные, не только RKNHardering.

### Откат

Создайте пользователя заново и восстановите backup. Не копируйте app data между UID вручную.

## Уровень доказательности

**Средняя.** Проверено по ветке `else if (userId != 0)`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Android multi-user](https://source.android.com/docs/devices/admin/multi-user).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `isolation-clone`, `isolation-work-profile`.

[К справочнику Native signs](../)
