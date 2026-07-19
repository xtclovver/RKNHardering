---
title: "RKNHardering является profile owner"
permalink: /help/ru/native/isolation-work-profile/
---

# RKNHardering является profile owner

> **ID:** `ISOLATION_WORK_PROFILE`
> **Категория:** Эмуляция, профили и изоляция
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Checker получает `DevicePolicyManager` и вызывает `isProfileOwnerApp(context.packageName)`. Сигнал появляется только если сам пакет RKNHardering зарегистрирован profile owner. Это уже, чем общий вопрос «запущено ли приложение внутри work profile»: обычное приложение в управляемом профиле без роли DPC может не дать эту строку.

### Точное условие срабатывания

`isProfileOwnerApp()` возвращает true для package RKNHardering.

## Что означает результат

Medium review указывает на очень специфичную роль DPC/profile owner, а не просто наличие work profile на устройстве.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Название сигнала шире фактической реализации. Для обычного приложения в Shelter/Insular чаще сработает secondary-user по userId, но не эта строка.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Если профиль не является частью теста, установите и запустите приложение в основном пользователе (`user 0`). Перед удалением work/private/clone-профиля экспортируйте его данные: удаление профиля стирает приложения и их хранилище. Shelter и Insular удобны для управляемого профиля, но не скрывают сам факт отдельного Android user. Если RKNHardering случайно назначен DPC, удалите управление профилем штатно через Shelter/Insular/Settings после экспорта данных.

### С root

Root-подмена userId, пути `/data/user/<id>` или ответов `DevicePolicyManager` создаёт несогласованное состояние и может повредить профиль. Надёжнее не маскировать профиль, а выбрать корректного пользователя для запуска. Хуки в целевом процессе ради одной проверки могут дополнительно вызвать `HOOK_MARKERS`, `RWX_MEMORY_REGIONS` и `LIBRARY_INTEGRITY`. Хук `DevicePolicyManager` только для этой строки оставит реальный userId и management state в других API.

### Как проверить результат

```bash
adb shell dpm list-owners
adb shell dumpsys device_policy | grep -A8 -B2 -i 'profile owner'
```
Команды могут требовать доступ shell; detail приложения остаётся окончательным.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление profile owner обычно удаляет work profile и его данные. Сначала экспортируйте всё важное.

### Откат

Создайте managed profile заново через доверенный DPC и восстановите данные.

## Уровень доказательности

**Средняя.** Проверено по точному вызову `isProfileOwnerApp`; документация исправляет прежнее чрезмерно широкое толкование.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [DevicePolicyManager.isProfileOwnerApp](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#isProfileOwnerApp%28java.lang.String%29).
- Внешняя первичная документация или официальный проект: [AOSP managed profiles](https://source.android.com/docs/devices/admin/managed-profiles).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `isolation-secondary-user`, `isolation-profile`.

[К справочнику Native signs](../)
