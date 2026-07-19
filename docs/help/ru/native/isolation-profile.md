---
title: "Сводка Android user/profile isolation"
permalink: /help/ru/native/isolation-profile/
---

# Сводка Android user/profile isolation

> **ID:** `ISOLATION_PROFILE`
> **Категория:** Эмуляция, профили и изоляция
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Служебная

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Это зонтичный ID. Текущий checker извлекает userId из пути `/data/user/<id>/` и отдельно вызывает `DevicePolicyManager.isProfileOwnerApp()`; положительные строки получают `ISOLATION_CLONE`, `ISOLATION_SECONDARY_USER` или `ISOLATION_WORK_PROFILE`. Отдельный producer `ISOLATION_PROFILE` отсутствует.

### Точное условие срабатывания

Сам ID не срабатывает; см. три дочерних сигнала.

## Что означает результат

Профиль не считается VPN-доказательством, но меняет package visibility, UID, VPN per-profile и доступ к данным. Поэтому обход через второе пространство не является прозрачным.

**Как строка влияет на отчёт:** Это зонтичный или резервный ID. Он связывает группу строк с документацией, но не всегда имеет отдельный положительный producer.

## Ограничения и возможные ложные срабатывания

Private Space и OEM-клоны имеют разные user types; текущая реализация видит главным образом numeric userId и profile-owner самого приложения.

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
adb shell dumpsys user | head -160
```
Сверьте userId с путём dataDir в detail.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление профиля стирает его приложения и данные. Экспортируйте данные до эксперимента.

### Откат

Создайте профиль заново штатным DPC/Settings и восстановите данные из резервной копии.

## Уровень доказательности

**Служебная.** Проверено по `evaluateIsolation()` и отсутствию прямого назначения зонтичного ID.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Внешняя первичная документация или официальный проект: [AOSP managed profiles](https://source.android.com/docs/devices/admin/managed-profiles).
- Внешняя первичная документация или официальный проект: [AOSP Private Space](https://source.android.com/docs/security/features/private-space).
- Внешняя первичная документация или официальный проект: [Application Sandbox](https://source.android.com/docs/security/app-sandbox).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `isolation-clone`, `isolation-secondary-user`, `isolation-work-profile`.

[К справочнику Native signs](../)
