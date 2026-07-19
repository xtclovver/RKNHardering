---
title: "SELinux permissive или недоступный enforce-файл"
permalink: /help/ru/native/root-selinux/
---

# SELinux permissive или недоступный enforce-файл

> **ID:** `ROOT_SELINUX`
> **Категория:** Root и состояние системы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

C++ читает `/sys/fs/selinux/enforce`. Значение `0` выдаёт `selinux|permissive` с high confidence. Если файл вообще не открывается, выдаётся `selinux|absent`; Kotlin считает это low-confidence review.

### Точное условие срабатывания

`enforce=0` либо невозможность открыть enforce-файл.

## Что означает результат

Permissive — сильная модификация безопасности. `absent` неоднозначен: путь может быть скрыт SELinux/namespace, отсутствовать в контейнере или быть недоступен обычному приложению.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Проверка не анализирует политику целиком. Enforcing не означает stock policy; root-модуль может добавить разрешения. Отсутствие файла не равно permissive.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Не устанавливайте прошивки, которые запускают SELinux permissive, если нужен чистый baseline. На production ROM оставьте enforcing. Если файл absent только для приложения, оцените соседние сигналы, а не ослабляйте policy.

### С root

Никогда не переводите SELinux в permissive ради VPNHide или другого модуля. Исправьте конкретные AVC-denial минимальным правилом либо откажитесь от несовместимого модуля. Подмена значения `enforce` без реального enforcing создаёт ложное чувство безопасности.

### Как проверить результат

```bash
adb shell getenforce
adb shell cat /sys/fs/selinux/enforce 2>/dev/null
adb logcat -d | grep 'avc: denied' | tail -50
```
`getenforce` shell и чтение app UID могут различаться только по доступу, не по реальному режиме ядра.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Permissive отключает принудительное применение SELinux и расширяет ущерб от компрометации. Неправильная sepolicy может вызвать bootloop.

### Откат

Верните enforcing и удалите последнее широкое sepolicy-правило. Если устройство не загружается, восстановите boot image/модуль через safe mode.

## Уровень доказательности

**Средняя.** Проверено по двум веткам `nativeDetectRoot()`; confidence различается для permissive и absent.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `root-property`, `root-system-rw`, `syscall-unavailable`.

[К справочнику Native signs](../)
