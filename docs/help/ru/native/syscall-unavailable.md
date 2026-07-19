---
title: "Нативная syscall/socket-проба недоступна"
permalink: /help/ru/native/syscall-unavailable/
---

# Нативная syscall/socket-проба недоступна

> **ID:** `SYSCALL_UNAVAILABLE`
> **Категория:** Служебные сигналы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Доступность

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Legacy checker собирает все `unavailable*` строки из syscall group. Сейчас producer — `unavailable|ip_recverr|denied` или `not_supported`. Они отображаются информационно с low confidence и ID `SYSCALL_UNAVAILABLE`.

### Точное условие срабатывания

Проба не может включить IP_RECVERR из-за EACCES/EPERM или ENOPROTOOPT.

## Что означает результат

Недоступность не означает clean. Она означает, что данный путь не дал измерения; review соседних signals остаётся действительным.

**Как строка влияет на отчёт:** Сигнал описывает невозможность выполнить пробу. `unavailable` нельзя интерпретировать как отсутствие VPN.

## Ограничения и возможные ложные срабатывания

ID агрегирующий и может принять новые unavailable kinds в будущих версиях. Текущий detail недостаточно различает SELinux и kernel feature без errno/context log.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Оставьте SELinux enforcing. Зафиксируйте `denied` или `not_supported`, модель, Android и kernel. Не пытайтесь получить root только ради этой диагностики.

### С root

Проверьте AVC logs и совместимость ядра, но не добавляйте широкое allow-rule. Для теста можно воспроизвести в отдельном minimal APK.

### Как проверить результат

```bash
adb logcat -d | grep -E 'avc: denied|IP_RECVERR' | tail -80
adb shell uname -a
```
Доступность из shell socket не равна app domain.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Широкая sepolicy для сетевых опций ослабляет sandbox. `unavailable` безопаснее, чем неверно открытая привилегия.

### Откат

Удалите тестовое sepolicy правило/модуль и перезагрузитесь.

## Уровень доказательности

**Доступность.** Проверено по `unavailableSyscalls` aggregation и единственному текущему producer.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- Внешняя первичная документация или официальный проект: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `ip-recverr`, `native-library`.

[К справочнику Native signs](../)
