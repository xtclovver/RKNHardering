---
title: "Зарезервированный положительный ID IP_RECVERR"
permalink: /help/ru/native/ip-recverr/
---

# Зарезервированный положительный ID IP_RECVERR

> **ID:** `IP_RECVERR`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** ID сохранён для совместимости; отдельного producer в 2.10.0 нет
> **Роль в вердикте:** Реестр/совместимость

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectIpRecvErr()` только пытается включить `IP_RECVERR`. При успехе он ничего не выдаёт. При EACCES/EPERM или ENOPROTOOPT формируется `unavailable|ip_recverr|...`, который Kotlin направляет в `SYSCALL_UNAVAILABLE`, а не `IP_RECVERR`. Поэтому положительный ID сейчас не появляется.

### Точное условие срабатывания

Отдельного `ip_recverr` producer нет. Ошибка доступности относится к соседнему ID.

## Что означает результат

Строка `IP_RECVERR` в UI обычно not found. Нельзя трактовать это как поддержку или отсутствие VPN; смотрите `syscall-unavailable`.

**Как строка влияет на отчёт:** ID сохранён в каталоге и UI, однако текущая версия 2.10.0 не формирует отдельную положительную строку этого kind. Обычно рядом работает более конкретный сигнал.

## Ограничения и возможные ложные срабатывания

Каталог и описание legacy сохранились от более широкого замысла. Код не читает error queue и не анализирует PMTU errors.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Ничего не меняйте ради этого ID. Если виден unavailable, зафиксируйте errno и версию ROM.

### С root

Не выдавайте приложению CAP_NET_ADMIN ради успешного setsockopt: IP_RECVERR обычно не требует его, а расширение прав создаст новые сигналы. Исправляйте policy только при реальном platform bug.

### Как проверить результат

```bash
rg -n 'detectIpRecvErr|ip_recverr|SYSCALL_UNAVAILABLE' app/src/main
```
Для runtime используйте detail `syscall-unavailable`.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Ослабление socket/SELinux policy ради diagnostic probe увеличивает поверхность атаки.

### Откат

Удалите только добавленное sepolicy/capability правило и перезагрузитесь.

## Уровень доказательности

**Реестр/совместимость.** Проверено по веткам EACCES/EPERM/ENOPROTOOPT и mapper unavailable.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [ip(7) IP_RECVERR](https://man7.org/linux/man-pages/man7/ip.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `syscall-unavailable`, `udp-pmtu-fail`.

[К справочнику Native signs](../)
