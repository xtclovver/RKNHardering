---
title: "Зарезервированный legacy ID TCP VPN-портов"
permalink: /help/ru/native/tcp-vpn-port/
---

# Зарезервированный legacy ID TCP VPN-портов

> **ID:** `TCP_VPN_PORT`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** ID сохранён для совместимости; отдельного producer в 2.10.0 нет
> **Роль в вердикте:** Реестр/совместимость

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`TCP_VPN_PORT` и mapping `tcp_vpn_port` присутствуют в каталоге и legacy loop, но текущий C++ не выдаёт такой kind. TCP connections проверяются отдельным `established_vpn`, а занятость localhost — `loopback_port_conflict`.

### Точное условие срабатывания

Отдельного положительного producer нет; UI обычно показывает not found.

## Что означает результат

Не путайте эту строку с фактическим TCP socket scan. Активный producer `established-vpn-socket` читает `/proc/net/tcp` и ищет remote port.

**Как строка влияет на отчёт:** ID сохранён в каталоге и UI, однако текущая версия 2.10.0 не формирует отдельную положительную строку этого kind. Обычно рядом работает более конкретный сигнал.

## Ограничения и возможные ложные срабатывания

Будущая версия может восстановить отдельный port probe; текущая страница фиксирует состояние 2.10.0.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для этого ID действий не требуется. Закройте реальный local API/listener и проверьте соседние signals.

### С root

Не устанавливайте port-hiding модуль ради registry-only строки. Если срабатывает `loopback-port-conflict`, используйте точечную Ports/firewall настройку.

### Как проверить результат

```bash
rg -n 'tcp_vpn_port|established_vpn|loopback_port_conflict' app/src/main
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Ложное чувство clean при открытом порте.

### Откат

Не требуется.

## Уровень доказательности

**Реестр/совместимость.** Проверено по отсутствию C++ literal producer и наличию catalog mapping.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `established-vpn-socket`, `loopback-port-conflict`.

[К справочнику Native signs](../)
