---
title: "Непривязанный UDP socket сразу получил private IPv4"
permalink: /help/ru/native/getsockname-leak/
---

# Непривязанный UDP socket сразу получил private IPv4

> **ID:** `GETSOCKNAME_LEAK`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectGetsocknameLeak()` создаёт `AF_INET/SOCK_DGRAM` socket и немедленно вызывает `getsockname()` — без `bind()` и `connect()`. Если адрес не 0.0.0.0 и попадает в 10/8, 172.16/12 или 192.168/16, выводится `getsockname_leak` с IP.

### Точное условие срабатывания

Неconnected и unbound UDP socket имеет ненулевой private IPv4 сразу после создания.

## Что означает результат

Checker считает это высоким сигналом необычной socket interposition или среды, потому что нормальный Linux socket обычно остаётся 0.0.0.0 до bind/connect. Сам private IP не доказывает, что он VPN-адрес.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Название «VPN IP leak» сильнее фактической проверки. Частный адрес может быть физическим Wi‑Fi/LAN. На обычном Android сигнал, скорее всего, отсутствует; срабатывание надо воспроизвести и искать hook/virtualization.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Сначала повторите на чистом устройстве и release APK. Отключите rootless virtualization, LSPatch, VPN SDK и network sandbox. Не меняйте LAN address ради этого сигнала.

### С root

Исключите RKNHardering из in-process Zygisk/Xposed hooks и проверьте libc/socket integrity. Не подменяйте private IP на публичный: правильный baseline до bind/connect — 0.0.0.0.

### Как проверить результат

Для точного воспроизведения соберите минимальный native test:
```c
int fd = socket(AF_INET, SOCK_DGRAM, 0);
struct sockaddr_in a = {}; socklen_t n = sizeof(a);
getsockname(fd, (struct sockaddr *)&a, &n);
```
Ожидаемый адрес до `bind/connect` — `0.0.0.0`. `ss` не заменяет эту пробу.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Глобальный hook `getsockname()` ломает приложения и может создавать сетевые утечки. Не изменяйте системную libc.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по отсутствию bind/connect и exact private ranges; kind high по текущему checker.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [getsockname(2)](https://man7.org/linux/man-pages/man2/getsockname.2.html).
- Внешняя первичная документация или официальный проект: [ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `so-bindtodevice`, `library-integrity`, `hook-markers`.

[К справочнику Native signs](../)
