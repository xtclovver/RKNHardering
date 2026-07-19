---
title: "Legacy socket identity под историческим именем SO_BINDTODEVICE"
permalink: /help/ru/native/so-bindtodevice/
---

# Legacy socket identity под историческим именем SO_BINDTODEVICE

> **ID:** `SO_BINDTODEVICE`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Функция `detectSocketLeaks()` не вызывает `SO_BINDTODEVICE`. Она создаёт несвязанный UDP/IPv4 socket, делает `getsockname()` и выдаёт `so_bindtodevice|local_ip=...`, только если local address не равен 0. Обычно несвязанный socket возвращает `0.0.0.0`, поэтому строка редка. Legacy policy — medium review.

### Точное условие срабатывания

Unconnected UDP socket сразу имеет ненулевой local IPv4 address.

## Что означает результат

Это подозрительная socket identity, но название страницы исторически неверно. Настоящий `SO_BINDTODEVICE` проверяется в `bindtodevice-leak`.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

В стандартном Linux адрес выбирается после connect/bind, поэтому текущая проба обычно ничего не выдаёт. Контейнер или hook может изменить поведение.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Не требуется менять сеть, если строка отсутствует. При срабатывании повторите на clean device и проверьте virtualization/proxy SDK.

### С root

Ищите hook, который автоматически bind/connect socket, а не маскируйте detail. Исключите target из in-process modules.

### Как проверить результат

Для воспроизведения нужен небольшой native test: `socket(AF_INET, SOCK_DGRAM)` → `getsockname()` без bind/connect. Команда `ss` не показывает незарегистрированный краткоживущий socket. В коде:
```bash
rg -n 'detectSocketLeaks|so_bindtodevice' app/src/main/cpp/native_signs_probe.cpp
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Изменение глобального socket binding ломает маршрутизацию приложений.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Средняя.** Проверено по фактическому коду; документация исправляет несоответствие имени реализации.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html).
- Внешняя первичная документация или официальный проект: [ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `bindtodevice-leak`, `getsockname-leak`.

[К справочнику Native signs](../)
