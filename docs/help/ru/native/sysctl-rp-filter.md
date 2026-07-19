---
title: "Reverse path filtering отключён глобально"
permalink: /help/ru/native/sysctl-rp-filter/
---

# Reverse path filtering отключён глобально

> **ID:** `SYSCTL_RP_FILTER`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectSysctl()` читает `/proc/sys/net/ipv4/conf/all/rp_filter`; ровно `0` создаёт `sysctl_rp_filter|rp_filter=0`. Legacy policy — medium review.

### Точное условие срабатывания

Global `rp_filter == 0`.

## Что означает результат

Отключённый reverse path filter встречается в сложной policy routing, VPN, tethering и multi-homing. На Android это не редкость и не прямое доказательство.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Реальное поведение зависит от per-interface и `max(all,interface)` semantics ядра. Проверка читает только `all`.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Не меняйте sysctl ради review. Сравните с clean baseline той же прошивки; OEM может штатно использовать 0.

### С root

Изменение на 1/2 способно ломать asymmetric routing и VPN. Если тестируете, сначала сохраните `all`, `default` и значения конкретных interfaces, затем проверьте доступность сети.

### Как проверить результат

```bash
adb shell cat /proc/sys/net/ipv4/conf/all/rp_filter
adb shell 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do printf "%s=" "$f"; cat "$f"; done' 2>/dev/null
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Строгий rp_filter может отбрасывать легитимный трафик split tunnel/multi-WAN.

### Откат

Верните сохранённые sysctl значения либо перезагрузите устройство, если изменение было непостоянным.

## Уровень доказательности

**Средняя.** Проверено по точному условию `rp_filter==0`; medium review.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [ip-sysctl rp_filter](https://docs.kernel.org/networking/ip-sysctl.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `sysctl-forwarding`, `vpn-policy-rules-netlink`.

[К справочнику Native signs](../)
