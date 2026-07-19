---
title: "IPv4 forwarding включён"
permalink: /help/ru/native/sysctl-forwarding/
---

# IPv4 forwarding включён

> **ID:** `SYSCTL_FORWARDING`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`/proc/sys/net/ipv4/ip_forward` читается как integer. Значение не 0 выдаёт `sysctl_forwarding|ip_forward=1`; legacy policy считает это medium review.

### Точное условие срабатывания

`ip_forward != 0`.

## Что означает результат

Forwarding характерен для router/tethering/root VPN, но Android может включать его для hotspot или системного сетевого режима. Это не самостоятельный VPN-признак.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Проба проверяет только global IPv4 key, не IPv6 forwarding и не per-interface behavior. Значение может меняться при включении hotspot.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Отключите hotspot/USB tethering и повторите. Обычное приложение не может менять sysctl. Если forwarding нужен по назначению, примите review как правдивую характеристику.

### С root

Не ставьте `ip_forward=0` вслепую: это сломает tethering, router/VPN forwarding. Для теста сохраните исходное значение и меняйте только на отдельном устройстве.

### Как проверить результат

```bash
adb shell cat /proc/sys/net/ipv4/ip_forward 2>&1
adb shell dumpsys connectivity | grep -i tether -A3 -B2
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Отключение forwarding обрывает раздачу и часть root VPN схем.

### Откат

Верните сохранённое значение или перезапустите tethering/устройство, чтобы Android применил штатную настройку.

## Уровень доказательности

**Средняя.** Проверено по `detectSysctl()`; kind medium.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [ip-sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `sysctl-rp-filter`, `route-table`.

[К справочнику Native signs](../)
