---
title: "Зарезервированный legacy ID ARP на VPN-интерфейсе"
permalink: /help/ru/native/arp-vpn-interface/
---

# Зарезервированный legacy ID ARP на VPN-интерфейсе

> **ID:** `ARP_VPN_INTERFACE`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** ID сохранён для совместимости; отдельного producer в 2.10.0 нет
> **Роль в вердикте:** Реестр/совместимость

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`ARP_VPN_INTERFACE`/`arp_vpn_iface` присутствует в каталоге и отмечен legacy high, но `detectArpNeighbors()` версии 2.10.0 не выдаёт такой kind. Он считает нулевые/broadcast MAC и формирует только `hidden_mac_neighbors`.

### Точное условие срабатывания

Отдельного producer нет.

## Что означает результат

ARP всё же читается, но фактический active signal — `hidden-mac-neighbors`. Интерфейс ARP из строки не сопоставляется с VPN-name в текущем коде.

**Как строка влияет на отчёт:** ID сохранён в каталоге и UI, однако текущая версия 2.10.0 не формирует отдельную положительную строку этого kind. Обычно рядом работает более конкретный сигнал.

## Ограничения и возможные ложные срабатывания

Будущий parser может добавить `arp_vpn_iface`; сейчас URL остаётся compatibility.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Не требуется обходить отсутствующий kind. Разберите реальные zero-MAC entries на соседней странице.

### С root

Root ARP-filter не нужен ради этого ID. Не очищайте neighbor table: это вызовет задержки и потерю локальной связи.

### Как проверить результат

```bash
rg -n 'arp_vpn_iface|hidden_mac_neighbors|detectArpNeighbors' app/src/main
adb shell cat /proc/net/arp 2>&1
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

`ip neigh flush all` нарушает текущие LAN-соединения и не устраняет producer.

### Откат

Не требуется; после случайного flush neighbor table восстановится трафиком/переподключением.

## Уровень доказательности

**Реестр/совместимость.** Проверено по отсутствию producer и фактическому output `hidden_mac_neighbors`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [arp(7)](https://man7.org/linux/man-pages/man7/arp.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `hidden-mac-neighbors`.

[К справочнику Native signs](../)
