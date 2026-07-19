---
title: "ARP entries с нулевым или broadcast MAC"
permalink: /help/ru/native/hidden-mac-neighbors/
---

# ARP entries с нулевым или broadcast MAC

> **ID:** `HIDDEN_MAC_NEIGHBORS`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectArpNeighbors()` читает `/proc/net/arp`, считает все rows и строки с MAC `00:00:00:00:00:00` либо содержащим `ff:ff:ff:ff:ff:ff`. Если hidden > 0, legacy policy считает kind high.

### Точное условие срабатывания

Хотя бы одна ARP row с нулевым/broadcast MAC.

## Что означает результат

Высокая политика проекта трактует это как скрытых соседей, однако незавершённый ARP/NUD и stale entry могут быть обычным сетевым состоянием. Detail total/hidden важен.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

ARP относится только к IPv4 и L2. Нулевая MAC может быть временной до разрешения адреса; broadcast может иметь законный смысл. Interface не проверяется на VPN.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Повторите после стабильного Wi‑Fi и небольшого трафика к gateway. Отключите/включите сеть, если entry зависла. Не очищайте ARP ради зелёной строки без понимания адреса.

### С root

Не скрывайте весь ARP table: это создаст count/mismatch и затруднит LAN. Если VPN-модуль генерирует фиктивную neighbor row, исправьте его конфигурацию или используйте внешний шлюз.

### Как проверить результат

```bash
adb shell cat /proc/net/arp 2>&1
adb shell ip neigh show 2>/dev/null
```
Снимите два повтора с интервалом: временная INCOMPLETE запись может исчезнуть.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Flush neighbor table временно обрывает локальные соединения и увеличивает ARP traffic.

### Откат

Переподключите Wi‑Fi/сеть; neighbor cache восстановится автоматически.

## Уровень доказательности

**Высокая.** Проверено по exact MAC conditions; legacy policy high, хотя false positive возможен.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [arp(7)](https://man7.org/linux/man-pages/man7/arp.7.html).
- Внешняя первичная документация или официальный проект: [ip-neighbour](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `arp-vpn-interface`, `interface-enumeration`.

[К справочнику Native signs](../)
