---
title: "Несогласованность количества интерфейсов между if_indextoname и RTM_GETLINK"
permalink: /help/ru/native/trim-oracle/
---

# Несогласованность количества интерфейсов между if_indextoname и RTM_GETLINK

> **ID:** `TRIM_ORACLE`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба считает успешные `if_indextoname()` для индексов 1…127 (`bind_probe`) и отдельно количество `RTM_NEWLINK` в полном RTM_GETLINK dump. Если числа различаются, выводится MISMATCH. Kind medium review.

### Точное условие срабатывания

`bindCount != rtmCount` после двух независимых перечислений.

## Что означает результат

Чаще всего это признак неполного фильтра: один API скрывает интерфейс, а другой оставляет индекс/entry. Но mismatch может возникнуть из-за индекса >127, race создания/удаления интерфейса или неполного netlink dump.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Название `bind_probe` историческое: фактически используется `if_indextoname`, а не bind. Верхняя граница 127 создаёт ложный mismatch на системах с большим ifindex. Snapshot не атомарный и не повторяется для подтверждения.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для диагностического сигнала сначала ничего не «исправляйте». Запишите baseline на том же устройстве без VPN, затем повторите с VPN при одинаковой сети, температуре и нагрузке. Только воспроизводимая разница между сериями пригодна для анализа. Одиночное значение MTU, времени или GSO не является доказательством. Перезапустите проверку несколько раз. Если mismatch возникает только во время смены Wi‑Fi/mobile/VPN, это race, а не устойчивый обход.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Исправлять нужно согласованность всех путей. Не скрывайте только RTM_NEWLINK через trim: `if_indextoname`, SIOCGIFNAME, routes и addresses должны давать совместимую картину.

### Как проверить результат

```bash
adb shell 'ip -o link show | wc -l'
adb shell 'ip -o link show'
```
Для exact comparison нужен native harness, перебирающий `if_indextoname(1..127)`, сразу после RTM_GETLINK dump. Повторите не менее пяти раз в стабильной сети.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Неправильная фильтрация netlink multipart messages может зациклить dump или сломать системные сетевые вызовы.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Средняя.** Проверено по two-count algorithm; kind medium, не detected. Указана граница 127 и race.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`vpnhide_regression_probe.cpp` — consistency/oracle-пробы](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/vpnhide_regression_probe.cpp).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- Внешняя первичная документация или официальный проект: [if_nametoindex(3)](https://man7.org/linux/man-pages/man3/if_nametoindex.3.html).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `rtm-getlink-vpn`, `ifindexname-vpn`, `vpnhide`.

[К справочнику Native signs](../)
