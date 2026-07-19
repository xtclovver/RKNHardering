---
title: "Основное перечисление сетевых интерфейсов"
permalink: /help/ru/native/interface-enumeration/
---

# Основное перечисление сетевых интерфейсов

> **ID:** `INTERFACE_ENUMERATION`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Смешанная

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`NativeInterfaceProbe.collectInterfaces()` получает интерфейсы через нативный `getifaddrs()`, объединяет записи по имени и добавляет индекс, MTU, flags, тип ARP и адреса. `evaluateInterfaces()` всегда выводит сводку количества интерфейсов и активных интерфейсов. Затем активные имена сравниваются с шаблонами `tun*`, `tap*`, `wg*`, `ppp*`, `utun*`, `zt*`, `tailscale*`, `svpn*`, `gre*`, `l2tp*`, `he-ipv6*`.

### Точное условие срабатывания

Высокодостоверное срабатывание создаётся только для интерфейса `isUp=true`, имя которого после нормализации совпало с VPN-шаблоном. Пустой список интерфейсов даёт review низкой уверенности; обычная сводка информационная.

## Что означает результат

Строка с конкретным VPN-like именем — сильный локальный признак TUN/WireGuard/PPP-пути. Сводка без такого имени ничего не доказывает и нужна для сравнения запусков.

**Как строка влияет на отчёт:** Один и тот же ID используется и для информационной сводки, и для подозрительных строк. Итог зависит от конкретного detail и ветки checker.

## Ограничения и возможные ложные срабатывания

Имена OEM и корпоративных интерфейсов могут совпасть с шаблоном. Обратная проблема тоже возможна: переименованный туннель не попадёт под шаблон, но его выдадут тип TUN/TAP, netlink, маршруты или несогласованность JVM/native.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве.

### Как проверить результат

```bash
adb shell ip -details link show
adb shell ip -br address show
adb shell cat /proc/net/dev
```
Сравните имя, состояние UP, индекс и MTU с деталью RKNHardering. Помните, что shell UID не равен UID приложения; окончательно проверяйте после `adb shell am force-stop com.notcvnt.rknhardering` и повторного запуска.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Внешний шлюз меняет весь сетевой путь. Root/kernel-фильтрация может вызвать потерю сети, зависание `getifaddrs()` или bootloop при несовместимом ядре.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Смешанная.** Проверено по `evaluateInterfaces()`, `NetworkInterfacePatterns` и C++-сборщику интерфейсов. Основной signal покрыт unit-тестами каталога и checker.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NetworkInterfacePatterns.kt` — правила имён интерфейсов](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [getifaddrs(3)](https://man7.org/linux/man-pages/man3/getifaddrs.3.html).
- Внешняя первичная документация или официальный проект: [Android VpnService](https://developer.android.com/reference/android/net/VpnService).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `tuntap-type`, `jvm-native-mismatch`, `getifaddrs-vpn`, `rtm-getlink-vpn`.

[К справочнику Native signs](../)
