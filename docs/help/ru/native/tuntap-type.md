---
title: "Тип интерфейса ARPHRD_TUNNEL/TUN-TAP независимо от имени"
permalink: /help/ru/native/tuntap-type/
---

# Тип интерфейса ARPHRD_TUNNEL/TUN-TAP независимо от имени

> **ID:** `TUNTAP_TYPE`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

После основного `getifaddrs()`-снимка checker читает тип интерфейса и сравнивает его с `ARPHRD_TUNTAP = 65534`. Проверка специально выбирает активные интерфейсы, которые имеют этот тип, но не совпадают с известными VPN-именами. Так закрывается простое переименование `tun0` в нейтральное имя.

### Точное условие срабатывания

`iface.isUp && iface.ifaceType == 65534 && !isVpnInterface(iface.name)` создаёт `detected=true` с высокой уверенностью.

## Что означает результат

Нейтральное имя при TUN/TAP-типе считается сильным несоответствием. Простое переименование интерфейса недостаточно для прохождения этой проверки.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Драйвер или OEM может использовать необычный ARP hardware type для легитимного виртуального интерфейса. Поэтому полезно сверить `/sys/class/net/<iface>/type`, назначение интерфейса и активные маршруты.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси. Переименование интерфейса без изменения его типа не помогает. Без root изменить kernel-reported type чужого интерфейса нельзя.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Backend должен скрывать сам интерфейс или согласованно подменять type; фильтрации только имени недостаточно.

### Как проверить результат

```bash
adb shell 'for i in /sys/class/net/*; do printf "%s type=" "${i##*/}"; cat "$i/type" 2>/dev/null; done'
adb shell ip -details link show
```
Найдите интерфейс из detail и подтвердите значение `65534`.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Подмена типа в ядре затрагивает сетевой стек и может сломать VPN. Не патчите sysfs-файл: это представление kernel state, а не обычная настройка.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено непосредственно по условию `ARPHRD_TUNTAP` в `NativeSignsChecker`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NetworkInterfacePatterns.kt` — правила имён интерфейсов](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [netdevice(7)](https://man7.org/linux/man-pages/man7/netdevice.7.html).
- Внешняя первичная документация или официальный проект: [Android VpnService](https://developer.android.com/reference/android/net/VpnService).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `interface-enumeration`, `sysclassnet-vpn`, `sysfs-vpn-leak`.

[К справочнику Native signs](../)
