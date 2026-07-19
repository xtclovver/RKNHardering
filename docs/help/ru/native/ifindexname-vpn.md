---
title: "VPN-имя через if_indextoname()"
permalink: /help/ru/native/ifindexname-vpn/
---

# VPN-имя через if_indextoname()

> **ID:** `IFINDEXNAME_VPN`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectIfindexnameVpn()` перебирает ifindex 1…127, вызывает `if_indextoname()` и ищет точные имена `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, `xfrm0`. Detail содержит имя и индекс.

### Точное условие срабатывания

Обратное разрешение хотя бы одного индекса возвращает фиксированное VPN-имя.

## Что означает результат

Даже если приложение не может перечислить каталог или route dump, kernel/libc разрешает индекс в VPN-like name. Это сильный признак неполного скрытия.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Индексы выше 127 не проверяются. Exact-name list узкий. Userspace hook `if_indextoname()` может скрыть строку, но его согласованность проверяет VPNHide regression oracle и RTM dump.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Не возвращайте фиктивное «чистое» имя только в `if_indextoname()`: несоответствие SIOCGIFINDEX/SIOCGIFNAME и RTM_GETLINK создаёт oracle. Kernel backend должен фильтровать согласованно.

### Как проверить результат

```bash
adb shell 'for i in $(seq 1 127); do n=$(cat /sys/class/net/*/ifindex 2>/dev/null | grep -x "$i" -m1); [ -n "$n" ] && :; done'
adb shell ip -o link show
```
Точное API лучше воспроизвести native harness с `if_indextoname()`; `ip` — сравнительный снимок.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Несогласованная подмена индексов нарушает bind-to-device, route resolution и может вызывать сбои системных сервисов.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по диапазону [1,127] и exact-name list; kind high.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`vpnhide_regression_probe.cpp` — consistency/oracle-пробы](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/vpnhide_regression_probe.cpp).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [if_nametoindex(3)](https://man7.org/linux/man-pages/man3/if_nametoindex.3.html).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `vpnhide`, `trim-oracle`, `rtm-getlink-vpn`, `interface-enumeration`.

[К справочнику Native signs](../)
