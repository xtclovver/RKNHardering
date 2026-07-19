---
title: "Фиксированные VPN-имена в getifaddrs()"
permalink: /help/ru/native/getifaddrs-vpn/
---

# Фиксированные VPN-имена в getifaddrs()

> **ID:** `GETIFADDRS_VPN`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectGetifaddrsVpn()` вызывает libc `getifaddrs()` и ищет точные имена `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, `xfrm0`. Повторяющиеся записи адресов не дедуплицируются, поэтому одно имя может встретиться несколько раз в detail.

### Точное условие срабатывания

В цепочке `ifaddrs` присутствует хотя бы одна запись с одним из шести точных имён; состояние UP не проверяется.

## Что означает результат

Прямой userspace-список интерфейсов содержит типичное VPN-имя. В отличие от основной `interface-enumeration`, этот deep-вектор может сработать и для интерфейса без флага UP.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Это не полный matcher проекта: `tailscale0`, `svpn0`, `zt*`, `gre*`, переименованные и OEM-интерфейсы здесь не ищутся. Userspace inline-hook способен подменить `getifaddrs()`, но raw netlink и другие пути останутся отдельными проверками.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси. Без root нельзя отфильтровать результат `getifaddrs()` другого приложения. Rootless hook/repack целевого APK создаёт более заметные признаки целостности и не рекомендуется.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Zygisk может перехватить libc-вызов, но raw syscall/netlink обходят userspace interposition. Для согласованного результата предпочтительнее kernel backend плюс system_server-слой.

### Как проверить результат

```bash
adb shell ip -br link
adb shell 'cat /proc/net/dev | grep -E "tun0|tun1|utun0|wg0|ppp0|xfrm0"'
```
Для точного воспроизведения нужен маленький native harness с `getifaddrs()`: `ip` использует собственные netlink-пути и является только сравнением.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Неполный userspace hook приводит к расхождениям с RTM_GETLINK, ifindex и Java API; это усиливает `trim-oracle` и mismatch-сигналы.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по exact-name loop в `detectGetifaddrsVpn()`; kind high.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [getifaddrs(3)](https://man7.org/linux/man-pages/man3/getifaddrs.3.html).
- Внешняя первичная документация или официальный проект: [VPNHide Zygisk limitations](https://github.com/okhsunrog/vpnhide/blob/main/zygisk/README.md).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `interface-enumeration`, `rtm-getlink-vpn`, `trim-oracle`, `sysclassnet-vpn`.

[К справочнику Native signs](../)
