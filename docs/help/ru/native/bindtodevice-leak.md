---
title: "SO_BINDTODEVICE подтверждает существование VPN-интерфейса"
permalink: /help/ru/native/bindtodevice-leak/
---

# SO_BINDTODEVICE подтверждает существование VPN-интерфейса

> **ID:** `BINDTODEVICE_LEAK`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Для `tun0`, `tun1`, `utun0`, `wg0`, `ppp0` создаётся UDP socket. Проба вызывает `setsockopt(SO_BINDTODEVICE, name)`, затем `getsockopt(SO_BINDTODEVICE)` и требует, чтобы возвращённая строка содержала то же имя. `xfrm0` в этом списке отсутствует.

### Точное условие срабатывания

И установка, и чтение SO_BINDTODEVICE успешны для одного из пяти фиксированных VPN-имён.

## Что означает результат

Kernel socket API принимает привязку к VPN-like netdev, то есть интерфейс реально существует и доступен процессу. Это сильнее простой проверки файла.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

В Linux SO_BINDTODEVICE может быть ограничен правами/политикой; отказ не означает отсутствие интерфейса. Exact list узкий. Проба не посылает трафик и не подтверждает route through device.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси. Нельзя запретить target app делать `setsockopt` только настройками обычного VPN. Второй профиль использует тот же kernel network stack.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Backend должен возвращать согласованную ошибку «интерфейс отсутствует» для target UID и одновременно скрывать getifaddrs/netlink/ifindex. Userspace hook можно обойти raw syscall.

### Как проверить результат

```bash
adb shell su -c 'for n in tun0 tun1 utun0 wg0 ppp0; do ip link show dev "$n" 2>/dev/null && echo present:$n; done'
```
Для точной проверки нужен native harness с SO_BINDTODEVICE; команда выше требует root лишь для ориентира и не повторяет UID/SELinux контекст приложения.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Глобальная блокировка SO_BINDTODEVICE может сломать VPN, DHCP, tethering и системные службы. Подмена errno должна быть per-UID.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по five-name loop, setsockopt+getsockopt confirmation и HIGH_CONFIDENCE set.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [socket(7) SO_BINDTODEVICE](https://man7.org/linux/man-pages/man7/socket.7.html).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `so-bindtodevice`, `getifaddrs-vpn`, `ifindexname-vpn`.

[К справочнику Native signs](../)
