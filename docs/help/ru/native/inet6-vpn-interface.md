---
title: "Legacy ioctl-проверка фиксированных VPN-интерфейсов"
permalink: /help/ru/native/inet6-vpn-interface/
---

# Legacy ioctl-проверка фиксированных VPN-интерфейсов

> **ID:** `INET6_VPN_INTERFACE`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectVpnInterfaces()` перебирает точные имена `tun0`, `tun1`, `utun0`, `utun1`, `wg0`, `wg1`, `ppp0`, `xfrm0`. `ifaceExists()` и второй `SIOCGIFFLAGS` должны успешно отработать; detail включает имя и flags. Kind legacy high.

### Точное условие срабатывания

Фиксированное имя существует и доступно через socket ioctl SIOCGIFFLAGS.

## Что означает результат

Сильный, но узкий name-based сигнал. Несмотря на историческое имя `inet6`, проверка не ограничена IPv6 и не читает адрес — она делает AF_INET ioctl flags.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Переименованный или нестандартный интерфейс не попадает в список; его могут поймать основной patterns/type/netlink checks. Название страницы не вполне соответствует реализации.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Backend должен перехватывать `SIOCGIFFLAGS`, а не только `getifaddrs`.

### Как проверить результат

```bash
for i in tun0 tun1 utun0 utun1 wg0 wg1 ppp0 xfrm0; do adb shell ip link show "$i" 2>/dev/null; done
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Несогласованная ошибка ioctl может вызвать JVM/native mismatch и ifindex oracle.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по точному `tunNames` и двум SIOCGIFFLAGS вызовам; kind high.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [netdevice ioctls](https://man7.org/linux/man-pages/man7/netdevice.7.html).
- Внешняя первичная документация или официальный проект: [VPNHide ioctl coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `interface-enumeration`, `ifindexname-vpn`, `getifaddrs-vpn`.

[К справочнику Native signs](../)
