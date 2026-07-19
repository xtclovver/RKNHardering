---
title: "VPN-интерфейс в netlink RTM_GETLINK"
permalink: /help/ru/native/rtm-getlink-vpn/
---

# VPN-интерфейс в netlink RTM_GETLINK

> **ID:** `RTM_GETLINK_VPN`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба открывает `AF_NETLINK/NETLINK_ROUTE`, отправляет `RTM_GETLINK` с `NLM_F_DUMP`, разбирает `RTM_NEWLINK` и атрибут `IFLA_IFNAME`. Ищутся точные имена `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, `xfrm0`; receive loop использует `poll(..., 2000)` и `recv()`.

### Точное условие срабатывания

В полном link dump получен хотя бы один `RTM_NEWLINK` с фиксированным VPN-именем.

## Что означает результат

Это один из наиболее важных путей: обычное приложение получает список netdev напрямую от ядра, даже когда `/proc` или `/sys` закрыты. Совпадение — сильный локальный признак.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Ищутся только шесть exact names. Проба не проверяет multipart truncation и sequence/pid строго; сбой send/poll/recv приводит к молчаливому отсутствию результата. Userspace hook только на `getifaddrs()` этот путь не закрывает.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси. Второй Android user не получает отдельный network namespace, поэтому рабочее/частное пространство обычно видит тот же RTM_GETLINK dump.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Для raw netlink нужен kernel-level filter или эквивалентная системная изоляция. Zygisk должен перехватить конкретное семейство recv-вызовов и всё равно остаётся обходным; upstream VPNHide прямо фиксирует этот предел.

### Как проверить результат

```bash
adb shell ip -details link show
adb shell 'ip -o link | grep -E "tun0|tun1|utun0|wg0|ppp0|xfrm0"'
```
`ip` также использует rtnetlink, но shell UID может получать другой отфильтрованный view.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Ошибочный skb/netlink filter может зависнуть на dump, повредить multipart reply или сломать сеть системным UID.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по `RTM_GETLINK`, `RTM_NEWLINK`, `IFLA_IFNAME`, six-name allowlist и HIGH_CONFIDENCE set.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- Внешняя первичная документация или официальный проект: [netlink(7)](https://man7.org/linux/man-pages/man7/netlink.7.html).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `getifaddrs-vpn`, `trim-oracle`, `ifindexname-vpn`, `interface-enumeration`.

[К справочнику Native signs](../)
