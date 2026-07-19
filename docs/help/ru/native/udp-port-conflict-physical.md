---
title: "Занятые VPN-порты UDP на физическом IPv4"
permalink: /help/ru/native/udp-port-conflict-physical/
---

# Занятые VPN-порты UDP на физическом IPv4

> **ID:** `UDP_PORT_CONFLICT_PHYSICAL`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба берёт первый IPv4 из `getifaddrs()`, исключая имена с substrings `tun`, `wg`, `ppp`, `xfrm`, `utun` и `lo`. Затем с SO_REUSEADDR пытается bind UDP на этом IP к портам 500, 4500, 1194, 1701, 51820. Только EADDRINUSE добавляет порт в result.

### Точное условие срабатывания

Хотя бы один из пяти UDP-портов уже занят на выбранном «физическом» IPv4.

## Что означает результат

На этом локальном адресе существует конфликтующий bind, часто соответствующий IKE/IPsec, OpenVPN, L2TP или WireGuard. Checker считает сигнал высоким, но владелец порта не устанавливается.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Первые `getifaddrs` records не гарантируют основной физический путь; container/OEM interface может быть выбран ошибочно. Порты имеют легитимные применения. SO_REUSEADDR/REUSEPORT и bind semantics могут давать разные результаты.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Сначала удалите реальный артефакт: выключите ненужный listener, API-порт, локальный демон или VPN-клиент; затем force-stop приложения и повторите тест. Если нужен VPN, внешний шлюз обычно чище любого локального обхода. Второй профиль может ограничить package visibility, но не гарантирует сокрытие сетевых объектов и сам создаёт сигнал user/profile. Остановите только известный вам VPN/server listener. Клиентский Android `VpnService` обычно не обязан слушать эти порты на physical IP, поэтому сначала найдите владельца.

### С root

Root позволяет фильтровать данные для конкретного UID, но добавляет собственную поверхность обнаружения. В VPNHide роли Apps и Ports предназначены соответственно для PackageManager и localhost; native-бэкенд закрывает поддерживаемые интерфейсные/маршрутные пути. Для нестандартного порта лучше сначала отключить control API, а не маскировать его. Любые iptables/nftables-правила применяйте через модуль с понятным откатом и проверяйте IPv4 и IPv6 loopback отдельно. Используйте `ss -ulpn`/`lsof` под root для атрибуции. Не скрывайте порт, пока не подтвержден процесс; перенос listener — более чистое решение, чем kernel hook.

### Как проверить результат

```bash
adb shell su -c 'ip -4 -br addr; ss -H -u -l -n -p | grep -E ":(500|4500|1194|1701|51820)( |$)"'
```
`connection/listener not shown` не исключает краткоживущий или namespace-specific bind; повторите саму проверку.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Остановка IKE/IMS/VPN процесса может оборвать мобильную связь или корпоративный туннель. Firewall не освобождает bind и потому может не убрать этот сигнал.

### Откат

Перезапустите остановленный сервис/VPN, верните прежний порт и удалите только временное UID-rule. Перезагрузка обычно освобождает тестовые sockets.

## Уровень доказательности

**Высокая.** Проверено по выбору first physical IPv4, five-port list и EADDRINUSE; kind high.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [bind(2)](https://man7.org/linux/man-pages/man2/bind.2.html).
- Внешняя первичная документация или официальный проект: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `udp-vpn-port`, `loopback-port-conflict`, `established-vpn-socket`.

[К справочнику Native signs](../)
