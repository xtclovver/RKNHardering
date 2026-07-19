---
title: "Занятые TCP-порты на 127.0.0.1"
permalink: /help/ru/native/loopback-port-conflict/
---

# Занятые TCP-порты на 127.0.0.1

> **ID:** `LOOPBACK_PORT_CONFLICT`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Для портов 51820, 1194, 443, 8443 создаётся TCP socket с SO_REUSEADDR и выполняется bind к `127.0.0.1`. Только `EADDRINUSE` выдаёт `loopback_port_conflict`; legacy policy high.

### Точное условие срабатывания

Невозможно bind выбранный localhost TCP port из-за `address already in use`.

## Что означает результат

Показывает listener или конфликтующий bind, но не его владельца. 443/8443 могут использоваться локальным web UI, dev server или security app, не обязательно VPN.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

SO_REUSEADDR и Android socket semantics влияют на результат. Проба не сканирует все порты, IPv6 `::1` и UDP.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Сначала удалите реальный артефакт: выключите ненужный listener, API-порт, локальный демон или VPN-клиент; затем force-stop приложения и повторите тест. Если нужен VPN, внешний шлюз обычно чище любого локального обхода. Второй профиль может ограничить package visibility, но не гарантирует сокрытие сетевых объектов и сам создаёт сигнал user/profile. Определите процесс и отключите ненужный local API. Простая смена порта помогает только против фиксированного списка и не должна считаться полным решением.

### С root

Root позволяет фильтровать данные для конкретного UID, но добавляет собственную поверхность обнаружения. В VPNHide роли Apps и Ports предназначены соответственно для PackageManager и localhost; native-бэкенд закрывает поддерживаемые интерфейсные/маршрутные пути. Для нестандартного порта лучше сначала отключить control API, а не маскировать его. Любые iptables/nftables-правила применяйте через модуль с понятным откатом и проверяйте IPv4 и IPv6 loopback отдельно. VPNHide Ports предназначен для ограничения доступа target UID к loopback, но фактический bind conflict может оставаться виден в зависимости от реализации. Лучше не запускать listener.

### Как проверить результат

```bash
adb shell ss -ltn 2>/dev/null | grep -E '127\.0\.0\.1:(51820|1194|443|8443)'
adb shell lsof -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ':(51820|1194|443|8443)'
```
`address already in use` означает, что порт занят.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Остановка неизвестного системного listener может нарушить приложение. Глобальный firewall loopback ломает IPC/local APIs.

### Откат

Верните сервис или удалите только созданное UID-rule. Не открывайте порт наружу вместо localhost.

## Уровень доказательности

**Высокая.** Проверено по четырём портам, AF_INET loopback и EADDRINUSE; kind high.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [bind(2)](https://man7.org/linux/man-pages/man2/bind.2.html).
- Внешняя первичная документация или официальный проект: [VPNHide Ports](https://github.com/okhsunrog/vpnhide).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `tcp-vpn-port`, `udp-port-conflict-physical`, `tcp-mss-low`.

[К справочнику Native signs](../)
