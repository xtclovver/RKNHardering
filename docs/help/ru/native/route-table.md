---
title: "Основная таблица маршрутов и default route"
permalink: /help/ru/native/route-table/
---

# Основная таблица маршрутов и default route

> **ID:** `ROUTE_TABLE`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Смешанная

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Native probe собирает IPv4/IPv6 маршруты, в том числе netlink-метаданные, а `evaluateRoutes()` выделяет default routes и дедуплицирует их по canonical interface и семье адресов. Default route на VPN-like интерфейсе получает high. Default route на неизвестном не-стандартном интерфейсе — medium, но в текущем checker также отмечается `detected=true`. Стандартные `wlan*`, `rmnet*`, `eth*`, `lo`, `ccmni*`, `ccemni*`, `seth*`, `dummy*` выводятся информационно.

### Точное условие срабатывания

Срабатывание возникает, когда default route указывает на VPN-шаблон либо на интерфейс вне allowlist стандартных имён. Отсутствие default route лишь информационно.

## Что означает результат

VPN default route — сильный локальный сигнал. Необычный интерфейс требует проверки: OEM, tethering, CLAT и корпоративный стек могут использовать нестандартное имя.

**Как строка влияет на отчёт:** Один и тот же ID используется и для информационной сводки, и для подозрительных строк. Итог зависит от конкретного detail и ветки checker.

## Ограничения и возможные ложные срабатывания

Android policy routing сложнее одной main table; фактический маршрут конкретного UID может определяться fwmark и `ip rule`. Поэтому clean default route не исключает VPN, а route dump во время handover может быть кратковременно нестабилен.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Без root исправляют не отображение таблицы, а саму схему маршрутизации. Для чистого телефона используйте внешний шлюз. Если VPN остаётся в `VpnService`, настройте split routing так, чтобы проверяемое приложение действительно выходило через ожидаемую физическую сеть, но не считайте это скрытием локальных маршрутов: интерфейс и policy rules могут оставаться видимыми. Не удаляйте маршруты командами `ip route` на рабочем устройстве — Android и VPN-служба восстановят их, а связь можно оборвать.

### С root

На root-устройстве нужен backend, который фильтрует источник данных, а не только libc. В upstream VPNHide kernel-бэкенды предназначены для `ioctl`, netlink и части route/procfs-векторов; Zygisk остаётся условным fallback. Не ставьте kmod и KPM одновременно: они могут перехватывать одни и те же функции ядра. Расширенные PMTU/MSS/qdisc/BPF-векторы заявлены VPNHide Next, но это внешнее заявление, которое надо воспроизвести на конкретном ядре.

### Как проверить результат

```bash
adb shell ip -4 route show table all
adb shell ip -6 route show table all
adb shell ip rule show
```
Сверьте interface, family, table и default. Для маршрута конкретного приложения shell-снимок недостаточен из-за UID/fwmark.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Ручное удаление default route оставит устройство без сети. Неправильная фильтрация route dump может вызвать несовпадение с ifindex или Java `LinkProperties`.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Смешанная.** Проверено по `evaluateRoutes()`, canonicalization и спискам standard/VPN interfaces.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NetworkInterfacePatterns.kt` — правила имён интерфейсов](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- Внешняя первичная документация или официальный проект: [Android VpnService.Builder routes](https://developer.android.com/reference/android/net/VpnService.Builder).
- Внешняя первичная документация или официальный проект: [VPNHide route coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `host-route`, `route-vpn-interface`, `vpn-policy-rules-netlink`, `route-count`.

[К справочнику Native signs](../)
