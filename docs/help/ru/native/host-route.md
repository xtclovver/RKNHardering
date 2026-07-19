---
title: "Публичный /32 или /128 host-route через физический интерфейс"
permalink: /help/ru/native/host-route/
---

# Публичный /32 или /128 host-route через физический интерфейс

> **ID:** `HOST_ROUTE`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`isVpnServerHostRouteCandidate()` рассматривает только netlink-строки: не default, prefix `/32` или `/128`, тип `unicast`, scope `global`/`link`, не local table 255 и не protocol kernel. Destination должен быть публично маршрутизируемым, а интерфейс — стандартным физическим. Такой маршрут похож на pinning адреса VPN-сервера вне туннеля, но также встречается у операторских и системных сервисов.

### Точное условие срабатывания

Подходящий публичный host route создаёт `needsReview=true`, confidence medium. `detected` остаётся false.

## Что означает результат

Это кандидат, а не доказательство. На типичном Android `VpnService` серверный socket обычно выводится из VPN через `protect()`/fwmark без отдельного host-route, поэтому сигнал чаще важен для root/kernel VPN или нестандартного клиента.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

CDN, captive portal, carrier IMS, OEM security service и статическая сеть могут создавать законный /32. Без process/socket correlation нельзя назвать адрес VPN endpoint.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Сначала установите владельца маршрута по времени появления: сравните снимки до запуска VPN, после запуска и после отключения. Если маршрут создаёт ваш клиент, предпочтите его штатный `VpnService.protect()`/split-route механизм; не удаляйте маршрут вручную. Внешний шлюз убирает локальный host-route.

### С root

Kernel backend может скрывать такую форму маршрута, но shape-based фильтрация рискует убрать легитимный /32. Upstream VPNHide документирует host-route logic главным образом для desktop-style/root VPN. Проверяйте, что target traffic действительно идёт через физическую сеть и что server socket не зацикливается.

### Как проверить результат

```bash
adb shell ip -4 route show table all | grep -E '(^| )/32| scope link'
adb shell ip -6 route show table all | grep '/128'
```
Снимите три состояния: VPN выключен, включён, клиент остановлен. Адрес не публикуйте в issue без маскирования.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление host-route может завернуть VPN-соединение внутрь самого туннеля и оборвать его. Фильтрация слишком широкого класса маршрутов ломает операторские сервисы.

### Откат

Перезапустите VPN-клиент или сеть, чтобы он восстановил маршрут. Root hook отключите через менеджер и перезагрузитесь.

## Уровень доказательности

**Средняя.** Проверено по строгому allowlist-условию `isVpnServerHostRouteCandidate()` и unit-тестам host-route. Сигнал намеренно review-only.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [VpnService.protect()](https://developer.android.com/reference/android/net/VpnService).
- Внешняя первичная документация или официальный проект: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- Внешняя первичная документация или официальный проект: [VPNHide host-route notes](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `route-table`, `vpn-policy-rules-netlink`, `established-vpn-socket`.

[К справочнику Native signs](../)
