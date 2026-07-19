---
title: "Legacy маршруты через фиксированные VPN-имена"
permalink: /help/ru/native/route-vpn-interface/
---

# Legacy маршруты через фиксированные VPN-имена

> **ID:** `ROUTE_VPN_INTERFACE`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectVpnRoutes()` читает `/proc/net/route`, считает строки на `tun0`, `tun1`, `utun0`, `ppp0`, `wg0`, `wg1` и выдаёт `route_vpn_iface|vpn_routes=N`, если count > 0. Это legacy high.

### Точное условие срабатывания

Хотя бы одна строка `/proc/net/route` использует фиксированный VPN iface.

## Что означает результат

Прямой IPv4 procfs leak. Он не зависит от того, является ли маршрут default.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

На новых Android SELinux часто закрывает procfs обычному приложению; тогда отсутствие строки не означает clean. IPv6 и netlink покрываются другими signals.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Без root исправляют не отображение таблицы, а саму схему маршрутизации. Для чистого телефона используйте внешний шлюз. Если VPN остаётся в `VpnService`, настройте split routing так, чтобы проверяемое приложение действительно выходило через ожидаемую физическую сеть, но не считайте это скрытием локальных маршрутов: интерфейс и policy rules могут оставаться видимыми. Не удаляйте маршруты командами `ip route` на рабочем устройстве — Android и VPN-служба восстановят их, а связь можно оборвать.

### С root

На root-устройстве нужен backend, который фильтрует источник данных, а не только libc. В upstream VPNHide kernel-бэкенды предназначены для `ioctl`, netlink и части route/procfs-векторов; Zygisk остаётся условным fallback. Не ставьте kmod и KPM одновременно: они могут перехватывать одни и те же функции ядра. Расширенные PMTU/MSS/qdisc/BPF-векторы заявлены VPNHide Next, но это внешнее заявление, которое надо воспроизвести на конкретном ядре. Upstream VPNHide документирует фильтрацию `/proc/net/route`; raw open/read должен быть закрыт kernel backend, если SELinux на ROM разрешает файл.

### Как проверить результат

```bash
adb shell cat /proc/net/route 2>&1 | head -80
```
`permission denied` — путь недоступен shell; приложение может иметь другой результат.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Нельзя редактировать procfs как файл. Удаление маршрутов ломает сеть.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по parser `/proc/net/route` и fixed name list; kind high.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [/proc/pid/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- Внешняя первичная документация или официальный проект: [VPNHide proc route coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `route-table`, `proc-ipv6-route-vpn`, `vpn-policy-rules`.

[К справочнику Native signs](../)
