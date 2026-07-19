---
title: "VPN-интерфейс в /proc/net/ipv6_route"
permalink: /help/ru/native/proc-ipv6-route-vpn/
---

# VPN-интерфейс в /proc/net/ipv6_route

> **ID:** `PROC_IPV6_ROUTE_VPN`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба читает `/proc/net/ipv6_route`, затем `/proc/self/net/ipv6_route`. Строка разбивается на десять токенов; десятый принимается за имя интерфейса. Совпадения с `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, `xfrm0` увеличивают count.

### Точное условие срабатывания

Хотя бы одна IPv6 route row с фиксированным VPN-именем.

## Что означает результат

Маршрутная таблица IPv6 прямо ссылается на VPN-like интерфейс. Даже выключенный IPv4 не закрывает этот путь.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Формат procfs kernel-specific и может быть закрыт SELinux. Проба не выводит destination/prefix/table, только count, поэтому для анализа нужен raw snapshot. Нестандартные имена не ловятся.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Без root исправляют не отображение таблицы, а саму схему маршрутизации. Для чистого телефона используйте внешний шлюз. Если VPN остаётся в `VpnService`, настройте split routing так, чтобы проверяемое приложение действительно выходило через ожидаемую физическую сеть, но не считайте это скрытием локальных маршрутов: интерфейс и policy rules могут оставаться видимыми. Не удаляйте маршруты командами `ip route` на рабочем устройстве — Android и VPN-служба восстановят их, а связь можно оборвать. Отключение IPv6 у профиля уменьшает поверхность, но может привести к утечке IPv6 мимо VPN либо полной потере IPv6; сначала тестируйте в отдельной сети.

### С root

На root-устройстве нужен backend, который фильтрует источник данных, а не только libc. В upstream VPNHide kernel-бэкенды предназначены для `ioctl`, netlink и части route/procfs-векторов; Zygisk остаётся условным fallback. Не ставьте kmod и KPM одновременно: они могут перехватывать одни и те же функции ядра. Расширенные PMTU/MSS/qdisc/BPF-векторы заявлены VPNHide Next, но это внешнее заявление, которое надо воспроизвести на конкретном ядре. Filter должен согласованно закрывать procfs и RTM_GETROUTE IPv6. Подмена только `/proc/net/ipv6_route` оставляет netlink dump.

### Как проверить результат

```bash
adb shell 'cat /proc/net/ipv6_route 2>/dev/null || cat /proc/self/net/ipv6_route 2>/dev/null'
adb shell ip -6 route show table all
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление IPv6 routes вручную может оборвать DNS/NAT64 и не переживёт пересоздание VPN. Kernel seq-file hook с ошибкой может повредить чтение procfs.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по двум proc paths, token[9] и six-name list; kind high.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [/proc/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- Внешняя первичная документация или официальный проект: [rtnetlink routes](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `route-table`, `rtm-getlink-vpn`, `proc-if-inet6-vpn`.

[К справочнику Native signs](../)
