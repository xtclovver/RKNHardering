---
title: "Подозрительные policy rules через RTM_GETRULE"
permalink: /help/ru/native/vpn-policy-rules-netlink/
---

# Подозрительные policy rules через RTM_GETRULE

> **ID:** `VPN_POLICY_RULES_NETLINK`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба отправляет IPv4 `RTM_GETRULE` dump и разбирает `RTM_NEWRULE`. Таблица берётся из `rtm_table` или `RTA_TABLE`, выходной интерфейс — из `RTA_OIF`, условный mark — из `RTA_FLOW`. Рассматриваются таблицы 100…200; правило считается VPN-like, если интерфейс равен одному из fixed tunnel names или номер таблицы 100…110.

### Точное условие срабатывания

Хотя бы одно правило table 100…110 независимо от iface либо table 100…200 с OIF `tun0/tun1/utun0/wg0/ppp0/xfrm0`.

## Что означает результат

Routing policy database содержит правило, которое heuristic связывает с VPN. Checker считает строку высокой уверенности.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Диапазоны таблиц эвристические и могут совпасть с OEM, enterprise, tethering или custom routing. `RTA_FLOW` здесь подписан как fwmark, хотя Linux policy rules обычно используют FRA_FWMARK; detail может быть неполным. Проверяется только AF_INET, не IPv6.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Без root исправляют не отображение таблицы, а саму схему маршрутизации. Для чистого телефона используйте внешний шлюз. Если VPN остаётся в `VpnService`, настройте split routing так, чтобы проверяемое приложение действительно выходило через ожидаемую физическую сеть, но не считайте это скрытием локальных маршрутов: интерфейс и policy rules могут оставаться видимыми. Не удаляйте маршруты командами `ip route` на рабочем устройстве — Android и VPN-служба восстановят их, а связь можно оборвать. Если правило создаёт ваш VPN-клиент, выключение режима TUN/VpnService удалит его. Per-app exclusion не обязательно удаляет общие rules.

### С root

На root-устройстве нужен backend, который фильтрует источник данных, а не только libc. В upstream VPNHide kernel-бэкенды предназначены для `ioctl`, netlink и части route/procfs-векторов; Zygisk остаётся условным fallback. Не ставьте kmod и KPM одновременно: они могут перехватывать одни и те же функции ядра. Расширенные PMTU/MSS/qdisc/BPF-векторы заявлены VPNHide Next, но это внешнее заявление, которое надо воспроизвести на конкретном ядре. Upstream VPNHide kernel backends заявляют фильтрацию RTM_GETRULE. После установки обязательно сравните target UID и shell snapshot, потому что rule filtering должен быть per-UID.

### Как проверить результат

```bash
adb shell ip rule show
adb shell ip -details rule show
adb shell ip route show table all
```
Сопоставьте table 100–200, OIF и реальные назначения. Не удаляйте правило до понимания, кто его создал.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление policy rule может лишить сеть VPN, системный UID, IMS, tethering или рабочий профиль. Неверный netlink filter может менять маршрутизацию не только отображение.

### Откат

Перед изменением сохраните `ip rule show` и `ip route show table all`. Верните штатный VPN/NetworkStack, отключите модуль и перезагрузитесь; Android обычно пересоздаёт system rules.

## Уровень доказательности

**Высокая.** Проверено по RTM_GETRULE parser, table ranges и HIGH_CONFIDENCE mapping. Отмечена неточность RTA_FLOW/fwmark.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [rtnetlink rules](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- Внешняя первичная документация или официальный проект: [ip-rule manual](https://man7.org/linux/man-pages/man8/ip-rule.8.html).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `vpn-policy-rules`, `route-table`, `route-count`.

[К справочнику Native signs](../)
