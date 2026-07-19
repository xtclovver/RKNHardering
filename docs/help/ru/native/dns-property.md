---
title: "Зарезервированный ID dns_prop"
permalink: /help/ru/native/dns-property/
---

# Зарезервированный ID dns_prop

> **ID:** `DNS_PROPERTY`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** ID сохранён для совместимости; отдельного producer в 2.10.0 нет
> **Роль в вердикте:** Реестр/совместимость

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`DNS_PROPERTY` и legacy mapping `dns_prop` сохранены в каталоге и UI, однако `native_signs_probe.cpp` версии 2.10.0 не формирует строку `dns_prop`. DNS-похожие keys `net.vpn.dns*` и `dhcp.tun0.dns*` сейчас попадают в общий kind `vpn_prop`, то есть на страницу `vpn-property`.

### Точное условие срабатывания

Отдельного положительного producer нет. Checker всё равно выводит информационную строку «не найдено» для этого kind.

## Что означает результат

Страница нужна для стабильности URL и обратной совместимости. Она не означает, что DNS вообще не проверяется: server-side DNS и `vpn_prop` находятся в других категориях.

**Как строка влияет на отчёт:** ID сохранён в каталоге и UI, однако текущая версия 2.10.0 не формирует отдельную положительную строку этого kind. Обычно рядом работает более конкретный сигнал.

## Ограничения и возможные ложные срабатывания

Будущая версия может вернуть отдельный `dns_prop`; при обновлении кода страницу надо сверить заново.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для текущей версии обходить этот ID не требуется. Исправляйте реальные DNS-сигналы: согласуйте resolver с ожидаемым маршрутом, исключите leak и проверяйте HTTP/DNS/UDP вместе.

### С root

Root не нужен для отсутствующего producer. Не устанавливайте модуль только ради зелёной строки `dns-property`; он может добавить root/hook признаки.

### Как проверить результат

```bash
rg -n 'dns_prop|DNS_PROPERTY' app/src/main
rg -n 'net\.vpn\.dns|dhcp\.tun0\.dns' app/src/main/cpp/native_signs_probe.cpp
```
Первый поиск покажет catalog/UI mapping, второй — реальный `vpn_prop` producer.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Главный риск — принять registry-only строку за отсутствие DNS-утечки.

### Откат

Не требуется; верните только изменения DNS, если они ухудшили сеть.

## Уровень доказательности

**Реестр/совместимость.** Проверено по отсутствию literal producer `dns_prop` в C++ и наличию mapping в `NativeSignalCatalog`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [Android DNS/VPN Builder](https://developer.android.com/reference/android/net/VpnService.Builder).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `vpn-property`, `general-diagnostics`.

[К справочнику Native signs](../)
