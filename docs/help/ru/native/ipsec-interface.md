---
title: "Интерфейсы IPsec/XFRM"
permalink: /help/ru/native/ipsec-interface/
---

# Интерфейсы IPsec/XFRM

> **ID:** `IPSEC_INTERFACE`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Низкая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Активные интерфейсы сопоставляются с регулярным выражением `^(ipsec|xfrm).*`. В отличие от TUN-паттернов, строка выводится как информационная: Android, OEM VPN и системные IPsec-компоненты могут создавать такие интерфейсы легитимно.

### Точное условие срабатывания

Любой активный интерфейс с именем `ipsec*` или `xfrm*` создаёт информационную строку с именем и индексом.

## Что означает результат

Сам по себе сигнал не переводит категорию в detected и не требует обхода. Он становится полезен только вместе с маршрутами, XFRM/β-данными, внешним IP или активным VPN transport.

**Как строка влияет на отчёт:** Строка информационная либо диагностическая. Она нужна для сравнения запусков, но сама по себе не доказывает VPN или вмешательство.

## Ограничения и возможные ложные срабатывания

IPsec может использовать policy/XFRM state без отдельного интерфейса, а OEM может выбрать другое имя. И наоборот, корпоративный профиль может законно поднять xfrm-интерфейс.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Если IPsec действительно не нужен, отключите соответствующий корпоративный VPN/always-on профиль штатными средствами. Если нужен, не переименовывайте интерфейс ради информационной строки. Внешний шлюз убирает IPsec state с телефона.

### С root

Kernel-фильтрация возможна только как часть согласованного сокрытия interfaces/routes/XFRM. Не удаляйте xfrm state командами `ip xfrm state flush`: это оборвёт соединение и может нарушить корпоративную политику. Для теста используйте отдельное устройство.

### Как проверить результат

```bash
adb shell ip -details link show | grep -Ei 'ipsec|xfrm'
adb shell ip xfrm state 2>&1 | head -80
adb shell ip xfrm policy 2>&1 | head -80
```
На обычном shell часть XFRM может быть закрыта — это не означает отсутствия.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Отключение always-on/lockdown VPN может убрать обязательную защиту трафика. Изменение XFRM state требует привилегий и немедленно ломает сессию.

### Откат

Верните корпоративный профиль или VPN-конфигурацию, затем перезагрузите сеть. Если применялся root-модуль, отключите его и перезагрузитесь.

## Уровень доказательности

**Низкая.** Проверено по `NetworkInterfacePatterns.IPSEC_INTERFACE_PATTERN` и информационной ветке `evaluateInterfaces()`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NetworkInterfacePatterns.kt` — правила имён интерфейсов](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Linux XFRM device documentation](https://docs.kernel.org/networking/xfrm_device.html).
- Внешняя первичная документация или официальный проект: [Android VPN guide](https://developer.android.com/develop/connectivity/vpn).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `interface-enumeration`, `vpn-policy-rules-netlink`, `route-table`.

[К справочнику Native signs](../)
