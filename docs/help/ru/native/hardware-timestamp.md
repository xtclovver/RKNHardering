---
title: "SIOCSHWTSTAMP успешно настроен на loopback"
permalink: /help/ru/native/hardware-timestamp/
---

# SIOCSHWTSTAMP успешно настроен на loopback

> **ID:** `HW_TIMESTAMP`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Низкая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба вызывает `ioctl(SIOCSHWTSTAMP)` для интерфейса `lo` с `HWTSTAMP_TX_ON`. Только rc=0 создаёт строку `hw_timestamp|lo configured`; отдельно она пытается включить software `SO_TIMESTAMPING`, но результат не выводит. Finding informational low.

### Точное условие срабатывания

Kernel разрешил SIOCSHWTSTAMP на loopback для обычного app socket.

## Что означает результат

Это характеристика driver/kernel permissions, не VPN. На многих системах loopback не поддерживает hardware timestamping или операция требует прав, поэтому отсутствие строки ожидаемо.

**Как строка влияет на отчёт:** Строка информационная либо диагностическая. Она нужна для сравнения запусков, но сама по себе не доказывает VPN или вмешательство.

## Ограничения и возможные ложные срабатывания

Проба не читает negotiated config, не получает timestamp и не проверяет tunnel/physical interface. Успех может быть особенностью vendor kernel или hook.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для диагностического сигнала сначала ничего не «исправляйте». Запишите baseline на том же устройстве без VPN, затем повторите с VPN при одинаковой сети, температуре и нагрузке. Только воспроизводимая разница между сериями пригодна для анализа. Одиночное значение MTU, времени или GSO не является доказательством. Никаких изменений не требуется. Сравните с чистым устройством той же прошивки.

### С root

Root-модуль может изменить этот показатель, но настройка ради конкретного числа легко нарушает TCP/UDP, DNS, звонки или энергопотребление. VPNHide Next заявляет фильтрацию ряда косвенных параметров, однако такие возможности нужно проверять отдельно от базового сокрытия интерфейсов. Не включайте максимальный набор kernel hooks до получения чистого baseline и рабочего отката. Не выдавайте CAP_NET_ADMIN приложению. Для корректного timestamp benchmark используйте отдельный privileged test tool на тестовом устройстве.

### Как проверить результат

```bash
adb shell uname -r
adb shell 'ethtool -T lo 2>/dev/null || true'
```
`ethtool` может отсутствовать; точный SIOCSHWTSTAMP result показывает сама native-проба.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Изменение timestamping драйверов/прав может повлиять на PTP, logging и сетевую производительность. Этот информационный сигнал не требует обхода.

### Откат

Удалите тестовую capability/sepolicy и перезагрузитесь. Верните stock kernel при его замене.

## Уровень доказательности

**Низкая.** Проверено по SIOCSHWTSTAMP rc==0 и informational mapping.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Linux timestamping](https://docs.kernel.org/networking/timestamping.html).
- Внешняя первичная документация или официальный проект: [netdevice(7)](https://man7.org/linux/man-pages/man7/netdevice.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `timing-oracle`, `gso-ok`, `normal-pmtu`.

[К справочнику Native signs](../)
