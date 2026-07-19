---
title: "Время socket/sendto на ARM64 через CNTVCT_EL0"
permalink: /help/ru/native/timing-oracle/
---

# Время socket/sendto на ARM64 через CNTVCT_EL0

> **ID:** `TIMING_ORACLE`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Низкая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

На arm64 выполняются 10 серий: чтение cycle counter, создание UDP socket, sendto 64 bytes на `127.0.0.1:53`, close, второе чтение. Выводятся min/max/avg cycles. На другой ABI выводится `not_arm64`. Оба варианта informational low.

### Точное условие срабатывания

Строка создаётся всегда при вызове: числа на arm64 или `not_arm64` иначе. Порог «VPN обнаружен» отсутствует.

## Что означает результат

Это raw performance telemetry. Без baseline, статистики и контроля частоты CPU значения не интерпретируются. В текущей версии timing не влияет на detected/review.

**Как строка влияет на отчёт:** Строка информационная либо диагностическая. Она нужна для сравнения запусков, но сама по себе не доказывает VPN или вмешательство.

## Ограничения и возможные ложные срабатывания

10 измерений мало; scheduler, DVFS, thermal throttling, emulator, background load и timer frequency влияют сильнее VPN. Loopback send не проходит VPN data path. Нет нормализации cntfrq.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для диагностического сигнала сначала ничего не «исправляйте». Запишите baseline на том же устройстве без VPN, затем повторите с VPN при одинаковой сети, температуре и нагрузке. Только воспроизводимая разница между сериями пригодна для анализа. Одиночное значение MTU, времени или GSO не является доказательством. Перед серией закройте нагрузку, стабилизируйте температуру и повторите не менее 20 запусков. Сравнивайте распределения, не одно avg.

### С root

Root-модуль может изменить этот показатель, но настройка ради конкретного числа легко нарушает TCP/UDP, DNS, звонки или энергопотребление. VPNHide Next заявляет фильтрацию ряда косвенных параметров, однако такие возможности нужно проверять отдельно от базового сокрытия интерфейсов. Не включайте максимальный набор kernel hooks до получения чистого baseline и рабочего отката. Не подменяйте CNTVCT или scheduler ради документации: это затронет криптографию, таймеры и anti-tamper. Для benchmark лучше perfetto/simpleperf в отдельной сборке.

### Как проверить результат

```bash
adb shell getprop ro.product.cpu.abi
adb shell dumpsys thermalservice | head -80
adb shell top -b -n 1 | head -30
```
Числа берите из нескольких отчётов RKNHardering при одинаковых условиях.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Фиксация CPU frequency/governor требует root, увеличивает нагрев и может повредить батарею при длительном тесте. Не держите performance mode постоянно.

### Откат

Верните governor/thermal настройки по умолчанию и перезагрузитесь. Для информационного сигнала обход не нужен.

## Уровень доказательности

**Низкая.** Проверено по 10 iterations, CNTVCT_EL0 и INFORMATIONAL_KINDS.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Arm generic timer documentation](https://developer.arm.com/documentation/102379/latest/).
- Внешняя первичная документация или официальный проект: [Perfetto](https://perfetto.dev/docs/).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `backpressure`, `gso-ok`, `general-diagnostics`.

[К справочнику Native signs](../)
