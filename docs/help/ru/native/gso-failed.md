---
title: "UDP_SEGMENT не принят setsockopt()"
permalink: /help/ru/native/gso-failed/
---

# UDP_SEGMENT не принят setsockopt()

> **ID:** `GSO_FAILED`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Низкая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба создаёт UDP socket и пытается `setsockopt(IPPROTO_UDP, UDP_SEGMENT, 1200)`. При ошибке выводится errno `gso_failed`; в checker это informational low, потому что отсутствие GSO не считается VPN-признаком.

### Точное условие срабатывания

Kernel/libc возвращает ошибку при настройке UDP_SEGMENT.

## Что означает результат

Показывает, что UDP GSO недоступен этому socket/ядру/среде. Это зависит от kernel config и API support, а не только от VPN.

**Как строка влияет на отчёт:** Строка информационная либо диагностическая. Она нужна для сравнения запусков, но сама по себе не доказывает VPN или вмешательство.

## Ограничения и возможные ложные срабатывания

Не различаются ENOPROTOOPT, EINVAL, EPERM и другие причины в логике verdict. Android kernels и vendor backports различаются. Не проверяется physical interface path.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для диагностического сигнала сначала ничего не «исправляйте». Запишите baseline на том же устройстве без VPN, затем повторите с VPN при одинаковой сети, температуре и нагрузке. Только воспроизводимая разница между сериями пригодна для анализа. Одиночное значение MTU, времени или GSO не является доказательством. Запишите errno и kernel version. Не меняйте VPN ради отсутствующей kernel feature.

### С root

Root-модуль может изменить этот показатель, но настройка ради конкретного числа легко нарушает TCP/UDP, DNS, звонки или энергопотребление. VPNHide Next заявляет фильтрацию ряда косвенных параметров, однако такие возможности нужно проверять отдельно от базового сокрытия интерфейсов. Не включайте максимальный набор kernel hooks до получения чистого baseline и рабочего отката. Не загружайте неизвестный kernel module ради UDP_SEGMENT. Поддержка требует совместимого kernel/network stack, а не Magisk property.

### Как проверить результат

```bash
adb shell uname -a
adb shell zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_INET|CONFIG_UDP' | head -40
```
Точный errno берётся из detail RKNHardering.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Замена ядра ради GSO может привести к bootloop, несовместимости модулей и потере данных. Этот информационный сигнал не оправдывает риск.

### Откат

Верните stock boot/kernel image и удалите экспериментальный module; перезагрузитесь.

## Уровень доказательности

**Низкая.** Проверено по UDP_SEGMENT=1200 failure branch; informational.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).
- Внешняя первичная документация или официальный проект: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `gso-send-failed`, `gso-ok`, `normal-pmtu`.

[К справочнику Native signs](../)
