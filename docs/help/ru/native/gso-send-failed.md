---
title: "UDP_SEGMENT принят, но отправка 4800 байт не удалась"
permalink: /help/ru/native/gso-send-failed/
---

# UDP_SEGMENT принят, но отправка 4800 байт не удалась

> **ID:** `GSO_SEND_FAILED`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Низкая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

После успешного `UDP_SEGMENT=1200` проба отправляет 4800-byte datagram на `127.0.0.1:53`. Если sendto возвращает -1, формируется `gso_send_failed|errno=N`. Checker показывает строку informational low.

### Точное условие срабатывания

GSO socket option принят, но loopback send большого буфера завершился ошибкой.

## Что означает результат

Это диагностика конкретного send path. Ошибка может быть связана с offload support, socket buffers, policy или kernel bug; VPN не доказан.

**Как строка влияет на отчёт:** Строка информационная либо диагностическая. Она нужна для сравнения запусков, но сама по себе не доказывает VPN или вмешательство.

## Ограничения и возможные ложные срабатывания

Не анализируется errno и фактическая segmentation. Loopback не равен physical/tunnel device. Receiver не нужен, delivery не проверяется.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для диагностического сигнала сначала ничего не «исправляйте». Запишите baseline на том же устройстве без VPN, затем повторите с VPN при одинаковой сети, температуре и нагрузке. Только воспроизводимая разница между сериями пригодна для анализа. Одиночное значение MTU, времени или GSO не является доказательством. Повторите после reboot без firewall/VPN и запишите errno. Не уменьшайте MTU наугад.

### С root

Root-модуль может изменить этот показатель, но настройка ради конкретного числа легко нарушает TCP/UDP, DNS, звонки или энергопотребление. VPNHide Next заявляет фильтрацию ряда косвенных параметров, однако такие возможности нужно проверять отдельно от базового сокрытия интерфейсов. Не включайте максимальный набор kernel hooks до получения чистого baseline и рабочего отката. Проверяйте kernel logs и vendor support. Не подменяйте только return value sendto: это создаёт ложный success и может скрыть реальную ошибку приложения.

### Как проверить результат

```bash
adb shell dmesg 2>/dev/null | grep -Ei 'udp|gso|segmentation|skb' | tail -80
adb shell uname -r
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Kernel/network sysctl эксперименты могут ухудшить UDP/QUIC и DNS. Не применяйте глобально на основном устройстве.

### Откат

Верните sysctl/kernel/module к baseline, перезагрузитесь и повторите DNS/QUIC тесты.

## Уровень доказательности

**Низкая.** Проверено по success-setsockopt/fail-send branch; informational.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).
- Внешняя первичная документация или официальный проект: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `gso-failed`, `gso-ok`, `udp-pmtu-fail`.

[К справочнику Native signs](../)
