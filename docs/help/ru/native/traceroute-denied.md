---
title: "Loopback UDP send с TTL=1 получил EACCES"
permalink: /help/ru/native/traceroute-denied/
---

# Loopback UDP send с TTL=1 получил EACCES

> **ID:** `TRACEROUTE_DENIED`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба создаёт обычный UDP socket, ставит `IP_TTL=1` и send timeout 100 ms, затем отправляет 64 bytes на `127.0.0.1:33434`. Строка появляется только если sendto вернул -1 именно с EACCES. ICMP reply, hop и внешний traceroute не измеряются.

### Точное условие срабатывания

EACCES при локальной UDP sendto после установки TTL=1.

## Что означает результат

Это признак policy/firewall denial для конкретного socket path. Он не доказывает VPN encapsulation. Checker выставляет review средней уверенности.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Название «traceroute» условное: destination loopback, raw socket не используется, hop discovery отсутствует. EPERM/ENETUNREACH/другие errno вообще не выводятся.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Отключите сторонний local firewall/DNS/VPN для контрольного запуска и запишите, исчезает ли EACCES. Не пытайтесь разрешить внешний traceroute — проверка локальная.

### С root

Проверьте UID-specific iptables/nftables и AVC. Не делайте flush; найдите точное правило, применяемое к loopback UDP/33434 или TTL-marked traffic.

### Как проверить результат

```bash
adb logcat -d | grep -E 'avc: denied|33434|traceroute' | tail -80
adb shell su -c 'iptables-save | grep -E "33434|owner|uid|lo"; ip6tables-save | grep -E "33434|owner|uid|lo"'
```
Shell packet может пройти, даже если app UID заблокирован.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Глобальный firewall flush может раскрыть трафик, отключить kill-switch и нарушить безопасность. Меняйте только подтверждённое UID-rule.

### Откат

Восстановите сохранённый ruleset/модуль и перезапустите firewall/VPN. Проверьте DNS и kill-switch.

## Уровень доказательности

**Средняя.** Проверено по loopback destination, TTL=1 и единственной EACCES branch; medium default.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [ip(7) IP_TTL](https://man7.org/linux/man-pages/man7/ip.7.html).
- Внешняя первичная документация или официальный проект: [sendto(2)](https://man7.org/linux/man-pages/man2/sendto.2.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `udp-pmtu-fail`, `syscall-unavailable`, `inet-diag-denied`.

[К справочнику Native signs](../)
