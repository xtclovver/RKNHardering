---
title: "Отправка UDP 1500 байт на loopback завершилась ошибкой"
permalink: /help/ru/native/udp-pmtu-fail/
---

# Отправка UDP 1500 байт на loopback завершилась ошибкой

> **ID:** `UDP_PMTU_FAIL`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Это альтернативная ветка той же пробы: `sendto(127.0.0.1:53, 1500)` вернул -1, а detail содержит errno. В отличие от `udp-pmtu-ok`, kind не включён в informational set, поэтому текущий checker делает medium `needsReview`.

### Точное условие срабатывания

Любая ошибка sendto, независимо от errno.

## Что означает результат

Ошибка необычна для loopback, но не доказывает VPN. Причиной может быть SELinux/firewall hook, ресурсный предел, invalid socket state, cancellation race или изменённый network stack.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Код не классифицирует errno и не устанавливает IP_MTU_DISCOVER. Поэтому `EMSGSIZE` нельзя автоматически назвать PMTU, а EACCES/ENOBUFS имеют совсем другой смысл.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Запишите точный errno, перезагрузите устройство и повторите без VPN/firewall/DNS-filter app. Не уменьшайте MTU ради исчезновения ошибки.

### С root

Проверьте `dmesg`/AVC, iptables/nftables и модули socket hooks. Удаляйте только правило, которое реально блокирует loopback. Не выдавайте capabilities приложению.

### Как проверить результат

```bash
adb logcat -d | grep -E 'avc: denied|udp_pmtu|sendto' | tail -80
adb shell iptables-save 2>/dev/null | grep -E 'lo|127[.]0[.]0[.]1|dport 53'
adb shell ip6tables-save 2>/dev/null | grep -E 'lo|::1|dport 53'
```
Для errno используйте detail RKNHardering; shell send имеет другой UID.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Сброс всех firewall rules — разрушительный шаг: можно отключить VPN kill-switch и системную защиту. Не делайте глобальный flush.

### Откат

Восстановите сохранённые правила или отключите виновный модуль через его manager; перезагрузитесь и проверьте DNS.

## Уровень доказательности

**Средняя.** Проверено по catch-all failure branch и medium default evaluation.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [sendto(2)](https://man7.org/linux/man-pages/man2/sendto.2.html).
- Внешняя первичная документация или официальный проект: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `udp-pmtu-ok`, `traceroute-denied`, `syscall-unavailable`.

[К справочнику Native signs](../)
