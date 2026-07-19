---
title: "Established TCP-соединение на типичный VPN-порт"
permalink: /help/ru/native/established-vpn-socket/
---

# Established TCP-соединение на типичный VPN-порт

> **ID:** `ESTABLISHED_VPN_SOCKET`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectEstablishedVpn()` читает `/proc/net/tcp`, выбирает state `01` (ESTABLISHED) и remote port 51820, 1194, 1195, 443 или 8443. Формируется `established_vpn`; legacy policy оценивает medium review.

### Точное условие срабатывания

Established IPv4 TCP socket с одним из пяти remote ports.

## Что означает результат

1194/1195 похожи на OpenVPN, но 443/8443 широко используются обычным HTTPS, а WireGuard 51820 обычно UDP. Поэтому сигнал намеренно не high.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Не связывает socket с процессом или VPN app, не читает tcp6 и может быть закрыт SELinux. Port-based классификация даёт много false positives.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Смотрите remote IP и владельца соединения до изменений. Закройте ненужный VPN/API процесс, но не блокируйте 443. Внешний шлюз переносит server socket с телефона.

### С root

Не фильтруйте весь `/proc/net/tcp` или порт 443. Для per-UID сокрытия нужен корректный socket/proc policy, но это легко создаёт mismatch с inet_diag. Лучше устранить реальный локальный VPN socket.

### Как проверить результат

```bash
adb shell cat /proc/net/tcp 2>&1 | head -80
adb shell ss -tn 2>/dev/null | grep -E ':(51820|1194|1195|443|8443) '
```
Hex parser в приложении использует remote port.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Блокировка 443 ломает почти весь HTTPS. Публикуя таблицу sockets, маскируйте IP.

### Откат

Удалите точечное firewall rule и перезапустите приложение/соединение.

## Уровень доказательности

**Средняя.** Проверено по state и `isVpnPort()`; medium review.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
- Внешняя первичная документация или официальный проект: [/proc/pid/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `tcp-vpn-port`, `inet-diag-denied`, `host-route`.

[К справочнику Native signs](../)
