---
title: "NETLINK_SOCK_DIAG недоступен приложению"
permalink: /help/ru/native/inet-diag-denied/
---

# NETLINK_SOCK_DIAG недоступен приложению

> **ID:** `INET_DIAG_DENIED`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба выполняет только `socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)`. Если создание сокета возвращает EACCES/EPERM, выдаётся `inet_diag_denied`; успешный socket сразу закрывается без dump. Kind medium review.

### Точное условие срабатывания

Ядро/SELinux запрещает создать NETLINK_SOCK_DIAG socket.

## Что означает результат

Это характеристика sandbox/ROM. Запрет не доказывает VPN; скорее он предотвращает чтение socket diagnostics. Строку следует использовать для объяснения недоступного покрытия.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Не проверяется возможность отправить SOCK_DIAG request после успешного socket и не различаются protocol-family policies. На stock Android запрет может быть ожидаемым.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Не пытайтесь обходить запрет. Сравните с baseline на той же прошивке и учитывайте, что остальные socket checks работают независимо.

### С root

Не выдавайте NET_ADMIN/NET_RAW и не расширяйте sepolicy RKNHardering. При разработке ROM проверьте минимальную политику в тестовом домене, не в production untrusted_app.

### Как проверить результат

```bash
adb shell 'cat /proc/net/netlink 2>/dev/null | head'
adb logcat -d | grep -Ei 'avc: denied.*sock_diag|NETLINK_SOCK_DIAG' | tail -30
```
Точный результат виден только из app domain.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Открытие inet_diag обычным приложениям может раскрывать сокеты других UID и ослабить приватность.

### Откат

Удалите capability/sepolicy change и перезагрузитесь. Проверьте SELinux enforcing.

## Уровень доказательности

**Средняя.** Проверено по единственной EACCES/EPERM branch и medium path checker.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [sock_diag kernel documentation](https://www.kernel.org/doc/html/latest/networking/diagnostic.html).
- Внешняя первичная документация или официальный проект: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `established-vpn-socket`, `syscall-unavailable`, `fib-trie-denied`.

[К справочнику Native signs](../)
