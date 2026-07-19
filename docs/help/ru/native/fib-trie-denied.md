---
title: "Доступ к /proc/net/fib_trie запрещён или завершился ошибкой"
permalink: /help/ru/native/fib-trie-denied/
---

# Доступ к /proc/net/fib_trie запрещён или завершился ошибкой

> **ID:** `FIB_TRIE_DENIED`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectFibTrieAccess()` только открывает `/proc/net/fib_trie`. Успешное открытие ничего не выводит; `EACCES/EPERM` даёт `SELinux denies`, `ENOENT` нейтрален, прочий errno тоже создаёт строку. В deep checker kind не high и не informational, поэтому это medium `needsReview`.

### Точное условие срабатывания

Открытие `/proc/net/fib_trie` завершилось EACCES, EPERM или любой ошибкой кроме ENOENT.

## Что означает результат

Это проверка доступности диагностического пути, а не обнаружение VPN. На современном Android запрет для untrusted_app может быть нормальной политикой. Строка требует review, но не должна считаться основанием «исправить» SELinux.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Название может вводить в заблуждение: denied обычно повышает приватность и закрывает утечку. Код не пытается прочитать содержимое при успехе и не сообщает «accessible». Shell и app UID имеют разные SELinux domains.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Ничего не ослабляйте. Зафиксируйте Android/ROM и сравните с чистым устройством той же сборки. Если приложение показывает `errno=N`, расшифруйте errno и проверьте, не повреждён ли procfs mount.

### С root

Не добавляйте allow-rule только ради исчезновения строки: это откроет маршруты обычному приложению. Для лабораторной диагностики читайте AVC logs, а не переводите SELinux в permissive.

### Как проверить результат

```bash
adb shell 'cat /proc/net/fib_trie >/dev/null; echo shell_rc=$?'
adb logcat -d | grep -E 'avc: denied.*fib_trie' | tail -30
```
Shell success/failure не воспроизводит `untrusted_app`; итог проверяется внутри RKNHardering.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

SELinux permissive или широкое allow-rule раскрывает сетевое состояние и ослабляет весь sandbox. Это хуже самого review-сигнала.

### Откат

Удалите тестовое sepolicy-правило, верните enforcing и перезагрузите устройство. Убедитесь `getenforce` → `Enforcing`.

## Уровень доказательности

**Средняя.** Проверено по errno branches; kind остаётся medium review.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [/proc/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- Внешняя первичная документация или официальный проект: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `bpf-map-accessible`, `sysfs-vpn-leak`, `syscall-unavailable`.

[К справочнику Native signs](../)
