---
title: "UID/EUID/GID процесса равен 0"
permalink: /help/ru/native/root-uid/
---

# UID/EUID/GID процесса равен 0

> **ID:** `ROOT_UID`
> **Категория:** Root и состояние системы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проба вызывает `getuid()`, `geteuid()` и `getgid()`. Если любое значение равно нулю, detail содержит все три числа; checker присваивает high-confidence review.

### Точное условие срабатывания

RKNHardering реально запущен с uid, euid или gid 0.

## Что означает результат

Для обычного Android-приложения это чрезвычайно сильная аномалия. Чаще всего причина — запуск под root/контейнером, изменённый launcher или тестовый harness.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Обычный root на устройстве не делает все приложения uid 0, поэтому отсутствие сигнала ничего не говорит о Magisk/KernelSU. Supplemental group с привилегиями, но не gid 0, здесь не анализируется.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Установите APK обычным PackageManager и запускайте из стандартного launcher. Не используйте `su -c am start` или root-обёртку. Переустановка в owner user обычно восстанавливает нормальный app UID.

### С root

Не выдавайте приложению root и проверьте, что модуль не меняет credentials процесса. Hide root здесь не нужен: правильное состояние — обычный app UID, даже если root manager установлен.

### Как проверить результат

```bash
adb shell pidof com.notcvnt.rknhardering
adb shell ps -A -o USER,UID,GID,PID,NAME | grep rknhardering
```
На части Android формат `ps` отличается; detail приложения остаётся источником истины.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Запуск GUI-приложения uid 0 даёт ему полный доступ к данным и резко увеличивает ущерб от ошибки.

### Откат

Остановите root-обёртку, очистите её автозапуск и переустановите APK обычным способом.

## Уровень доказательности

**Средняя.** Проверено по прямому условию uid/euid/gid == 0.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Android application sandbox](https://source.android.com/docs/security/app-sandbox).
- Внешняя первичная документация или официальный проект: [credentials(7)](https://man7.org/linux/man-pages/man7/credentials.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `root-su-binary`, `root-management`.

[К справочнику Native signs](../)
