---
title: "Происхождение ключевых libc-символов"
permalink: /help/ru/native/library-integrity/
---

# Происхождение ключевых libc-символов

> **ID:** `LIBRARY_INTEGRITY`
> **Категория:** Хуки и целостность процесса
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

C++ вызывает `dlsym(RTLD_DEFAULT)` и `dladdr()` для `getifaddrs`, `if_nametoindex`, `socket`, `fopen`, `inet_ntop`, `ioctl`. Символ считается подозрительным, если отсутствует либо его библиотека не содержит `libc.so`, `libc++` или `libm.so`. Каждая такая строка — medium review.

### Точное условие срабатывания

Missing symbol или разрешение адреса в неожиданную библиотеку.

## Что означает результат

Сигнал хорошо выявляет часть PLT/ELF interposition и нештатную libc-обёртку. Он не доказывает VPN, но объясняет, почему результаты API могут быть подменены.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Inline hook внутри оригинального `libc.so`, trampolines и raw syscall могут не изменить результат `dladdr`. Производительская библиотека или sanitizer в debug-сборке может быть легитимной.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Используйте официальный APK без repack, sanitizer и стороннего loader. Если это ваша debug-сборка, повторите на release. Rootless virtualization/LSPatch следует полностью убрать из процесса, а не только переименовать пакет.

### С root

Исключите RKNHardering из Zygisk/Xposed scope. Для VPN-сокрытия используйте out-of-process system_server/kernel backend. Проверяйте после reboot: force-stop не выгружает framework из zygote.

### Как проверить результат

Встроенный detail показывает `symbol`, адрес и библиотеку. Для native test harness можно повторить `dlsym`/`dladdr`; обычный `ldd` для APK не воспроизводит runtime namespace. Полезная команда разработчика:
```bash
rg -n 'nativeLibraryIntegrity|dlsym|dladdr' app/src/main/cpp/native_signs_probe.cpp
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Замена системной libc или linker-конфигурации может сделать устройство незагружаемым. Не пытайтесь «исправлять» адреса бинарным патчем на рабочем телефоне.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Средняя.** Проверено по точному списку шести символов и allowlist библиотек в `evaluateLibraryIntegrity()`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [dladdr(3)](https://man7.org/linux/man-pages/man3/dladdr.3.html).
- Внешняя первичная документация или официальный проект: [dlsym(3)](https://man7.org/linux/man-pages/man3/dlsym.3.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `hook-markers`, `rwx-memory-regions`, `jvm-native-mismatch`.

[К справочнику Native signs](../)
