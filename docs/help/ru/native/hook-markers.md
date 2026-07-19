---
title: "Именованные маркеры инъекций в /proc/self/maps"
permalink: /help/ru/native/hook-markers/
---

# Именованные маркеры инъекций в /proc/self/maps

> **ID:** `HOOK_MARKERS`
> **Категория:** Хуки и целостность процесса
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Нативная функция читает `/proc/self/maps` текущего процесса и ищет подстроки `frida-agent`, `frida-gadget`, `libfrida`, `libsubstrate`, `com.saurik.substrate`, `XposedBridge`, `libxposed`, `lspatch`, `LSPosed`, `libriru`, `libzygisk`. Для совпадения сохраняются marker и полная строка map. Kotlin считает известные marker high confidence, но выставляет `needsReview`, а не прямой detected категории.

### Точное условие срабатывания

Любая строка maps с одним из фиксированных marker создаёт review; известные marker имеют high confidence.

## Что означает результат

Проверка показывает, что в процесс загружена библиотека или mapping с узнаваемым именем. Это сильный признак instrumentation, но не обязательно злонамеренного: тестовая сборка, accessibility/monitoring SDK или модуль пользователя тоже может быть причиной.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Переименование файла обходит строковый список, но не другие проверки целостности. Anonymous/memfd mappings могут не иметь marker. Наоборот, безобидный путь с таким словом теоретически даст совпадение.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Без root лучший вариант — чистый APK из доверенного источника без repack, LSPatch, Frida Gadget, виртуализатора и rootless-Xposed. Перенос приложения во «второе пространство» не очищает его процесс автоматически: контейнер может внедрять собственные библиотеки и оставить ещё больше расхождений.

### С root

При root не включайте целевое приложение в scope Xposed/Vector и не загружайте в него Zygisk-модуль без необходимости. Для VPN-сокрытия предпочтительна схема, где Java-фильтрация выполняется в `system_server`, а native-фильтрация — в ядре. DenyList/App Profile, NoHello, Zygisk Next, SUSFS и похожие инструменты могут уменьшать часть следов, но ни один из них не является гарантией против `maps`, linker, mount и raw-syscall проверок одновременно.

### Как проверить результат

Для собственного debuggable build можно снять maps через `run-as`:
```bash
adb shell run-as com.notcvnt.rknhardering cat /proc/self/maps 2>/dev/null | grep -Ei 'frida|xposed|lsposed|zygisk|riru|substrate|lspatch'
```
Для release `run-as` обычно недоступен. Используйте detail самой проверки и сравните с перечнем загруженных модулей.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Вывод `/proc/self/maps` содержит пути и структуру процесса; не публикуйте его целиком без очистки. Отключение модулей может повлиять на другие приложения.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Средняя.** Проверено по фиксированному массиву `kSuspiciousMarkers` и `evaluateHookMarkers()`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [/proc/pid/maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html).
- Внешняя первичная документация или официальный проект: [Vector](https://github.com/JingMatrix/Vector).
- Внешняя первичная документация или официальный проект: [Magisk/Zygisk](https://github.com/topjohnwu/Magisk).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `rwx-memory-regions`, `library-integrity`, `lsposed`, `hook-property`.

[К справочнику Native signs](../)
