---
title: "Зарезервированный общий ID VPN-файлов"
permalink: /help/ru/native/vpn-file/
---

# Зарезервированный общий ID VPN-файлов

> **ID:** `VPN_FILE`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** ID сохранён для совместимости; отдельного producer в 2.10.0 нет
> **Роль в вердикте:** Реестр/совместимость

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Каталог содержит legacy kind `vpn_file`, но текущий `detectVpnFiles()` не выдаёт его. Он разделяет пути по prefix `vpnhide`, `lsposed` и `zygisk`. Первые два получают отдельные ID; `zygisk` не входит в legacy allowlist и отображается через `UNKNOWN`.

### Точное условие срабатывания

Отдельного `vpn_file` producer в 2.10.0 нет; строка этого ID обычно информационная «не найдено».

## Что означает результат

Это compatibility URL, а не активная файловая проверка. Реальные path checks описаны на `vpnhide`, `lsposed` и `unknown-signals`.

**Как строка влияет на отчёт:** ID сохранён в каталоге и UI, однако текущая версия 2.10.0 не формирует отдельную положительную строку этого kind. Обычно рядом работает более конкретный сигнал.

## Ограничения и возможные ложные срабатывания

Название может ввести в заблуждение: приложение всё же проверяет конкретные файлы, просто не назначает им общий ID.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Не требуется менять файловую систему ради этой строки. Удаляйте только реально ненужный VPN/root framework штатным uninstall, а не маскируйте catalog-only ID.

### С root

Root-маскирование общего `vpn_file` бессмысленно. Если виден конкретный path, работайте с его producer и одновременно проверяйте mounts/properties.

### Как проверить результат

```bash
rg -n 'vpn_file|detectVpnFiles|findings.emplace_back' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Ручное удаление `/data/adb` или package data может повредить root manager и модули.

### Откат

Используйте штатную переустановку удалённого инструмента; не восстанавливайте каталоги копированием без правильных SELinux labels.

## Уровень доказательности

**Реестр/совместимость.** Проверено по mapping и фактическим prefix строкам C++.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [Android app data sandbox](https://source.android.com/docs/security/app-sandbox).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `vpnhide`, `lsposed`, `unknown-signals`.

[К справочнику Native signs](../)
