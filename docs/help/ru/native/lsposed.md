---
title: "Файловые артефакты LSPosed/Vector-подобного стека"
permalink: /help/ru/native/lsposed/
---

# Файловые артефакты LSPosed/Vector-подобного стека

> **ID:** `LSPOSED`
> **Категория:** Хуки и целостность процесса
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Legacy file probe проверяет `/data/adb/lspd`, `/data/adb/modules/lsposed`, `/data/misc/lspd`, `/data/data/org.lsposed.manager`. Доступный путь выдаёт `lsposed`; legacy policy считает его medium review, не direct detected.

### Точное условие срабатывания

Существует и виден приложению один из четырёх фиксированных paths.

## Что означает результат

Артефакт framework или старой установки. Современный Vector может использовать другие имена, а путь может остаться после удаления.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Проверка path-based и не доказывает, что RKNHardering находится в scope. И наоборот, framework может работать без видимого фиксированного пути, но проявиться в maps/library integrity.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Без root лучший вариант — чистый APK из доверенного источника без repack, LSPatch, Frida Gadget, виртуализатора и rootless-Xposed. Перенос приложения во «второе пространство» не очищает его процесс автоматически: контейнер может внедрять собственные библиотеки и оставить ещё больше расхождений. Удалите rootless/repacked framework штатно и установите чистый APK.

### С root

При root не включайте целевое приложение в scope Xposed/Vector и не загружайте в него Zygisk-модуль без необходимости. Для VPN-сокрытия предпочтительна схема, где Java-фильтрация выполняется в `system_server`, а native-фильтрация — в ядре. DenyList/App Profile, NoHello, Zygisk Next, SUSFS и похожие инструменты могут уменьшать часть следов, но ни один из них не является гарантией против `maps`, linker, mount и raw-syscall проверок одновременно. Для VPNHide scope должен включать только `System Framework`, а не RKNHardering. Скачивайте актуальный framework из [Vector releases](https://github.com/JingMatrix/Vector/releases/latest); оригинальный LSPosed сохранён как архивный источник.

### Как проверить результат

```bash
adb shell 'for p in /data/adb/lspd /data/adb/modules/lsposed /data/misc/lspd /data/data/org.lsposed.manager; do [ -e "$p" ] && echo "$p"; done'
```
Проверяйте также `hook-markers` и `library-integrity`.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление framework без отключения модулей может оставить систему в полусостоянии. Scope target app создаёт in-process следы.

### Откат

Отключите модуль, перезагрузитесь, затем удалите framework штатным manager. При bootloop используйте safe mode root manager.

## Уровень доказательности

**Средняя.** Проверено по четырём paths и legacy medium policy.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Vector releases](https://github.com/JingMatrix/Vector/releases/latest).
- Внешняя первичная документация или официальный проект: [Archived LSPosed](https://github.com/LSPosed/LSPosed).
- Внешняя первичная документация или официальный проект: [VPNHide framework setup](https://github.com/okhsunrog/vpnhide).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `hook-markers`, `hook-property`, `library-integrity`, `vpnhide`.

[К справочнику Native signs](../)
