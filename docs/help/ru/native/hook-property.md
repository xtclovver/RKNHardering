---
title: "System properties LSPosed/Magisk/Zygote hook"
permalink: /help/ru/native/hook-property/
---

# System properties LSPosed/Magisk/Zygote hook

> **ID:** `HOOK_PROPERTY`
> **Категория:** Хуки и целостность процесса
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectVpnFiles()` читает `persist.sys.lspd.hook`, `ro.magisk.version`, `init.svc.zygote_restart`; любое непустое значение выдаёт `hook_prop`. Legacy policy считает этот kind high и `detected=true`.

### Точное условие срабатывания

Непустая одна из трёх hook-related properties.

## Что означает результат

Высокодостоверный legacy indicator модифицированного runtime/root framework. Название property важнее самого value.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Список короткий и version-specific. `init.svc.zygote_restart` может теоретически использоваться OEM, а современные framework могут не экспортировать эти keys.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Без root лучший вариант — чистый APK из доверенного источника без repack, LSPatch, Frida Gadget, виртуализатора и rootless-Xposed. Перенос приложения во «второе пространство» не очищает его процесс автоматически: контейнер может внедрять собственные библиотеки и оставить ещё больше расхождений.

### С root

При root не включайте целевое приложение в scope Xposed/Vector и не загружайте в него Zygisk-модуль без необходимости. Для VPN-сокрытия предпочтительна схема, где Java-фильтрация выполняется в `system_server`, а native-фильтрация — в ядре. DenyList/App Profile, NoHello, Zygisk Next, SUSFS и похожие инструменты могут уменьшать часть следов, но ни один из них не является гарантией против `maps`, linker, mount и raw-syscall проверок одновременно. Если property создаёт старый модуль, обновите/удалите его. Массовый resetprop не заменяет исключение target из injection.

### Как проверить результат

```bash
adb shell getprop persist.sys.lspd.hook
adb shell getprop ro.magisk.version
adb shell getprop init.svc.zygote_restart
```
Непустая строка соответствует trigger.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Подмена zygote service properties может нарушить запуск приложений и усложнить crash diagnostics.

### Откат

Удалите точечные resetprop правила/legacy module и перезагрузитесь.

## Уровень доказательности

**Высокая.** Проверено по `hookPropNames`; kind входит в legacy high set.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Magisk](https://github.com/topjohnwu/Magisk).
- Внешняя первичная документация или официальный проект: [Vector](https://github.com/JingMatrix/Vector).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `lsposed`, `hook-markers`, `root-magisk-property`.

[К справочнику Native signs](../)
