---
title: "Несогласованность Java NetworkInterface и native getifaddrs"
permalink: /help/ru/native/jvm-native-mismatch/
---

# Несогласованность Java NetworkInterface и native getifaddrs

> **ID:** `JVM_NATIVE_MISMATCH`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Смешанная

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Checker строит два независимых снимка: C/C++ `getifaddrs()` и Java `NetworkInterface.getNetworkInterfaces()`. Он сравнивает набор имён, индекс одного и того же интерфейса и набор адресов. VPN-like имя, присутствующее только в одном слое, считается high; обычные различия индекса или адресов — medium review.

### Точное условие срабатывания

High: VPN-подобный интерфейс виден только native либо только JVM. Medium: любой другой missing interface, различный ifindex или непустые несовпадающие наборы адресов.

## Что означает результат

Этот сигнал чаще указывает не на сам VPN, а на неполное сокрытие или hook только одного API. Именно поэтому одни Java-хуки без native-покрытия и одни libc-хуки без framework-покрытия дают оракул.

**Как строка влияет на отчёт:** Один и тот же ID используется и для информационной сводки, и для подозрительных строк. Итог зависит от конкретного detail и ветки checker.

## Ограничения и возможные ложные срабатывания

Снимки выполняются последовательно, поэтому во время handover, переключения Wi‑Fi/cellular, CLAT или краткой смены IPv6 адреса возможна честная гонка. Повторите тест при стабильной сети.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Стабилизируйте сеть и исключите переключение между Wi‑Fi и мобильной сетью во время теста. Если VPN остаётся локально, обычный non-root не может заставить два системных API согласованно скрыть чужой интерфейс; внешний шлюз устраняет исходную причину.

### С root

Нужны оба слоя: framework-фильтрация в `system_server` и native/kernel-фильтрация. Не включайте Xposed scope на сам RKNHardering: это может очистить Java-список, но добавить process hooks. После изменения проверяйте имена, индексы и адреса, а не только отсутствие `tun0`.

### Как проверить результат

```bash
adb shell ip -o address show
adb shell ip -o link show
```
Для точного сравнения используйте встроенный detail RKNHardering или собственный test APK, который в одном процессе вызывает `NetworkInterface` и JNI `getifaddrs()`. Shell-команды не воспроизводят app namespace полностью.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Частичная подмена опаснее отсутствия подмены: она создаёт заметное противоречие. Несогласованные kernel hooks могут ломать сетевую библиотеку и зависать на перечислении.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Смешанная.** Проверено по `evaluateJvmNativeMismatch()`; ветки missing VPN interface имеют high, index/address mismatch — medium.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NetworkInterfacePatterns.kt` — правила имён интерфейсов](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Java NetworkInterface](https://developer.android.com/reference/java/net/NetworkInterface).
- Внешняя первичная документация или официальный проект: [getifaddrs(3)](https://man7.org/linux/man-pages/man3/getifaddrs.3.html).
- Внешняя первичная документация или официальный проект: [VPNHide architecture](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `interface-enumeration`, `getifaddrs-vpn`, `library-integrity`, `trim-oracle`.

[К справочнику Native signs](../)
