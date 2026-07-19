---
title: "Сводка признаков эмулятора"
permalink: /help/ru/native/emulator-indicators/
---

# Сводка признаков эмулятора

> **ID:** `EMULATOR_INDICATORS`
> **Категория:** Эмуляция, профили и изоляция
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Служебная

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Это зонтичный ID категории. Текущий `evaluateEmulator()` назначает конкретные ID для QEMU properties, pipe, goldfish/ranchu, driver, BlueStacks и Build-профиля. Отдельная положительная строка `EMULATOR_INDICATORS` сейчас не формируется.

### Точное условие срабатывания

Сам ID не имеет producer; он нужен как стабильная точка справочника и для будущей агрегации.

## Что означает результат

Оценивайте дочерние строки. Отсутствие всех перечисленных marker не доказывает физическое устройство: современный эмулятор может маскировать стандартные признаки.

**Как строка влияет на отчёт:** Это зонтичный или резервный ID. Он связывает группу строк с документацией, но не всегда имеет отдельный положительный producer.

## Ограничения и возможные ложные срабатывания

Список не включает аппаратную аттестацию, сенсоры, telephony, графические тайминги и полный fingerprint-анализ.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для отсутствия этого класса признаков используйте физическое устройство с production-сборкой. Свойства QEMU, goldfish/ranchu, специальные устройства и build fingerprint являются частью окружения; обычное приложение не может согласованно изменить их без системной модификации. Облачный телефон или OEM-клон тоже следует считать отдельным окружением и сравнивать с физическим baseline.

### С root

Подмена пары `getprop` значений не делает эмулятор физическим устройством: остаются драйверы, `/dev`-узлы, аппаратный профиль, ABI и поведение ядра. Root-модули для spoofing могут убрать один marker и создать hook/property/library mismatch. Для разработки допустимо использовать их как эксперимент, но для корректного результата RKNHardering лучше запускать на реальном устройстве.

### Как проверить результат

```bash
adb shell getprop ro.kernel.qemu
adb shell getprop ro.hardware
adb shell getprop ro.product.board
adb shell getprop ro.build.fingerprint
adb shell ls -l /dev/qemu_pipe /dev/socket/qemud 2>/dev/null
```
Смотрите конкретные дочерние страницы для точных критериев.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Spoofing большого набора build properties может сломать OTA, Play services и совместимость приложений.

### Откат

Удалите spoofing-модуль/правила property и вернитесь к snapshot эмулятора либо стоковому boot image.

## Уровень доказательности

**Служебная.** Проверено по каталогу и `evaluateEmulator()`; зонтичный ID не назначается положительным findings в версии 2.10.0.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [Android Emulator](https://developer.android.com/studio/run/emulator).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `emulator-qemu-property`, `emulator-build-profile`, `emulator-qemu-pipe`.

[К справочнику Native signs](../)
