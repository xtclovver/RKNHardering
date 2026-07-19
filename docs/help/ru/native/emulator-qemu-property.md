---
title: "Системные свойства QEMU"
permalink: /help/ru/native/emulator-qemu-property/
---

# Системные свойства QEMU

> **ID:** `EMULATOR_QEMU_PROPERTY`
> **Категория:** Эмуляция, профили и изоляция
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

C++ читает `ro.kernel.qemu`, `ro.kernel.qemu.gles`, `ro.boot.qemu`, `qemu.hw.mainkeys`. Любое существующее непустое значение выдаётся как `qemu_prop`; checker присваивает high confidence review.

### Точное условие срабатывания

Непустая property из фиксированного списка, независимо от конкретного значения.

## Что означает результат

Сильный признак QEMU-ориентированного окружения. На физическом production-устройстве эти properties обычно отсутствуют.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Property может быть оставлена кастомной прошивкой или тестовым vendor image. Эмулятор, который фильтрует properties, может пройти этот конкретный вектор.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для отсутствия этого класса признаков используйте физическое устройство с production-сборкой. Свойства QEMU, goldfish/ranchu, специальные устройства и build fingerprint являются частью окружения; обычное приложение не может согласованно изменить их без системной модификации. Облачный телефон или OEM-клон тоже следует считать отдельным окружением и сравнивать с физическим baseline.

### С root

Подмена пары `getprop` значений не делает эмулятор физическим устройством: остаются драйверы, `/dev`-узлы, аппаратный профиль, ABI и поведение ядра. Root-модули для spoofing могут убрать один marker и создать hook/property/library mismatch. Для разработки допустимо использовать их как эксперимент, но для корректного результата RKNHardering лучше запускать на реальном устройстве. Даже если `resetprop` уберёт строку, pipe, goldfish/ranchu и Build profile останутся для перекрёстной проверки.

### Как проверить результат

```bash
for p in ro.kernel.qemu ro.kernel.qemu.gles ro.boot.qemu qemu.hw.mainkeys; do adb shell getprop "$p"; done
```
Непустой вывод сопоставьте с detail.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Изменение boot properties может нарушить графику, input и поведение init в эмуляторе.

### Откат

Верните snapshot/AVD config или удалите resetprop-правило и перезагрузите окружение.

## Уровень доказательности

**Средняя.** Проверено по массиву `kQemuProps`; signal high-confidence, но review-only.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Android Emulator](https://developer.android.com/studio/run/emulator).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `emulator-qemu-pipe`, `emulator-goldfish`, `emulator-build-profile`.

[К справочнику Native signs](../)
