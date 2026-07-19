---
title: "Эвристики Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT"
permalink: /help/ru/native/emulator-build-profile/
---

# Эвристики Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT

> **ID:** `EMULATOR_BUILD`
> **Категория:** Эмуляция, профили и изоляция
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Kotlin отмечает fingerprint, если он начинается `generic`/`unknown` либо содержит `vbox`, `emulator`, `test-keys`; model — `google_sdk`, `Emulator`, `Android SDK built for`; hardware — точные `goldfish`, `ranchu`, `vbox86`; product — `sdk_gphone*`, `vbox86p`, `emulator`, `sdk`, `google_sdk`; manufacturer — точный `Genymotion`. Каждый факт — medium review.

### Точное условие срабатывания

Совпадение с любым из перечисленных Build-паттернов.

## Что означает результат

Это широкая эвристика, поэтому `test-keys` может означать кастомную физическую прошивку, а не эмулятор. Результат нужно сочетать с QEMU/device markers.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Build fields легко подменяются и различаются у OEM. Производственная GSI или dev board может закономерно выглядеть как generic.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для отсутствия этого класса признаков используйте физическое устройство с production-сборкой. Свойства QEMU, goldfish/ranchu, специальные устройства и build fingerprint являются частью окружения; обычное приложение не может согласованно изменить их без системной модификации. Облачный телефон или OEM-клон тоже следует считать отдельным окружением и сравнивать с физическим baseline. Для физического устройства с custom ROM единственный чистый baseline — официальный production build; factory reset не меняет fingerprint.

### С root

Подмена пары `getprop` значений не делает эмулятор физическим устройством: остаются драйверы, `/dev`-узлы, аппаратный профиль, ABI и поведение ядра. Root-модули для spoofing могут убрать один marker и создать hook/property/library mismatch. Для разработки допустимо использовать их как эксперимент, но для корректного результата RKNHardering лучше запускать на реальном устройстве. Согласованно менять fingerprint/model/product/hardware сложно; частичный spoof виден в других слоях и может нарушить Play Integrity.

### Как проверить результат

```bash
adb shell getprop ro.build.fingerprint
adb shell getprop ro.product.model
adb shell getprop ro.hardware
adb shell getprop ro.product.name
adb shell getprop ro.product.manufacturer
```
Проверьте точные подстроки из реализации.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Некорректный fingerprint ломает OTA/Play services; подмена hardware/product может выбрать несовместимый HAL.

### Откат

Удалите spoofing-модуль и восстановите build props из исходного образа.

## Уровень доказательности

**Средняя.** Проверено по `collectBuildEmulatorFacts()`; все строки medium review.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Android Build API](https://developer.android.com/reference/android/os/Build).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `emulator-qemu-property`, `emulator-goldfish`, `root-property`.

[К справочнику Native signs](../)
