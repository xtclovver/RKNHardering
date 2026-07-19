---
title: "Файлы BlueStacks"
permalink: /help/ru/native/emulator-bluestacks/
---

# Файлы BlueStacks

> **ID:** `EMULATOR_BLUESTACKS`
> **Категория:** Эмуляция, профили и изоляция
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проверяются `/system/lib/libbstfolder_jni.so` и `/data/bluestacks.prop`. Доступный путь создаёт `bluestacks` и high-confidence review.

### Точное условие срабатывания

Существует хотя бы один из двух фиксированных BlueStacks artifacts.

## Что означает результат

Сильный vendor-specific marker. Он не покрывает новые версии/варианты BlueStacks, если пути изменены.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

Остаточный файл после миграции образа может сработать без активного компонента. Другие Android-эмуляторы этой проверкой не охватываются.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Для отсутствия этого класса признаков используйте физическое устройство с production-сборкой. Свойства QEMU, goldfish/ranchu, специальные устройства и build fingerprint являются частью окружения; обычное приложение не может согласованно изменить их без системной модификации. Облачный телефон или OEM-клон тоже следует считать отдельным окружением и сравнивать с физическим baseline.

### С root

Подмена пары `getprop` значений не делает эмулятор физическим устройством: остаются драйверы, `/dev`-узлы, аппаратный профиль, ABI и поведение ядра. Root-модули для spoofing могут убрать один marker и создать hook/property/library mismatch. Для разработки допустимо использовать их как эксперимент, но для корректного результата RKNHardering лучше запускать на реальном устройстве. Удаление файла внутри guest может сломать shared folder и не убрать остальные BlueStacks признаки.

### Как проверить результат

```bash
adb shell ls -l /system/lib/libbstfolder_jni.so /data/bluestacks.prop 2>/dev/null
```
На `/data` возможен отказ в доступе.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Изменение system image BlueStacks может повредить обновление или shared-folder integration.

### Откат

Верните snapshot или переустановите официальный образ эмулятора.

## Уровень доказательности

**Средняя.** Проверено по массиву `kBlueStacksPaths`; high confidence review.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [BlueStacks support](https://support.bluestacks.com/).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `emulator-indicators`, `emulator-build-profile`.

[К справочнику Native signs](../)
