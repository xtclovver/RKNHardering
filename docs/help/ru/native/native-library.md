---
title: "Загрузка нативной библиотеки проверок"
permalink: /help/ru/native/native-library/
---

# Загрузка нативной библиотеки проверок

> **ID:** `NATIVE_LIBRARY`
> **Категория:** Служебные сигналы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Доступность

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Перед всеми JNI-пробами `NativeSignsBridge` загружает нативную библиотеку. Если `System.loadLibrary` завершился ошибкой, `NativeSignsChecker` и глубокий VPN-detector возвращают строку с ID `NATIVE_LIBRARY`, включая текст исключения, если он доступен. Ни интерфейсы, ни маршруты, ни root/hook-пробы после этого не считаются выполненными.

### Точное условие срабатывания

Срабатывание — это ошибка загрузки `.so`, несовместимый ABI, отсутствующая библиотека, linker/namespace-ошибка или исключение JNI. Успешная загрузка отдельной положительной строки не создаёт.

## Что означает результат

Это не признак чистого устройства и не признак VPN. Результат означает, что значительная часть native-покрытия отсутствует, поэтому итог надо считать неполным.

**Как строка влияет на отчёт:** Сигнал описывает невозможность выполнить пробу. `unavailable` нельзя интерпретировать как отсутствие VPN.

## Ограничения и возможные ложные срабатывания

Причиной могут быть повреждённый APK, split APK без нужной ABI, несовместимый процесс 32/64 bit, вмешательство упаковщика, ошибка сборки или ограничение среды. После repack такой сбой особенно вероятен.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Переустановите официальный APK той же версии, не извлекайте и не подписывайте его заново. Проверьте, что устройство поддерживает ABI сборки и что установка завершилась без split-конфликта. Для разработки соберите APK штатным Gradle-task и сравните `lib/*` внутри APK.

### С root

Сначала отключите модули, которые меняют linker namespace, Zygote или загрузку библиотек для RKNHardering. Не пытайтесь скрыть VPN через намеренный срыв JNI: приложение прямо показывает недоступность проверки, а не принимает её за clean.

### Как проверить результат

```bash
adb shell pm path com.notcvnt.rknhardering
adb shell dumpsys package com.notcvnt.rknhardering | grep -E 'primaryCpuAbi|secondaryCpuAbi'
adb logcat -c
adb shell am force-stop com.notcvnt.rknhardering
# Затем откройте приложение и найдите UnsatisfiedLinkError/dlopen в logcat:
adb logcat | grep -Ei 'rknhardering|UnsatisfiedLinkError|dlopen|linker'
```
Для локальной сборки дополнительно выполните `unzip -l app-release.apk | grep '/lib/'`.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Переустановка может удалить локальные данные приложения, если используется `adb install -r` с несовместимой подписью или предварительно выполнено удаление. Сохраните экспорт отчётов и настройки.

### Откат

Верните APK с исходной подписью и очистите только изменения, которые влияли на загрузку. Если проблема появилась после root-модуля, отключите именно его и перезагрузитесь.

## Уровень доказательности

**Доступность.** Проверено по веткам `libraryUnavailableResult()` в двух Kotlin-checker и по регистрации JNI-методов. Сигнал описывает покрытие проверки, а не состояние сети.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignsBridge.kt` — загрузка JNI и native bridge](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/probe/NativeSignsBridge.kt).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Android ABI management](https://developer.android.com/ndk/guides/abis).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `general-diagnostics`, `syscall-unavailable`, `library-integrity`.

[К справочнику Native signs](../)
