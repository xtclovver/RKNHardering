---
title: "Deep native detector не вернул ни одной строки"
permalink: /help/ru/native/general-diagnostics/
---

# Deep native detector не вернул ни одной строки

> **ID:** `GENERAL_DIAGNOSTICS`
> **Категория:** Служебные сигналы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Служебная

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`VpnNativeDetectorChecker` добавляет `GENERAL_DIAGNOSTICS` только когда после парсинга `findings` пуст. Это может означать, что все producer functions молчали, scan был отменён до output, либо строки были отброшены parser. При недоступной native library используется другой ID.

### Точное условие срабатывания

`findings.isEmpty()` после `detectVpnDetector()` и `parseRow()`.

## Что означает результат

Сообщение «аномалии не найдены» относится только к deep category и только к успешно распознанным rows. Оно не гарантирует отсутствие VPN и не отменяет legacy, Java, server-side и β-проверки.

**Как строка влияет на отчёт:** Это зонтичный или резервный ID. Он связывает группу строк с документацией, но не всегда имеет отдельный положительный producer.

## Ограничения и возможные ложные срабатывания

Некоторые probes по дизайну молчат при clean, но `route_count`, `normal_pmtu`, timing и UDP PMTU обычно создают telemetry. Поэтому completely empty result может также указывать на cancellation/parser/ABI peculiarities. `gso_ok` сейчас отбрасывается из-за отсутствия detail, но другие rows обычно остаются.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Проверьте, что scan завершился, native library загружена и category не была отменена. Сравните лог и повторите на стабильной сети.

### С root

Временно исключите RKNHardering из всех modules/scopes и повторите. Не используйте пустой output как цель антидетекта: срыв диагностики заметен и снижает доверие к отчёту.

### Как проверить результат

```bash
adb logcat -c
adb shell am force-stop com.notcvnt.rknhardering
# Запустите полный scan, затем:
adb logcat -d | grep -Ei 'RKNHardering|native|vpn detector|cancel|JNI' | tail -200
```
Также проверьте соседний `native-library` result.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Принудительный срыв JNI/scan может скрыть реальные ошибки и не является корректным прохождением проверки.

### Откат

Верните официальный APK, отключите вмешивающийся модуль и перезагрузитесь. Повторите полный baseline.

## Уровень доказательности

**Служебная.** Проверено по `findings.isEmpty()` branch и parser behavior.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignsBridge.kt` — загрузка JNI и native bridge](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/probe/NativeSignsBridge.kt).
- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Android JNI guidance](https://developer.android.com/training/articles/perf-jni).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `native-library`, `unknown-signals`, `route-count`.

[К справочнику Native signs](../)
