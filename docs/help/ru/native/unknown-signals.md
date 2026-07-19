---
title: "Неизвестный или не сопоставленный native kind"
permalink: /help/ru/native/unknown-signals/
---

# Неизвестный или не сопоставленный native kind

> **ID:** `UNKNOWN`
> **Категория:** Служебные сигналы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Служебная

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`NativeSignalCatalog.info(null)` и неизвестные ID используют `UNKNOWN`. В legacy/deep mappers неизвестный kind обычно приводит к `null`, после чего finding может получить fallback-статью или вообще не пройти конкретный parser. Эта страница нужна для forward compatibility, а не для одной C++-пробы.

### Точное условие срабатывания

UI/ссылка получает null/неизвестный NativeSignalId либо новая native строка ещё не добавлена в catalog mapping.

## Что означает результат

Это дефект согласования версии producer, parser, enum и документации. По одной неизвестной строке нельзя назначить уверенность или способ обхода; сначала нужен raw kind/detail и commit/version.

**Как строка влияет на отчёт:** Это зонтичный или резервный ID. Он связывает группу строк с документацией, но не всегда имеет отдельный положительный producer.

## Ограничения и возможные ложные срабатывания

Release APK может не показывать raw row полностью. При смешивании APK/документации разных версий slug/title расходятся. Не следует автоматически считать unknown clean или detected.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Сохраните экспорт отчёта, версию APK, ABI и exact detail. Переустановите официальный release без repack и повторите. Для issue приложите минимально необходимый лог без персональных данных.

### С root

Повторите без модулей, которые меняют JNI/strings. Если вы добавили собственную native-пробу, одновременно обновите `NativeSignalId`, `NativeSignalCatalog`, mapper, строки UI, русскую статью и unit tests.

### Как проверить результат

```bash
rg -n 'NativeSignalId|fromLegacyVpnKind|fromDeepVpnKind|UNKNOWN' app/src/main/java/com/notcvnt/rknhardering
./gradlew testDebugUnitTest --tests com.notcvnt.rknhardering.NativeSignalCatalogTest
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Публикуемый raw log может содержать интерфейсы, IP, пути и package names. Перед issue удалите секреты и персональные данные.

### Откат

Откатите несовместимый producer/catalog change или установите согласованную версию APK и docs.

## Уровень доказательности

**Служебная.** Проверено по catalog fallback и mapping tables. Сигнал служебный.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Внешняя первичная документация или официальный проект: [Project issues](https://github.com/xtclovver/RKNHardering/issues).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `native-library`, `general-diagnostics`, `syscall-unavailable`.

[К справочнику Native signs](../)
