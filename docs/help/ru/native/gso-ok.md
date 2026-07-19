---
title: "UDP GSO принят и loopback send успешен"
permalink: /help/ru/native/gso-ok/
---

# UDP GSO принят и loopback send успешен

> **ID:** `GSO_OK`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Нативный producer есть, но строка теряется при текущем разборе UI
> **Роль в вердикте:** Реестр/совместимость

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`UDP_SEGMENT=1200` принят, затем `sendto()` 4800 bytes на loopback:53 возвращает успех. В native result kind не имеет detail, поэтому parser получает `gso_ok` только если строка сериализована с разделителем; текущий C++ добавляет именно `gso_ok` без `|`, а deep `parseRow()` требует kind и непустой detail после второго separator. После prefix это `vdet|gso_ok`, поэтому текущий Kotlin parser отбрасывает строку.

### Точное условие срабатывания

На C++ уровне — успешные setsockopt и sendto. На UI уровне версии 2.10.0 producer фактически не доходит до finding из-за формата без detail.

## Что означает результат

Если строка не отображается, это не означает GSO failure: это текущая несовместимость формата producer/parser. После исправления сигнал должен оставаться информационным.

**Как строка влияет на отчёт:** ID сохранён в каталоге и UI, однако текущая версия 2.10.0 не формирует отдельную положительную строку этого kind. Обычно рядом работает более конкретный сигнал.

## Ограничения и возможные ложные срабатывания

Кроме parser gap, loopback GSO не измеряет VPN path и не подтверждает hardware offload. Сам success не является антидетектом.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Ничего не меняйте ради отсутствующей UI-строки. Для разработки исправьте C++ на `gso_ok|sent=4800` либо разрешите empty detail в parser и добавьте unit test.

### С root

Root не требуется и не должен использоваться. Не патчите kernel только для появления диагностической строки.

### Как проверить результат

```bash
rg -n 'gso_ok|parseRow|indexOf' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt
```
После исправления запустите checker unit test и реальное устройство с поддержкой UDP_SEGMENT.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Изменение parser влияет на все malformed deep rows; добавьте тест, чтобы не принимать пустые/повреждённые kinds без разбора.

### Откат

Откатите только code change, если тесты/telemetry ухудшились. На устройстве постоянных изменений нет.

## Уровень доказательности

**Реестр/совместимость.** Проверено по C++ строке без separator/detail и Kotlin `parseRow()` с `sep <= 0`/blank rejection. ID остаётся каталогизированным.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [Unit-тесты native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `gso-failed`, `gso-send-failed`, `general-diagnostics`.

[К справочнику Native signs](../)
