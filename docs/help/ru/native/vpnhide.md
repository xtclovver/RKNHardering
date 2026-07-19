---
title: "Артефакты VPNHide и regression-oracles"
permalink: /help/ru/native/vpnhide/
---

# Артефакты VPNHide и regression-oracles

> **ID:** `VPNHIDE`
> **Категория:** Хуки и целостность процесса
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Смешанная

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Один ID объединяет два разных источника. Legacy `detectVpnFiles()` проверяет `/data/local/tmp/vpnhide`, `/data/data/com.vpnhide`, `/data/local/tmp/.vpnhide`, `/data/data/com.vpn.hide`; найденный path — high `vpnhide`. Глубокий detector также направляет сюда результаты двух regression-проб: SIOCGIFINDEX/SIOCGIFNAME consistency и SIOCGIFCONF tail. Oracle/tail-vpn имеют high, tail-oracle medium, clean informational, unavailable — error.

### Точное условие срабатывания

High: доступный legacy path, стабильный индекс интерфейса без обратного имени, либо VPN-like имя в хвосте буфера SIOCGIFCONF. Medium: правдоподобный stale non-VPN хвост. Clean/unavailable не являются detection.

## Что означает результат

Сигнал может означать либо прямой файловый артефакт, либо неполную фильтрацию интерфейсов. По одному заголовку нельзя понять причину — читайте detail/checkId.

**Как строка влияет на отчёт:** Один и тот же ID используется и для информационной сводки, и для подозрительных строк. Итог зависит от конкретного detail и ветки checker.

## Ограничения и возможные ложные срабатывания

Legacy path names не совпадают с современными путями всех версий VPNHide. Regression-oracles проверяют конкретные ошибки реализации и могут не поймать другой bypass.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Без root VPNHide обычно не установлен, поэтому path должен отсутствовать. Если сигнал oracle появляется без VPNHide, это может быть другой фильтр/ROM bug: повторите на чистом baseline. Для скрытия самого VPN без root используйте внешний шлюз.

### С root

Установку выполняйте только из [официального VPNHide release](https://github.com/okhsunrog/vpnhide/releases/latest). Настройте `System Framework` и ровно один native backend. После каждого обновления прогоняйте оба regression checkId: отсутствие `tun0` недостаточно, если остаётся index или stale tail. Не складывайте kmod+KPM.

### Как проверить результат

```bash
# Только чтение доступных путей:
adb shell 'for p in /data/local/tmp/vpnhide /data/data/com.vpnhide /data/local/tmp/.vpnhide /data/data/com.vpn.hide; do [ -e "$p" ] && echo "$p"; done'
# Для кода regression probes:
rg -n 'vpnhide_ifindex|vpnhide_ifconf' app/src/main/cpp/vpnhide_regression_probe.cpp
```
В UI различайте checkId `native.vpnhide.ifindex_consistency` и `native.vpnhide.ifconf_tail`.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Kernel backend может вызвать bootloop/panic; одновременные backend особенно опасны. Удаление package data стирает настройки.

### Откат

До установки сохраните boot/init_boot и список модулей. При bootloop отключите последний модуль через safe mode manager или восстановите рабочий образ.

## Уровень доказательности

**Смешанная.** Проверено по legacy path list, C++ regression probe и confidence policy `VpnNativeDetectorChecker`.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`vpnhide_regression_probe.cpp` — consistency/oracle-пробы](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/vpnhide_regression_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [VPNHide](https://github.com/okhsunrog/vpnhide).
- Внешняя первичная документация или официальный проект: [VPNHide releases](https://github.com/okhsunrog/vpnhide/releases/latest).
- Внешняя первичная документация или официальный проект: [VPNHide detection vectors](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Внешняя первичная документация или официальный проект: [VPNHide Next](https://github.com/soranerai/vpnhide_next).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `ifindexname-vpn`, `trim-oracle`, `jvm-native-mismatch`, `lsposed`.

[К справочнику Native signs](../)
