---
title: "Зарезервированный deep ID qdisc"
permalink: /help/ru/native/deep-vpn-qdisc/
---

# Зарезервированный deep ID qdisc

> **ID:** `DEEP_VPN_QDISC`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** ID сохранён для совместимости; отдельного producer в 2.10.0 нет
> **Роль в вердикте:** Реестр/совместимость

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Каталог `fromDeepVpnKind("vpn_qdisc")` направляет строку в `DEEP_VPN_QDISC`, но текущий `nativeDetectVpnDetector()` не вызывает функцию, формирующую `vpn_qdisc`. Активный producer находится только в legacy `nativeDetectVpnAdvanced()` и описан на странице `vpn-qdisc`.

### Точное условие срабатывания

В текущем deep pipeline отдельного trigger нет. ID появится лишь если в будущем `nativeDetectVpnDetector()` начнёт возвращать kind `vpn_qdisc` или native bridge изменится.

## Что означает результат

Обычно страница открывается из каталога, но runtime finding с этим ID отсутствует. Не используйте отсутствие deep ID как подтверждение, что qdisc/counters скрыты.

**Как строка влияет на отчёт:** ID сохранён в каталоге и UI, однако текущая версия 2.10.0 не формирует отдельную положительную строку этого kind. Обычно рядом работает более конкретный сигнал.

## Ограничения и возможные ложные срабатывания

Имя `qdisc` в legacy producer также неточно: текущая функция читает `/proc/net/dev` RX/TX для tun0/wg0, а не qdisc через rtnetlink TC. Это отмечено в обеих статьях.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Ничего не меняйте ради неактивного ID. Для фактического сигнала смотрите `vpn-qdisc` и `proc-net-dev-vpn`.

### С root

Не устанавливайте kernel-модуль только ради пустой строки реестра. Если добавляете реальный qdisc detector, сначала определите RTM_GETQDISC/TC semantics и отдельную модель ложных срабатываний.

### Как проверить результат

```bash
rg -n 'detectQdisc|nativeDetectVpnDetector|nativeDetectVpnAdvanced|"vpn_qdisc"' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering
```
Проверьте, что вызов отсутствует именно в consolidated deep function.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Попытка скрывать traffic-control глобально может сломать shaping, QoS и NetworkStack. Здесь исправлять нечего до появления producer.

### Откат

Если вы экспериментально добавляли вызов, откатите только изменение pipeline и тесты; устройство менять не требуется.

## Уровень доказательности

**Реестр/совместимость.** Проверено по JNI function call list и catalog mapping; status registry-only.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [Linux traffic control netlink](https://man7.org/linux/man-pages/man8/tc.8.html).
- Внешняя первичная документация или официальный проект: [VPNHide Next](https://github.com/soranerai/vpnhide_next).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `vpn-qdisc`, `proc-net-dev-vpn`, `route-count`.

[К справочнику Native signs](../)
