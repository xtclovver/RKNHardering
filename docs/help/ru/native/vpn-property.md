---
title: "Старые VPN/DNS system properties"
permalink: /help/ru/native/vpn-property/
---

# Старые VPN/DNS system properties

> **ID:** `VPN_PROPERTY`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectVpnPropertiesAll()` читает `net.vpn.dns1..4`, `dhcp.tun0.dns1/2`, `net.interfaces.default.type`, `net.interfaces.default.name`. Любое непустое значение создаёт `vpn_prop`. Дополнительно `net.interfaces.default.type` повторно проверяется на подстроку `tun` или `vpn`. В legacy policy этот kind имеет high confidence и `detected=true`.

### Точное условие срабатывания

Непустая фиксированная VPN property либо `default.type`, содержащая `tun`/`vpn`.

## Что означает результат

Сильный legacy-признак, если прошивка действительно экспортирует такие свойства. На новых Android эти имена часто отсутствуют даже при активном VPN.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Список property не является частью стабильного Android API. OEM может оставлять stale value после отключения VPN или вообще не использовать эти ключи.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Полностью остановите VPN-клиент и перезагрузите сеть, затем проверьте, исчезла ли property. Если она задаётся прошивкой, обычное приложение её не изменит; внешний шлюз не всегда очистит stale property до reboot, но не создаёт новый `VpnService`.

### С root

`resetprop` способен скрыть legacy key, однако это закрывает только одну поверхность. Не подменяйте DNS-значение без согласования реального resolver path. Лучше устранить producer property или использовать системный фильтр, который не меняет глобальную сеть.

### Как проверить результат

```bash
for p in net.vpn.dns1 net.vpn.dns2 net.vpn.dns3 net.vpn.dns4 dhcp.tun0.dns1 dhcp.tun0.dns2 net.interfaces.default.type net.interfaces.default.name; do
  printf '%s=' "$p"; adb shell getprop "$p"
done
```
Повторите после отключения VPN и reboot.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Глобальная подмена DNS/property может вызвать утечки DNS или потерю резолвинга. Не очищайте все `net.*` свойства скриптом.

### Откат

Удалите точечное resetprop-правило и перезагрузитесь; верните исходный VPN/DNS config.

## Уровень доказательности

**Высокая.** Проверено по точному списку properties; `vpn_prop` входит в legacy high-confidence kinds.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [Android system properties](https://source.android.com/docs/core/architecture/configuration/sysprops-apis).
- Внешняя первичная документация или официальный проект: [VpnService.Builder DNS](https://developer.android.com/reference/android/net/VpnService.Builder).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `dns-property`, `hook-property`, `interface-enumeration`.

[К справочнику Native signs](../)
