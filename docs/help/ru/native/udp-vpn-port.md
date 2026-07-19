---
title: "Зарезервированный legacy ID UDP VPN-портов"
permalink: /help/ru/native/udp-vpn-port/
---

# Зарезервированный legacy ID UDP VPN-портов

> **ID:** `UDP_VPN_PORT`
> **Категория:** VPN-артефакты и сокеты
> **Статус в RKNHardering 2.10.0:** ID сохранён для совместимости; отдельного producer в 2.10.0 нет
> **Роль в вердикте:** Реестр/совместимость

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`UDP_VPN_PORT`/`udp_vpn_port` сохранены в каталоге и даже отмечены legacy high, но текущий C++ не создаёт строку этого kind. Реальные UDP checks — conflict на физическом IP и PMTU/GSO diagnostics.

### Точное условие срабатывания

Отдельного producer нет; высокая политика не активируется без строки.

## Что означает результат

Страница нужна для совместимости. Занятые UDP 500/4500/1194/1701/51820 проверяет `udp-port-conflict-physical`.

**Как строка влияет на отчёт:** ID сохранён в каталоге и UI, однако текущая версия 2.10.0 не формирует отдельную положительную строку этого kind. Обычно рядом работает более конкретный сигнал.

## Ограничения и возможные ложные срабатывания

Наличие ID high в Kotlin может создать неверное впечатление активной проверки; документация явно разделяет registry и producer.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Закройте ненужный UDP listener или перенесите VPN на шлюз. Для catalog-only ID обход не нужен.

### С root

Точечный UID firewall допустим только для реально найденного listener. Не блокируйте IKE/WireGuard порты глобально, если они нужны VPN.

### Как проверить результат

```bash
rg -n 'udp_vpn_port|udp_port_conflict_physical' app/src/main
adb shell ss -lun 2>/dev/null | head -80
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Глобальная блокировка UDP 500/4500 ломает IPsec; 51820 может использовать WireGuard.

### Откат

Удалите только созданное firewall rule и перезапустите VPN.

## Уровень доказательности

**Реестр/совместимость.** Проверено по catalog mapping и отсутствию producer.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `udp-port-conflict-physical`, `udp-pmtu-ok`, `udp-pmtu-fail`.

[К справочнику Native signs](../)
