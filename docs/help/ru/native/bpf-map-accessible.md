---
title: "Доступ к netd BPF iface-index map"
permalink: /help/ru/native/bpf-map-accessible/
---

# Доступ к netd BPF iface-index map

> **ID:** `BPF_MAP_ACCESSIBLE`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Legacy probe пытается открыть read-only три пути: `/sys/fs/bpf/map_netd_iface_index_name_map`, `/sys/fs/bpf/netd_shared/map_netd_iface_index_name_map`, `/sys/fs/bpf/netd_iface_index_name_map`. Успех выдаёт `bpf_map_accessible`; legacy policy high.

### Точное условие срабатывания

Обычный app process может открыть один из фиксированных BPF pin paths.

## Что означает результат

На stock Android доступ обычно ограничен. Доступность может позволить извлекать mapping ifindex→name и обходить поверхностное скрытие.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Проба проверяет только open, не читает map и не подтверждает наличие VPN entry. Path layout меняется по Android версиям.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

На production ROM не ослабляйте SELinux/BPF filesystem permissions. Если доступ появился в custom ROM, самый чистый вариант — stock enforcing build.

### С root

Исправьте policy минимально: target UID не должен читать netd maps. Не выключайте BPF/netd глобально. VPNHide Next заявляет eBPF filtering, но это kernel-level эксперимент с высоким риском.

### Как проверить результат

```bash
adb shell ls -l /sys/fs/bpf 2>/dev/null | head -80
adb shell 'for p in /sys/fs/bpf/map_netd_iface_index_name_map /sys/fs/bpf/netd_shared/map_netd_iface_index_name_map /sys/fs/bpf/netd_iface_index_name_map; do [ -r "$p" ] && echo readable:$p; done'
```
Shell доступ не равен app UID.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Изменение netd BPF maps/policy может сломать accounting, firewall и сеть. Не удаляйте pinned maps.

### Откат

Верните sepolicy/module и перезагрузите netd/устройство; при нестабильности восстановите boot image.

## Уровень доказательности

**Высокая.** Проверено по трём paths; legacy high.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [Linux BPF docs](https://docs.kernel.org/bpf/index.html).
- Внешняя первичная документация или официальный проект: [AOSP eBPF traffic monitoring](https://source.android.com/docs/core/datausage/ebpf-traffic-monitor).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `deep-bpf-map-accessible`, `ifindexname-vpn`.

[К справочнику Native signs](../)
