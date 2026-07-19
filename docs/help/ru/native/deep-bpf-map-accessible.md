---
title: "Зарезервированный deep ID доступности BPF map"
permalink: /help/ru/native/deep-bpf-map-accessible/
---

# Зарезервированный deep ID доступности BPF map

> **ID:** `DEEP_BPF_MAP_ACCESSIBLE`
> **Категория:** Маршруты и сетевой стек
> **Статус в RKNHardering 2.10.0:** ID сохранён для совместимости; отдельного producer в 2.10.0 нет
> **Роль в вердикте:** Реестр/совместимость

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`fromDeepVpnKind("bpf_map_accessible")` сопоставлен с `DEEP_BPF_MAP_ACCESSIBLE`, но consolidated `nativeDetectVpnDetector()` не вызывает `detectBpfMaps()`. Сейчас та же kind-строка формируется только legacy pipeline и получает ID `BPF_MAP_ACCESSIBLE`.

### Точное условие срабатывания

В текущем deep pipeline producer отсутствует. Потенциальный trigger совпал бы с успешным open одного из трёх netd BPF pin paths.

## Что означает результат

Отсутствие deep finding не показывает, закрыты ли BPF maps. Смотрите legacy `bpf-map-accessible` и фактический доступ app UID.

**Как строка влияет на отчёт:** ID сохранён в каталоге и UI, однако текущая версия 2.10.0 не формирует отдельную положительную строку этого kind. Обычно рядом работает более конкретный сигнал.

## Ограничения и возможные ложные срабатывания

Два ID для одного kind могут вводить в заблуждение при будущих изменениях. Документация фиксирует состояние версии 2.10.0; после подключения функции надо обновить mapping/tests.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Сохраняйте stock SELinux/BPF permissions и не ослабляйте `/sys/fs/bpf`. Для текущего ID действий нет.

### С root

Не удаляйте pinned netd maps и не отключайте eBPF. Если цель — закрыть доступ, меняйте policy минимально для untrusted_app и тестируйте traffic accounting.

### Как проверить результат

```bash
rg -n 'detectBpfMaps|nativeDetectVpnDetector|nativeDetectVpnAdvanced|bpf_map_accessible' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Удаление или повреждение netd BPF maps может сломать firewall, статистику данных и сеть. Не выполняйте destructive cleanup.

### Откат

Откатите sepolicy/module и перезагрузите устройство; при повреждении netd state восстановите boot/system image, а не пересоздавайте карты вручную.

## Уровень доказательности

**Реестр/совместимость.** Проверено по отсутствию вызова в deep function и наличию legacy producer; status registry-only.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [Linux BPF](https://docs.kernel.org/bpf/index.html).
- Внешняя первичная документация или официальный проект: [AOSP eBPF traffic monitoring](https://source.android.com/docs/core/datausage/ebpf-traffic-monitor).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `bpf-map-accessible`, `proc-net-dev-vpn`.

[К справочнику Native signs](../)
