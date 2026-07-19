---
title: "Счётчики VPN-интерфейса в /proc/net/dev"
permalink: /help/ru/native/proc-net-dev-vpn/
---

# Счётчики VPN-интерфейса в /proc/net/dev

> **ID:** `PROC_NET_DEV_VPN`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проверяются `/proc/net/dev` и `/proc/self/net/dev`. После двух header lines parser извлекает имя до двоеточия и ищет exact `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, `xfrm0`. Для первого совпадения выводятся RX/TX bytes.

### Точное условие срабатывания

В procfs device statistics присутствует строка одного из шести VPN-интерфейсов; ненулевой трафик не требуется.

## Что означает результат

Сетевой интерфейс остаётся видимым в глобальной статистике. Нулевые counters всё равно подтверждают объект; ненулевые помогают связать его с активностью.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

На части Android чтение закрыто SELinux. Ищутся только exact names. Проба возвращает первое совпадение и не анализирует packet/error/drop counters.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси. Очистка статистики не удаляет строку и не нужна. Внешний gateway устраняет сам local netdev.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Для этого пути нужен seq-file/procfs filter. Upstream VPNHide в своей матрице не заявляет `/proc/net/dev` для стабильных kernel backends; VPNHide Next заявляет его на максимальном уровне, с теми же рисками ядра.

### Как проверить результат

```bash
adb shell 'cat /proc/net/dev 2>/dev/null || cat /proc/self/net/dev 2>/dev/null'
adb shell ip -s link show
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Обнуление глобальных counters ломает системный traffic accounting и может повлиять на Data Saver, статистику и firewall policy.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по proc parser и HIGH_CONFIDENCE mapping.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [/proc/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Внешняя первичная документация или официальный проект: [VPNHide Next](https://github.com/soranerai/vpnhide_next).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `vpn-qdisc`, `deep-vpn-qdisc`, `bpf-map-accessible`, `sysclassnet-vpn`.

[К справочнику Native signs](../)
