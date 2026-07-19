---
title: "VPN-интерфейс доступен через sysfs и proc/sys"
permalink: /help/ru/native/sysfs-vpn-leak/
---

# VPN-интерфейс доступен через sysfs и proc/sys

> **ID:** `SYSFS_VPN_LEAK`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectSysfsLeak()` не перечисляет каталоги целиком, а делает `stat()` для фиксированных имён `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, `xfrm0`. Проверяются `/sys/class/net`, `/sys/devices/virtual/net`, а также ветки `/proc/sys/net/{ipv4,ipv6}/{conf,neigh}`. Любой существующий путь собирается в одну строку `sysfs_vpn_leak`.

### Точное условие срабатывания

Хотя бы один из 36 фиксированных путей существует и доступен для `stat()` из процесса приложения.

## Что означает результат

Это прямое подтверждение того, что kernel object с типичным VPN-именем остаётся видимым через файловое представление сети. Строка высокодостоверная, но она подтверждает имя интерфейса, а не то, что трафик RKNHardering обязательно идёт через него.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Список имён намеренно узкий. Переименованный интерфейс может не попасть сюда, но обнаружиться через основной matcher, тип 65534, netlink, ifindex oracle или маршруты. На stock enforcing Android часть путей может быть закрыта SELinux; отсутствие строки тогда означает только отсутствие доступа по этому пути.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси. Очистка кэша, Private Space и per-app bypass не удаляют `/sys/class/net/<iface>` из общего kernel namespace. Внешний шлюз — единственный non-root вариант, который действительно не создаёт этот объект на телефоне.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Для этого вектора backend должен фильтровать lookup/stat/readdir или скрывать сам netdev согласованно. Upstream VPNHide документирует `/sys/class/net` как пробел, обычно прикрытый SELinux; VPNHide Next заявляет filesystem-level скрытие на максимальном уровне, но это нужно проверять на конкретном ROM.

### Как проверить результат

```bash
adb shell 'for b in /sys/class/net /sys/devices/virtual/net /proc/sys/net/ipv4/conf /proc/sys/net/ipv6/conf /proc/sys/net/ipv4/neigh /proc/sys/net/ipv6/neigh; do for n in tun0 tun1 utun0 wg0 ppp0 xfrm0; do [ -e "$b/$n" ] && echo "$b/$n"; done; done'
```
Команда выполняется под shell UID. Для проверки target UID ориентируйтесь на detail RKNHardering; после изменения сделайте force-stop и перезапустите приложение.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Глобальное сокрытие `/sys` или `/proc/sys/net` ломает диагностику и может затронуть системные сервисы. Неверный kernel hook способен вызвать bootloop или panic.

### Откат

Отключите модуль из recovery/безопасного режима, восстановите исходный boot image и перезагрузитесь. Не оставляйте SELinux permissive как «обход».

## Уровень доказательности

**Высокая.** Проверено по шести именам, двум sysfs bases и четырём proc/sys bases в `detectSysfsLeak()`; kind входит в HIGH_CONFIDENCE.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Внешняя первичная документация или официальный проект: [Linux sysfs networking ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net).
- Внешняя первичная документация или официальный проект: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Внешняя первичная документация или официальный проект: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Внешняя первичная документация или официальный проект: [VPNHide Next](https://github.com/soranerai/vpnhide_next).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `sysclassnet-vpn`, `getifaddrs-vpn`, `tuntap-type`, `ifindexname-vpn`.

[К справочнику Native signs](../)
