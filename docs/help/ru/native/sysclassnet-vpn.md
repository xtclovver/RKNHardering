---
title: "Фиксированные VPN-интерфейсы в /sys/class/net"
permalink: /help/ru/native/sysclassnet-vpn/
---

# Фиксированные VPN-интерфейсы в /sys/class/net

> **ID:** `SYSCLASSNET_VPN`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

`detectSysclassnetVpn()` делает `stat()` только для `/sys/class/net/{tun0,tun1,utun0,wg0,ppp0,xfrm0}` и перечисляет найденные имена. Это более узкий дубликат части `sysfs-vpn-leak`, сохранённый как отдельный диагностический ID.

### Точное условие срабатывания

Существует хотя бы один из шести фиксированных каталогов `/sys/class/net/<name>`.

## Что означает результат

Kernel sysfs показывает netdev с типичным VPN-именем. Совпадение считается высокодостоверным локальным артефактом.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Не проверяются содержимое `type`, `mtu`, `operstate` и нестандартные имена. SELinux может запретить traversal; тогда строка отсутствует даже при реальном интерфейсе. Наоборот, выключенный, но не удалённый netdev всё равно сработает.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Проверяйте, что решение закрывает не только `readdir`, но и прямой `stat("/sys/class/net/tun0")`; иначе этот exact-path probe обходит скрытый список каталога.

### Как проверить результат

```bash
adb shell 'for n in tun0 tun1 utun0 wg0 ppp0 xfrm0; do [ -e /sys/class/net/$n ] && { echo "[$n]"; cat /sys/class/net/$n/type /sys/class/net/$n/mtu /sys/class/net/$n/operstate 2>/dev/null; }; done'
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Широкая подмена sysfs может нарушить NetworkStack, netd и OEM-сервисы. Не меняйте владельца/режимы sysfs-файлов: они создаются ядром.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Высокая.** Проверено по exact `stat()` calls и HIGH_CONFIDENCE mapping.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [sysfs class net ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net).
- Внешняя первичная документация или официальный проект: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `sysfs-vpn-leak`, `tuntap-type`, `proc-net-dev-vpn`.

[К справочнику Native signs](../)
