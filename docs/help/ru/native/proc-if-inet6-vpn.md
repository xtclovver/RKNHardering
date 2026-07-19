---
title: "VPN-интерфейс в /proc/net/if_inet6"
permalink: /help/ru/native/proc-if-inet6-vpn/
---

# VPN-интерфейс в /proc/net/if_inet6

> **ID:** `PROC_IF_INET6_VPN`
> **Категория:** Интерфейсы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Высокая

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

Проверяются `/proc/net/if_inet6` и `/proc/self/net/if_inet6`. Каждая строка разбивается на шесть токенов; шестой токен — имя интерфейса. Считаются `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, `xfrm0`; при первом доступном файле с совпадениями функция завершается.

### Точное условие срабатывания

В IPv6 interface table найдена одна или несколько строк с фиксированным VPN-именем.

## Что означает результат

VPN-like netdev имеет IPv6-адрес и виден через procfs. Это прямой артефакт, даже если основной трафик IPv4.

**Как строка влияет на отчёт:** Строка переводится в `detected=true` и считается высокодостоверным локальным признаком.

## Ограничения и возможные ложные срабатывания

Интерфейс без IPv6-адреса здесь не появится. Доступ к procfs зависит от Android/SELinux. Список имён узкий, а дубликаты адресов увеличивают count.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Самый надёжный non-root способ — не создавать VPN-интерфейс на проверяемом телефоне: вынести туннель на роутер, travel-router, отдельный телефон-шлюз или другой узел сети. Per-app bypass в `VpnService` меняет маршрут трафика выбранного приложения, но `establish()` всё равно создаёт системный VPN-интерфейс, поэтому локальная проверка интерфейсов может продолжить срабатывать. Режим локального HTTP/SOCKS-прокси без TUN иногда убирает этот конкретный вектор, но оставляет порты, proxy-настройки и не покрывает приложения, которые игнорируют прокси. Отключение IPv6 внутри VPN может убрать именно эту строку, но ухудшает связность и не скрывает интерфейс через IPv4/netlink. Это не полноценный обход.

### С root

Для лабораторного сокрытия обычно нужен системный Java-слой и один native-бэкенд. У VPNHide это APK + Vector/LSPosed со scope только `System Framework` и ровно один из kmod, KPM или Zygisk. Для проверки, которая может идти прямым syscall или netlink, предпочтительнее kmod/KPM: userspace-хук Zygisk можно обойти и он оставляет след внутри процесса. Сначала изучите [карту покрытия VPNHide](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) и скачивайте сборки только из [официального release](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next заявляет более широкое покрытие, но сам предупреждает о возможных bootloop и kernel panic; его следует проверять только на тестовом устройстве. Upstream VPNHide отмечает `/proc/net/if_inet6` как Zygisk-only gap для kernel backends на момент его документации; проверяйте текущий release и конкретный backend, не полагайтесь на название модуля.

### Как проверить результат

```bash
adb shell 'cat /proc/net/if_inet6 2>/dev/null || cat /proc/self/net/if_inet6 2>/dev/null'
adb shell 'ip -6 addr show'
```

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Глобальное отключение IPv6 ломает IPv6-only/NAT64 сети, DNS64 и часть мобильной связности. Не используйте это как первый шаг.

### Откат

Верните IPv6-настройки VPN/системы, удалите точечный filter и перезагрузитесь. Проверьте мобильную сеть и Wi‑Fi отдельно.

## Уровень доказательности

**Высокая.** Проверено по двум paths, parser token[5] и six-name list; kind high.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`VpnNativeDetectorChecker.kt` — deep VPN verdict и confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [/proc/net documentation](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- Внешняя первичная документация или официальный проект: [VPNHide coverage gaps](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `proc-ipv6-route-vpn`, `getifaddrs-vpn`, `sysfs-vpn-leak`.

[К справочнику Native signs](../)
