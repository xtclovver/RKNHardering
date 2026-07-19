---
title: Локальные Android-сигналы — Binder, TUN, маршруты и localhost
permalink: /help/ru/anti-detection/local-signals/
---

# Локальные Android-сигналы — Binder, TUN, маршруты и localhost

Локальные проверки отвечают на вопрос не «куда ушёл пакет», а «как Android описывает сеть этому UID». Они остаются видимыми даже при прямом egress и хорошем GeoIP.

## Карта локальных каналов

| Канал | Примеры в RKNHardering | Почему одного хука мало |
|---|---|---|
| Framework/Binder | `TRANSPORT_VPN`, `IS_VPN`, `VpnTransportInfo`, `NOT_VPN`, `LinkProperties`, callbacks | Данные формирует `system_server`; native-хук их не меняет |
| libc/JNI | `NetworkInterface`, `getifaddrs`, `ioctl` | Java-хук `ConnectivityManager` не влияет на libc и ядро |
| netlink/kernel | `RTM_GETLINK`, `RTM_GETADDR`, routes, policy rules, qdisc | Raw syscall обходит обычный Zygisk/libc interposition |
| proc/sysfs | `/proc/net/*`, `/sys/class/net` | SELinux зависит от ROM; отказ доступа не гарантирован на всех устройствах |
| PackageManager | VPN-клиенты и `VpnService` declarations | Отдельно от активности туннеля |
| Local control plane | SOCKS/HTTP, Xray gRPC, Clash/sing-box REST | Пароль не скрывает listener; сканирование видит протокол и порт |
| dumpsys/system services | `vpn_management`, активные `VpnService` | Обычное приложение часто ограничено, но ROM/privilege меняют доступность |

## Без root

### Что можно сделать

Выключите системный HTTP/SOCKS proxy и PAC, если они не обязательны. Проверьте `settings get global http_proxy`, Java properties и настройки конкретной сети. Системный proxy — отдельный прямой детект, который никак не помогает скрыть VPN.

Отключите ненужные localhost listeners. В Clash/mihomo/sing-box/Xray control API должен быть либо выключен, либо недоступен приложению. Сильный secret защищает команды, но RKNHardering дополнительно распознаёт SOCKS5, HTTP CONNECT и известные REST/gRPC API.

Используйте Android package visibility в свою пользу, но не переоценивайте её. Начиная с Android 11 приложения по умолчанию видят отфильтрованный набор пакетов, однако `QUERY_ALL_PACKAGES`, intent queries, общий UID/installer и OEM-политики могут расширять обзор. Официальное описание: [Package visibility filtering](https://developer.android.com/training/package-visibility).

Если нужна чистая картина всех локальных каналов, перенесите VPN на внешний шлюз. Это устраняет `VpnService`, TUN, VPN app и localhost daemon на проверяемом Android одним архитектурным изменением.

### Что без root не решается в общем случае

Нельзя заставить ядро Android выдавать одному чужому UID отфильтрованный netlink dump, не меняя ядро/систему. Нельзя надёжно переписать Binder-ответ `NetworkCapabilities` другого приложения. Нельзя скрыть существующий TUN от `getifaddrs` и одновременно оставить его работающим для остальных приложений средствами обычного sandboxed APK.

Модифицированный APK/«rootless Xposed» не является эквивалентом. Репаковка меняет подпись и целостность приложения, а инъекция в его процесс прямо попадает под `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `LIBRARY_INTEGRITY`, β direct-syscall/linker проверки. Для RKNHardering это обычно хуже, чем исходный VPN-сигнал.

### Второй профиль

Рабочий профиль может скрыть установленные в другом профиле VPN-приложения и дать отдельные сетевые настройки, но Android всё равно использует общий kernel/network stack, а RKNHardering видит userId/profile state. Подробности — в [разделе о профилях](../profiles/).

## С root

Для полного локального покрытия нужны два слоя и, при необходимости, третий:

1. **Framework слой:** модуль VPNHide в Vector/LSPosed, область действия только `System Framework`. Он очищает Binder-объекты до сериализации в целевой процесс.
2. **Native слой:** ровно один из kmod, KPM или Zygisk. Kernel-варианты предпочтительнее, потому что raw syscall не обходит фильтрацию и целевой процесс остаётся нетронутым.
3. **Ports/package слой:** фильтрация `PackageManager` и блокировка loopback для целевого UID.

Подробная установка — [VPNHide и VPNHide Next](../root-vpnhide/).

### NetworkCapabilities и LinkProperties

VPNHide upstream заявляет фильтрацию `NetworkCapabilities`, `NetworkInfo`, `LinkProperties`, активной сети, списка сетей и callbacks в `system_server`. Это правильная точка вмешательства: RKNHardering получает уже очищенный Parcel, а не загруженный Xposed bridge в собственный процесс.

Проверьте область действия. В Vector/LSPosed должен быть выбран **только `System Framework`**, а не RKNHardering. Добавление целевого приложения в scope создаёт process-local hook surface и не требуется архитектуре VPNHide.

### Интерфейсы, маршруты и netlink

Kernel-бэкенд должен закрыть как минимум:

- `ioctl(SIOCGIFFLAGS/SIOCGIFNAME/SIOCGIFCONF/...)`;
- `getifaddrs()` и `NetworkInterface`;
- netlink `RTM_GETLINK`, `RTM_GETADDR`, route dump;
- `/proc/net/route` и IPv6 route там, где доступ разрешён;
- ifindex-оракулы и policy rules, если выбранный бэкенд их поддерживает.

VPNHide upstream документирует известные пробелы: raw syscall обходит Zygisk, а kernel-бэкенды в текущей карте не закрывают некоторые `/proc/net/tcp*`/`if_inet6` пути; KPM имеет отдельные parity-ограничения. Поэтому «модуль активен» проверяется не по статусу менеджера, а по конкретным строкам RKNHardering.

VPNHide Next заявляет более широкий режим, включая sysfs/procfs, MTU/MSS/TCP_INFO, PMTU/GSO, BPF, qdisc, timing и link-local. Это внешнее заявление; сравнивайте `Мин/Сред/Макс` на своей прошивке и храните recovery-путь.

### Localhost и API

Лучший вариант — выключить listener. Если это невозможно, примените блокировку по UID. В VPNHide upstream для этого существует отдельный `portshide`, который формирует правила для выбранных приложений. VPNHide Next заявляет kernel-хук `security_socket_connect` вместо iptables.

Не делайте вывод по одному `connection refused`: это означает отказ в соединении и может быть желаемым результатом. `timeout` означает, что операция не завершилась вовремя; для сканера это другой профиль поведения и иногда самостоятельный timing-сигнал. Проверяйте, как именно RKNHardering классифицирует результат.

### PackageManager

Роль Apps в VPNHide фильтрует перечисление, intent resolution, direct lookup, installer и UID mapping для выбранных observer UID. Системные UID и self-lookup должны оставаться рабочими. После настройки убедитесь, что launcher/installer не сломан и что VPN-клиент видит сам себя.

## Проверка результата

Узнайте UID целевого пакета:

```bash
adb shell cmd package list packages -U | grep 'com.notcvnt.rknhardering'
```

Проверьте базовое состояние:

```bash
adb shell dumpsys connectivity
adb shell ip -details link
adb shell ip route show table all
adb shell ip rule
adb shell settings get global http_proxy
```

Для VPNHide upstream, если установлен соответствующий backend, используйте только read-only диагностику:

```bash
adb shell su -c 'cat /data/system/vpnhide_config.json'
adb shell su -c 'ls -la /data/adb/modules | grep -i vpnhide'
adb shell su -c 'cat /proc/vpnhide_ctl 2>/dev/null || cat /proc/vpnhide_targets 2>/dev/null'
adb logcat -d | grep -iE 'VpnHide|Vector|LSPosed'
```

Путь `/proc/vpnhide_*` зависит от версии/форка. `no such file or directory` означает, что путь отсутствует или версия использует другой control interface; не создавайте файл вручную.

После изменения сделайте force-stop и два запуска. Для Zygisk/port rules иногда нужен перезапуск процесса; для kernel/system_server слоя обычно достаточно обновления конфигурации, но после установки модуля обязательна перезагрузка.

## Остаточные сигналы

Локальная чистота не убирает GeoIP, DNS, STUN и server fingerprint. Kernel hide не скрывает root автоматически. Package hiding не меняет подписи файлов и процесс-local hooks. Обратная ситуация тоже важна: чистый root namespace не скрывает `TRANSPORT_VPN`.

[Назад к оглавлению](../)
