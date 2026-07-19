---
title: Справочник нативных проверок RKNHardering
permalink: /help/ru/native/
---

# Справочник нативных проверок RKNHardering

Здесь разобраны **все 85 `NativeSignalId` версии 2.10.0**. Это не перечень общих советов: каждая страница привязана к конкретному Kotlin/C++-условию, показывает роль строки в итоговом вердикте и разделяет действия **без root** и **с root**.

Для каждого сигнала указаны точный API, syscall, netlink request, файл, property или heuristic; ограничения; команды проверки; риски и откат. Отдельно отмечены исторические ID, у которых в текущем pipeline нет producer, и строка `gso_ok`, которую C++ создаёт без detail, а UI parser версии 2.10.0 отбрасывает.

Практическая матрица по всем локальным и серверным проверкам находится в [полной инструкции по противодействию обнаружению](../anti-detection/matrix/). Начинать лучше с [модели угроз](../anti-detection/threat-model/) и [лабораторной методики](../anti-detection/lab/): иначе легко убрать одну строку и одновременно создать три новых.

## Как читать роль сигнала

- **Высокая** — строка обычно устанавливает `detected=true`.
- **Средняя** — строка устанавливает `needsReview=true`; это основание для разбора, не самостоятельный окончательный вывод.
- **Низкая** — telemetry или baseline без порога обнаружения.
- **Смешанная** — один ID обслуживает несколько веток с разным влиянием.
- **Реестр/совместимость** — ID существует, но в версии 2.10.0 нет отдельного активного producer либо есть parser gap.

Команды ADB на страницах нужны для диагностики. `adb shell` работает под другим UID и SELinux domain, поэтому его результат не заменяет повторную проверку внутри RKNHardering. Root/kernel действия сначала выполняйте на тестовом устройстве с копией boot image и понятным способом отключить модуль из recovery.

## Интерфейсы

| Страница | ID | Роль | Статус | Что именно разбирает статья |
|---|---|---|---|---|
| [interface-enumeration](./interface-enumeration/) | `INTERFACE_ENUMERATION` | Смешанная | Активная проверка | Основное перечисление сетевых интерфейсов |
| [tuntap-type](./tuntap-type/) | `TUNTAP_TYPE` | Высокая | Активная проверка | Тип интерфейса ARPHRD_TUNNEL/TUN-TAP независимо от имени |
| [ipsec-interface](./ipsec-interface/) | `IPSEC_INTERFACE` | Низкая | Активная проверка | Интерфейсы IPsec/XFRM |
| [jvm-native-mismatch](./jvm-native-mismatch/) | `JVM_NATIVE_MISMATCH` | Смешанная | Активная проверка | Несогласованность Java NetworkInterface и native getifaddrs |
| [inet6-vpn-interface](./inet6-vpn-interface/) | `INET6_VPN_INTERFACE` | Высокая | Активная проверка | Legacy ioctl-проверка фиксированных VPN-интерфейсов |
| [arp-vpn-interface](./arp-vpn-interface/) | `ARP_VPN_INTERFACE` | Реестр/совместимость | ID сохранён для совместимости; отдельного producer в 2.10.0 нет | Зарезервированный legacy ID ARP на VPN-интерфейсе |
| [hidden-mac-neighbors](./hidden-mac-neighbors/) | `HIDDEN_MAC_NEIGHBORS` | Высокая | Активная проверка | ARP entries с нулевым или broadcast MAC |
| [sysfs-vpn-leak](./sysfs-vpn-leak/) | `SYSFS_VPN_LEAK` | Высокая | Активная проверка | VPN-интерфейс доступен через sysfs и proc/sys |
| [getifaddrs-vpn](./getifaddrs-vpn/) | `GETIFADDRS_VPN` | Высокая | Активная проверка | Фиксированные VPN-имена в getifaddrs() |
| [sysclassnet-vpn](./sysclassnet-vpn/) | `SYSCLASSNET_VPN` | Высокая | Активная проверка | Фиксированные VPN-интерфейсы в /sys/class/net |
| [rtm-getlink-vpn](./rtm-getlink-vpn/) | `RTM_GETLINK_VPN` | Высокая | Активная проверка | VPN-интерфейс в netlink RTM_GETLINK |
| [proc-if-inet6-vpn](./proc-if-inet6-vpn/) | `PROC_IF_INET6_VPN` | Высокая | Активная проверка | VPN-интерфейс в /proc/net/if_inet6 |
| [proc-net-dev-vpn](./proc-net-dev-vpn/) | `PROC_NET_DEV_VPN` | Высокая | Активная проверка | Счётчики VPN-интерфейса в /proc/net/dev |
| [ifindexname-vpn](./ifindexname-vpn/) | `IFINDEXNAME_VPN` | Высокая | Активная проверка | VPN-имя через if_indextoname() |

## Маршруты и сетевой стек

| Страница | ID | Роль | Статус | Что именно разбирает статья |
|---|---|---|---|---|
| [route-table](./route-table/) | `ROUTE_TABLE` | Смешанная | Активная проверка | Основная таблица маршрутов и default route |
| [host-route](./host-route/) | `HOST_ROUTE` | Средняя | Активная проверка | Публичный /32 или /128 host-route через физический интерфейс |
| [route-vpn-interface](./route-vpn-interface/) | `ROUTE_VPN_INTERFACE` | Высокая | Активная проверка | Legacy маршруты через фиксированные VPN-имена |
| [sysctl-forwarding](./sysctl-forwarding/) | `SYSCTL_FORWARDING` | Средняя | Активная проверка | IPv4 forwarding включён |
| [sysctl-rp-filter](./sysctl-rp-filter/) | `SYSCTL_RP_FILTER` | Средняя | Активная проверка | Reverse path filtering отключён глобально |
| [vpn-policy-rules](./vpn-policy-rules/) | `VPN_POLICY_RULES` | Высокая | Активная проверка | Legacy нестандартные IPv4 маршруты на VPN-интерфейсе |
| [vpn-qdisc](./vpn-qdisc/) | `VPN_QDISC` | Средняя | Активная проверка | Legacy счётчики трафика tun0/wg0 под именем qdisc |
| [tcp-mss-low](./tcp-mss-low/) | `TCP_MSS_LOW` | Высокая | Активная проверка | Низкий TCP MSS на локальном соединении |
| [bpf-map-accessible](./bpf-map-accessible/) | `BPF_MAP_ACCESSIBLE` | Высокая | Активная проверка | Доступ к netd BPF iface-index map |
| [proc-ipv6-route-vpn](./proc-ipv6-route-vpn/) | `PROC_IPV6_ROUTE_VPN` | Высокая | Активная проверка | VPN-интерфейс в /proc/net/ipv6_route |
| [vpn-policy-rules-netlink](./vpn-policy-rules-netlink/) | `VPN_POLICY_RULES_NETLINK` | Высокая | Активная проверка | Подозрительные policy rules через RTM_GETRULE |
| [fib-trie-denied](./fib-trie-denied/) | `FIB_TRIE_DENIED` | Средняя | Активная проверка | Доступ к /proc/net/fib_trie запрещён или завершился ошибкой |
| [deep-vpn-qdisc](./deep-vpn-qdisc/) | `DEEP_VPN_QDISC` | Реестр/совместимость | ID сохранён для совместимости; отдельного producer в 2.10.0 нет | Зарезервированный deep ID qdisc |
| [deep-bpf-map-accessible](./deep-bpf-map-accessible/) | `DEEP_BPF_MAP_ACCESSIBLE` | Реестр/совместимость | ID сохранён для совместимости; отдельного producer в 2.10.0 нет | Зарезервированный deep ID доступности BPF map |
| [route-count](./route-count/) | `ROUTE_COUNT` | Низкая | Активная проверка | Информационный подсчёт маршрутов и интерфейсов |
| [trim-oracle](./trim-oracle/) | `TRIM_ORACLE` | Средняя | Активная проверка | Несогласованность количества интерфейсов между if_indextoname и RTM_GETLINK |
| [pmtu-mss-combined](./pmtu-mss-combined/) | `PMTU_MSS_COMBINED` | Низкая | Активная проверка | TCP_INFO MSS на локальном соединении 127.0.0.1:443 |
| [udp-pmtu-ok](./udp-pmtu-ok/) | `UDP_PMTU_OK` | Низкая | Активная проверка | Отправка UDP 1500 байт на 127.0.0.1:53 успешна |
| [udp-pmtu-fail](./udp-pmtu-fail/) | `UDP_PMTU_FAIL` | Средняя | Активная проверка | Отправка UDP 1500 байт на loopback завершилась ошибкой |
| [normal-pmtu](./normal-pmtu/) | `NORMAL_PMTU` | Низкая | Активная проверка | MTU первого не-туннельного интерфейса |
| [timing-oracle](./timing-oracle/) | `TIMING_ORACLE` | Низкая | Активная проверка | Время socket/sendto на ARM64 через CNTVCT_EL0 |
| [backpressure](./backpressure/) | `BACKPRESSURE` | Низкая | Активная проверка | Loopback UDP flood: 50 000 пакетов по 1400 байт |
| [gso-failed](./gso-failed/) | `GSO_FAILED` | Низкая | Активная проверка | UDP_SEGMENT не принят setsockopt() |
| [gso-send-failed](./gso-send-failed/) | `GSO_SEND_FAILED` | Низкая | Активная проверка | UDP_SEGMENT принят, но отправка 4800 байт не удалась |
| [gso-ok](./gso-ok/) | `GSO_OK` | Реестр/совместимость | Нативный producer есть, но строка теряется при текущем разборе UI | UDP GSO принят и loopback send успешен |
| [hardware-timestamp](./hardware-timestamp/) | `HW_TIMESTAMP` | Низкая | Активная проверка | SIOCSHWTSTAMP успешно настроен на loopback |
| [traceroute-denied](./traceroute-denied/) | `TRACEROUTE_DENIED` | Средняя | Активная проверка | Loopback UDP send с TTL=1 получил EACCES |

## VPN-артефакты и сокеты

| Страница | ID | Роль | Статус | Что именно разбирает статья |
|---|---|---|---|---|
| [vpn-property](./vpn-property/) | `VPN_PROPERTY` | Высокая | Активная проверка | Старые VPN/DNS system properties |
| [dns-property](./dns-property/) | `DNS_PROPERTY` | Реестр/совместимость | ID сохранён для совместимости; отдельного producer в 2.10.0 нет | Зарезервированный ID dns_prop |
| [vpn-file](./vpn-file/) | `VPN_FILE` | Реестр/совместимость | ID сохранён для совместимости; отдельного producer в 2.10.0 нет | Зарезервированный общий ID VPN-файлов |
| [tcp-vpn-port](./tcp-vpn-port/) | `TCP_VPN_PORT` | Реестр/совместимость | ID сохранён для совместимости; отдельного producer в 2.10.0 нет | Зарезервированный legacy ID TCP VPN-портов |
| [udp-vpn-port](./udp-vpn-port/) | `UDP_VPN_PORT` | Реестр/совместимость | ID сохранён для совместимости; отдельного producer в 2.10.0 нет | Зарезервированный legacy ID UDP VPN-портов |
| [established-vpn-socket](./established-vpn-socket/) | `ESTABLISHED_VPN_SOCKET` | Средняя | Активная проверка | Established TCP-соединение на типичный VPN-порт |
| [so-bindtodevice](./so-bindtodevice/) | `SO_BINDTODEVICE` | Средняя | Активная проверка | Legacy socket identity под историческим именем SO_BINDTODEVICE |
| [loopback-port-conflict](./loopback-port-conflict/) | `LOOPBACK_PORT_CONFLICT` | Высокая | Активная проверка | Занятые TCP-порты на 127.0.0.1 |
| [ip-recverr](./ip-recverr/) | `IP_RECVERR` | Реестр/совместимость | ID сохранён для совместимости; отдельного producer в 2.10.0 нет | Зарезервированный положительный ID IP_RECVERR |
| [inet-diag-denied](./inet-diag-denied/) | `INET_DIAG_DENIED` | Средняя | Активная проверка | NETLINK_SOCK_DIAG недоступен приложению |
| [bindtodevice-leak](./bindtodevice-leak/) | `BINDTODEVICE_LEAK` | Высокая | Активная проверка | SO_BINDTODEVICE подтверждает существование VPN-интерфейса |
| [getsockname-leak](./getsockname-leak/) | `GETSOCKNAME_LEAK` | Высокая | Активная проверка | Непривязанный UDP socket сразу получил private IPv4 |
| [udp-port-conflict-physical](./udp-port-conflict-physical/) | `UDP_PORT_CONFLICT_PHYSICAL` | Высокая | Активная проверка | Занятые VPN-порты UDP на физическом IPv4 |

## Хуки и целостность процесса

| Страница | ID | Роль | Статус | Что именно разбирает статья |
|---|---|---|---|---|
| [hook-markers](./hook-markers/) | `HOOK_MARKERS` | Средняя | Активная проверка | Именованные маркеры инъекций в /proc/self/maps |
| [rwx-memory-regions](./rwx-memory-regions/) | `RWX_MEMORY_REGIONS` | Низкая | Активная проверка | Крупные RWX-области памяти |
| [library-integrity](./library-integrity/) | `LIBRARY_INTEGRITY` | Средняя | Активная проверка | Происхождение ключевых libc-символов |
| [vpnhide](./vpnhide/) | `VPNHIDE` | Смешанная | Активная проверка | Артефакты VPNHide и regression-oracles |
| [lsposed](./lsposed/) | `LSPOSED` | Средняя | Активная проверка | Файловые артефакты LSPosed/Vector-подобного стека |
| [hook-property](./hook-property/) | `HOOK_PROPERTY` | Высокая | Активная проверка | System properties LSPosed/Magisk/Zygote hook |

## Root и состояние системы

| Страница | ID | Роль | Статус | Что именно разбирает статья |
|---|---|---|---|---|
| [root-indicators](./root-indicators/) | `ROOT_INDICATORS` | Служебная | Активная проверка | Сводка нативных root-индикаторов |
| [root-su-binary](./root-su-binary/) | `ROOT_SU_BINARY` | Средняя | Активная проверка | Файл su в известных путях |
| [root-property](./root-property/) | `ROOT_PROPERTY` | Средняя | Активная проверка | Подозрительные системные свойства root/debug |
| [root-management](./root-management/) | `ROOT_MANAGEMENT` | Средняя | Активная проверка | Каталоги и файлы root-менеджеров |
| [root-system-rw](./root-system-rw/) | `ROOT_SYSTEM_RW` | Средняя | Активная проверка | Доступность /system для записи |
| [root-suspicious-mount](./root-suspicious-mount/) | `ROOT_SUSPICIOUS_MOUNT` | Средняя | Активная проверка | Mount-строки с Magisk/core-only и root-маркерами |
| [root-overlay-mount](./root-overlay-mount/) | `ROOT_OVERLAY_MOUNT` | Средняя | Активная проверка | Overlay mount поверх /system или /vendor |
| [root-selinux](./root-selinux/) | `ROOT_SELINUX` | Средняя | Активная проверка | SELinux permissive или недоступный enforce-файл |
| [root-uid](./root-uid/) | `ROOT_UID` | Средняя | Активная проверка | UID/EUID/GID процесса равен 0 |
| [root-magisk-property](./root-magisk-property/) | `ROOT_MAGISK_PROPERTY` | Средняя | Активная проверка | Magisk-специфичные system properties |

## Эмуляция, профили и изоляция

| Страница | ID | Роль | Статус | Что именно разбирает статья |
|---|---|---|---|---|
| [emulator-indicators](./emulator-indicators/) | `EMULATOR_INDICATORS` | Служебная | Активная проверка | Сводка признаков эмулятора |
| [emulator-qemu-property](./emulator-qemu-property/) | `EMULATOR_QEMU_PROPERTY` | Средняя | Активная проверка | Системные свойства QEMU |
| [emulator-qemu-pipe](./emulator-qemu-pipe/) | `EMULATOR_QEMU_PIPE` | Средняя | Активная проверка | Устройства и сокеты QEMU/Genymotion |
| [emulator-goldfish](./emulator-goldfish/) | `EMULATOR_GOLDFISH` | Средняя | Активная проверка | Goldfish/Ranchu в hardware/board properties |
| [emulator-qemu-driver](./emulator-qemu-driver/) | `EMULATOR_QEMU_DRIVER` | Средняя | Активная проверка | Goldfish в /proc/tty/drivers |
| [emulator-bluestacks](./emulator-bluestacks/) | `EMULATOR_BLUESTACKS` | Средняя | Активная проверка | Файлы BlueStacks |
| [emulator-build-profile](./emulator-build-profile/) | `EMULATOR_BUILD` | Средняя | Активная проверка | Эвристики Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT |
| [isolation-profile](./isolation-profile/) | `ISOLATION_PROFILE` | Служебная | Активная проверка | Сводка Android user/profile isolation |
| [isolation-clone](./isolation-clone/) | `ISOLATION_CLONE` | Средняя | Активная проверка | OEM clone/dual-app userId |
| [isolation-secondary-user](./isolation-secondary-user/) | `ISOLATION_SECONDARY_USER` | Средняя | Активная проверка | Запуск не в основном пользователе |
| [isolation-work-profile](./isolation-work-profile/) | `ISOLATION_WORK_PROFILE` | Средняя | Активная проверка | RKNHardering является profile owner |

## Служебные сигналы

| Страница | ID | Роль | Статус | Что именно разбирает статья |
|---|---|---|---|---|
| [native-library](./native-library/) | `NATIVE_LIBRARY` | Доступность | Активная проверка | Загрузка нативной библиотеки проверок |
| [syscall-unavailable](./syscall-unavailable/) | `SYSCALL_UNAVAILABLE` | Доступность | Активная проверка | Нативная syscall/socket-проба недоступна |
| [general-diagnostics](./general-diagnostics/) | `GENERAL_DIAGNOSTICS` | Служебная | Активная проверка | Deep native detector не вернул ни одной строки |
| [unknown-signals](./unknown-signals/) | `UNKNOWN` | Служебная | Активная проверка | Неизвестный или не сопоставленный native kind |

## Основные официальные точки загрузки root-компонентов

- [VPNHide releases](https://github.com/okhsunrog/vpnhide/releases/latest) и его [карта покрытия](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- [VPNHide Next releases](https://github.com/soranerai/vpnhide_next/releases/latest) — экспериментальный fork с более агрессивными kernel hooks.
- [Vector releases](https://github.com/JingMatrix/Vector/releases/latest) для framework/Xposed-слоя.
- [Magisk releases](https://github.com/topjohnwu/Magisk/releases/latest), [KernelSU Next releases](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest) и [APatch releases](https://github.com/bmax121/APatch/releases/latest).

Скачивайте APK/ZIP только из официального репозитория или release, проверяйте подпись/хэш, не запускайте неизвестные installer scripts с root и не ставьте несколько native backends, которые перехватывают одни функции ядра.

[К оглавлению языка](../)
