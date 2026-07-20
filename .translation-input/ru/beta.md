---
title: β-проверки — условия, кворум и противодействие
permalink: /help/ru/anti-detection/beta/
---

# β-проверки — условия, кворум и противодействие

β-режим в RKNHardering включается явно. Он не превращает каждый отказ или необычную строку в `DETECTED`: `PERMISSION_DENIED`, `UNSUPPORTED`, race, malformed/truncated и смена network epoch подавляются или понижаются. Положительное наблюдение должно совпасть с реестром source/domain/independence group.

Только две проверки могут стать самостоятельным hard signal: **`beta.vpn_binder`** с authority `BINDER_SERVICE` и **`beta.tun_fd`** с authority `KERNEL_QUERY`. Для обеих нужны минимум две успешные выборки, одинаковая классификация и стабильный epoch. Остальные β-проверки дают review или участвуют в кворуме независимых групп.

## Без root

Главные стратегии те же: внешний gateway убирает локальный VPN; owner user убирает profile-контекст; отключённый proxy/control plane убирает локальные sockets; оригинальный APK без virtual container убирает sandbox/hook противоречия. Не пытайтесь «лечить» permission denial выдачей Shizuku/root — это расширяет доступ проверки и может открыть больше реальных сигналов.

## С root

β-слой особенно хорошо видит частичные hooks. Framework должен очищать Binder согласованно, kernel backend — raw netlink/socket/TUN FD, а target process должен оставаться без Xposed/Zygisk injection. Root/Shizuku глобальные probes запускаются только при явном выборе; во время проверки своей защиты полезно включить их осознанно, но не выдавать приложению постоянные лишние права.

## Полная таблица β-ID

| β-ID | Что наблюдает | Домен / независимая группа | Без root | С root | Остаток |
|---|---|---|---|---|---|
| `beta.vpn_binder` | Binder-запрос к Android VPN service/состоянию. **Hard-authority при стабильном повторе.** | `VPN_OR_PROXY` / `android_vpn_service` | Внешний gateway. | System-server framework filtering; target вне Xposed scope. | Binder и native модель должны совпасть. |
| `beta.user_profile` | Текущий user/profile через Android user APIs. | `ISOLATED_PROFILE` / `android_user_manager` | Owner user. | Только правильное UID targeting; не ломать UserManager. | Правдивый профильный сигнал остаётся. |
| `beta.foreground_user` | Foreground user и соответствие контексту процесса. | `ISOLATED_PROFILE` / `android_user_manager` | Owner user. | Только правильное UID targeting; не ломать UserManager. | Правдивый профильный сигнал остаётся. |
| `beta.connectivity_binder` | Connectivity Binder ответы против публичной модели. | `NETWORK_PATH_DIVERGENCE` / `android_connectivity` | Внешний gateway. | System-server framework filtering; target вне Xposed scope. | Binder и native модель должны совпасть. |
| `beta.netd_netid` | netd/network ID активного пути. | `NETWORK_PATH_DIVERGENCE` / `netd` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.socket_identity` | Socket mark/netId/identity. | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.inet_diag_cookie` | INET_DIAG cookie и socket identity. | `NETWORK_PATH_DIVERGENCE` / `socket_diag` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.route_lookup` | Single route lookup к контрольной цели. | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.policy_rules` | Policy routing rules для UID/netId. | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.rtnl_address` | RTNL address dump IPv4/IPv6. | `NETWORK_PATH_DIVERGENCE` / `kernel_link` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.extended_rtnetlink` | Расширенный rtnetlink/netd routing контекст. | `NETWORK_PATH_DIVERGENCE` / `kernel_routing` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.interface_driver` | Driver/kind/details сетевого интерфейса. | `VPN_OR_PROXY` / `kernel_link` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.interface_traffic` | Счётчики интерфейсов и фактический egress. | `NETWORK_PATH_DIVERGENCE` / `active_egress` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.wireguard_genl` | WireGuard generic-netlink state. | `VPN_OR_PROXY` / `kernel_vpn` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.ovpn_genl` | OpenVPN DCO/generic-netlink state. | `VPN_OR_PROXY` / `kernel_vpn` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.xfrm` | XFRM/IPsec states и policies. | `VPN_OR_PROXY` / `kernel_ipsec` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.unix_diag` | Unix-domain sockets локального control plane. | `VPN_OR_PROXY` / `local_control_plane` | Выключить proxy/control daemon. | UID/namespace block. | Listener/Unix socket может остаться видимым. |
| `beta.unix_peer_identity` | Peer credentials/identity Unix socket. | `VPN_OR_PROXY` / `local_control_plane` | Выключить proxy/control daemon. | UID/namespace block. | Listener/Unix socket может остаться видимым. |
| `beta.tun_fd` | Kernel query TUN file descriptor. **Hard-authority при стабильном повторе.** | `VPN_OR_PROXY` / `process_fd` | Убрать локальный VpnService через внешний gateway. | Kernel filtering; userspace hook недостаточен. | Hard только при ≥2 стабильных совпадающих выборках. |
| `beta.bpf_netd` | BPF/netd maps и traffic policy. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.cgroup_bpf` | Cgroup BPF attachment/policy. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.netfilter_path` | Netfilter path/redirect state. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.original_destination` | Original destination после transparent redirect. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.direct_syscall_consistency` | Сравнение libc API с direct syscall. | `HOOK_OR_TAMPERING` / `hook_consistency` | Без process injection. | Kernel backend, target вне Zygisk/Xposed. | Частичный hook раскрывается альтернативным путём. |
| `beta.io_uring_consistency` | Альтернативный io_uring путь против hooked API. | `HOOK_OR_TAMPERING` / `alternate_syscall_path` | Без process injection. | Kernel backend, target вне Zygisk/Xposed. | Частичный hook раскрывается альтернативным путём. |
| `beta.fd_identity` | Тип/identity file descriptors процесса. | `HOOK_OR_TAMPERING` / `process_fd` | Без process injection. | Kernel backend, target вне Zygisk/Xposed. | Частичный hook раскрывается альтернативным путём. |
| `beta.sandbox_identity.process` | Process identity виртуального контейнера. | `APP_VIRTUALIZATION` / `process_identity` | Оригинальный APK в обычном sandbox. | Не использовать virtual container/repack. | Root не делает контейнер обычным профилем. |
| `beta.sandbox_identity.filesystem` | Filesystem layout/identity sandbox. | `APP_VIRTUALIZATION` / `filesystem_identity` | Оригинальный APK в обычном sandbox. | Не использовать virtual container/repack. | Root не делает контейнер обычным профилем. |
| `beta.sandbox_identity.namespace` | Namespace identity sandbox/virtualization. | `APP_VIRTUALIZATION` / `namespace_identity` | Оригинальный APK в обычном sandbox. | Не использовать virtual container/repack. | Root не делает контейнер обычным профилем. |
| `beta.fscrypt_identity` | fscrypt/user storage identity. | `APP_VIRTUALIZATION` / `filesystem_identity` | Оригинальный APK в обычном sandbox. | Не использовать virtual container/repack. | Root не делает контейнер обычным профилем. |
| `beta.linker_integrity` | Linker/loader integrity и hooks. | `HOOK_OR_TAMPERING` / `loader_integrity` | Без process injection. | Kernel backend, target вне Zygisk/Xposed. | Частичный hook раскрывается альтернативным путём. |
| `beta.dns_netid` | DNS resolver netId/path. | `NETWORK_PATH_DIVERGENCE` / `dns_path` | Согласовать реальный route/DNS/TLS; внешний gateway. | Root не подменяет серверный путь; исключить MITM. | Network epoch и шум; server context сам по себе не всегда hard. |
| `beta.native_dns_resolver` | Native resolver против framework DNS. | `NETWORK_PATH_DIVERGENCE` / `dns_path` | Согласовать реальный route/DNS/TLS; внешний gateway. | Root не подменяет серверный путь; исключить MITM. | Network epoch и шум; server context сам по себе не всегда hard. |
| `beta.proxy_selector` | Java ProxySelector/system proxy consistency. | `VPN_OR_PROXY` / `android_proxy` | Выключить proxy/control daemon. | UID/namespace block. | Listener/Unix socket может остаться видимым. |
| `beta.transport_matrix` | HTTP/DNS/UDP матрица canary endpoints. | `NETWORK_PATH_DIVERGENCE` / `active_egress` | Согласовать реальный route/DNS/TLS; внешний gateway. | Root не подменяет серверный путь; исключить MITM. | Network epoch и шум; server context сам по себе не всегда hard. |
| `beta.tls_interception` | TLS interception/certificate path. | `VPN_OR_PROXY` / `tls_path` | Согласовать реальный route/DNS/TLS; внешний gateway. | Root не подменяет серверный путь; исключить MITM. | Network epoch и шум; server context сам по себе не всегда hard. |
| `beta.pktinfo` | IP_PKTINFO/IPv6 pktinfo входящего/исходящего пути. | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.netlink_transitions` | Временная последовательность netlink network events. | `NETWORK_PATH_DIVERGENCE` / `network_timeline` | Внешний gateway или отсутствие локального VPN. | Kernel-level filtering по конкретному каналу; Next advanced — эксперимент. | Denial часто neutral; kernel/ROM parity различается. |
| `beta.traceroute` | Traceroute/path observation. | `SYSTEM_NETWORK_CONTEXT` / `path_observation` | Согласовать реальный route/DNS/TLS; внешний gateway. | Root не подменяет серверный путь; исключить MITM. | Network epoch и шум; server context сам по себе не всегда hard. |
| `beta.server_fingerprint` | Удалённый fingerprint наблюдаемого канала. | `SYSTEM_NETWORK_CONTEXT` / `server_observation` | Согласовать реальный route/DNS/TLS; внешний gateway. | Root не подменяет серверный путь; исключить MITM. | Network epoch и шум; server context сам по себе не всегда hard. |
| `beta.root_emulator` | Сводная β-оценка root/emulator/device integrity. | `DEVICE_INTEGRITY` / `device_integrity` | Физический сток без root. | Минимизировать root surface; эмулятор не spoofить частично. | Review/кворум возможен. |


## Как читать кворум

Проверено проектом: β-network evidence становится `DETECTED`, когда есть как минимум две независимые network groups либо одна β-group плюс независимый стабильный network source. Isolation плюс network signal тоже может дать detected. Для tamper/app-virtualization нужны две независимые группы. `SYSTEM_NETWORK_CONTEXT`, куда попадают traceroute/server fingerprint, исключён из hard quorum сам по себе.

Следовательно, правильная цель — не «заглушить все β строки», а убрать независимость доказательств. Например, чистый Binder при грязном `tun_fd` и route lookup не помогает; чистый route dump при direct-syscall mismatch показывает частичный userspace hook.

## Проверка

Запускайте две последовательные выборки без переключения сети. Затем повторите после force-stop. Если результат меняется при каждом запуске, сначала исправьте гонку/network epoch, а не устанавливайте новый hide-модуль.

Привилегированный probe используйте в отдельном лабораторном прогоне. Не делайте Shizuku/root постоянной зависимостью обычного пользовательского теста: отсутствие privilege в политике β считается доступностью/ограничением, а не доказательством чистоты.

[Назад к оглавлению](../)
