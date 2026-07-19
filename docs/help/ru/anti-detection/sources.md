---
title: Источники, загрузки и статус утверждений
permalink: /help/ru/anti-detection/sources/
---

# Источники, загрузки и статус утверждений

Последняя ручная сверка ключевых ссылок и текущего состояния проектов: **19 июля 2026 года**. Для загрузки всегда используйте `releases/latest` официального репозитория, а не перепакованные APK/ZIP из чатов. Если проект публикует SHA-256 или подпись, сверяйте её до установки.

## RKNHardering — проверено проектом

- [Исходный проект RKNHardering](https://github.com/xtclovver/RKNHardering)
- [Архитектура и текущие проверки в README](https://github.com/xtclovver/RKNHardering/blob/main/README.md)
- Локальные источники этой копии: `DirectSignsChecker`, `IndirectSignsChecker`, `BypassChecker`, `NativeSignsChecker`, `VpnNativeDetectorChecker`, `BetaCheckRegistry`, `BetaEvidencePolicy`, `VerdictEngine`, `NativeSignalId`, `EvidenceSource`.
- [Исследовательская записка по β-проверкам](https://github.com/xtclovver/RKNHardering/blob/main/docs/beta-checks-research.md)

Все точные количества и ID в этой инструкции получены из локального кода, а не из сторонних списков.

## Android/AOSP — архитектурные ограничения

- [`VpnService`](https://developer.android.com/reference/android/net/VpnService) — создание виртуального интерфейса, `protect()`, underlying networks.
- [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder) — allowed/disallowed applications, routes, DNS, MTU, proxy.
- [Package visibility filtering](https://developer.android.com/training/package-visibility) — ограничения видимости пакетов Android 11+.
- [AOSP Work profiles](https://source.android.com/docs/devices/admin/managed-profiles) — отдельный userId/UID и данные профиля.
- [AOSP Private space](https://source.android.com/docs/security/features/private-space) — private profile и locked/stopped state.
- [AOSP Application Sandbox](https://source.android.com/docs/security/app-sandbox) — UID-based isolation.

## VPNHide upstream — внешнее заявление, проверять на устройстве

- [Репозиторий](https://github.com/okhsunrog/vpnhide)
- [Последний release](https://github.com/okhsunrog/vpnhide/releases/latest)
- [Полная карта detection vectors](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)
- [kmod README](https://github.com/okhsunrog/vpnhide/blob/main/kmod/README.md)
- [KPM README](https://github.com/okhsunrog/vpnhide/blob/main/kmod/kpm/README.md)
- [Zygisk README](https://github.com/okhsunrog/vpnhide/blob/main/zygisk/README.md)
- [LSPosed/app README](https://github.com/okhsunrog/vpnhide/blob/main/lsposed/README.md)
- [portshide README](https://github.com/okhsunrog/vpnhide/blob/main/portshide/README.md)

Значимые ограничения из документации проекта: server-side сигналы вне области; raw syscall обходит Zygisk; kernel-бэкенды и Zygisk не нужно складывать; некоторые procfs и KPM parity случаи остаются условными.

## VPNHide Next — расширенный экспериментальный форк

- [Репозиторий](https://github.com/soranerai/vpnhide_next)
- [Последний release](https://github.com/soranerai/vpnhide_next/releases/latest)
- [LSPosed/system_server README](https://github.com/soranerai/vpnhide_next/blob/main/lsposed/README.md)
- [Kernel module README](https://github.com/soranerai/vpnhide_next/blob/main/kmod/README.md)

Проект заявляет дополнительные MTU/MSS/TCP_INFO, PMTU/GSO, BPF, qdisc, timing, sysfs/procfs и profile-векторы. Его README отдельно предупреждает о нестабильности, bootloop и kernel panic. Эти возможности помечены в инструкции как внешние заявления.

## Root и framework

- [Magisk](https://github.com/topjohnwu/Magisk), [releases](https://github.com/topjohnwu/Magisk/releases/latest), [install.md](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md)
- [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next), [releases](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest), [docs](https://kernelsu-next.github.io/webpage/)
- [APatch](https://github.com/bmax121/APatch), [releases](https://github.com/bmax121/APatch/releases/latest), [русская установка](https://apatch.dev/ru/install.html)
- [Vector](https://github.com/JingMatrix/Vector), [releases](https://github.com/JingMatrix/Vector/releases/latest)
- [Архивированный LSPosed](https://github.com/LSPosed/LSPosed)
- [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext), [releases](https://github.com/Dr-TSNG/ZygiskNext/releases/latest)
- [NoHello](https://github.com/MhmRdd/NoHello), [releases](https://github.com/MhmRdd/NoHello/releases/latest)
- [SUSFS core](https://gitlab.com/simonpunk/susfs4ksu), [SUSFS userspace module](https://github.com/sidex15/susfs4ksu-module), [releases](https://github.com/sidex15/susfs4ksu-module/releases/latest)
- [Hide My Applist](https://github.com/Dr-TSNG/Hide-My-Applist), [releases](https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest)

NoHello/Zygisk Next/SUSFS/HMA не считаются обязательными и не гарантируются против RKNHardering. Они перечислены как варианты исследования root surface. HMA особенно важно не путать с VPNHide Apps: HMA обычно работает в контексте выбранного приложения, а VPNHide фильтрует PackageManager в `system_server`.

## Профили и клоны

- [Shelter](https://gitea.angry.im/PeterCxy/Shelter)
- [Insular](https://gitlab.com/secure-system/Insular)
- [AOSP managed profiles](https://source.android.com/docs/devices/admin/managed-profiles)
- [AOSP Private Space](https://source.android.com/docs/security/features/private-space)

Удаление профиля стирает его данные. Перед экспериментом нужна отдельная резервная копия.

## VPN-клиенты и маршрутизация

- [sing-box Android](https://sing-box.sagernet.org/clients/android/)
- [sing-box route rules](https://sing-box.sagernet.org/configuration/route/rule/)
- [sing-box DNS](https://sing-box.sagernet.org/configuration/dns/)
- [Mihomo general configuration](https://wiki.metacubex.one/en/config/general/)
- [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense)
- [Community Sub-Store guide](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md)
- [Community S-UI guide](https://github.com/jinndi/RKNHardering-defense/blob/main/S-UI.md)

Материалы `RKNHardering-defense` помечены как сообщения сообщества. Они полезны для split routing и внешнего шлюза, но не являются подтверждением скрытия всех локальных и β-векторов версии 2.10.0.

## Почему нет ссылок на случайные «универсальные bypass APK»

Приложение, которое требует отключить Play Protect, выдать Accessibility/Device Admin без понятной причины, загрузить SuperKey, импортировать приватную подписку или установить неподписанный kernel ZIP, создаёт несоразмерный риск. Проверяйте источник, историю репозитория, release signature/hash и разрешения. Не передавайте root-ключи, VPN-секреты и логи с токенами авторам непроверенных сборок.

[Назад к оглавлению](../)
