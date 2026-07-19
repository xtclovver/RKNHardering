---
title: Лабораторная методика, команды проверки и откат
permalink: /help/ru/anti-detection/lab/
---

# Лабораторная методика, команды проверки и откат

Один случайный запуск ничего не доказывает. Сеть меняется, GeoIP-провайдеры расходятся, Android переключает default network, а β-политика намеренно подавляет нестабильные наблюдения. Ниже — минимальный воспроизводимый протокол.

## Тестовые профили

Создайте минимум четыре профиля, меняя одну переменную за раз.

| ID | Состояние | Зачем |
|---|---|---|
| B0 | Чистое устройство, VPN выключен | Базовые OEM/ROM/root/emulator ложные срабатывания |
| B1 | VPN включён, RKNHardering внутри VPN | Полный набор VPN и server-side сигналов |
| B2 | VPN включён, RKNHardering исключён | Явно показывает TUN + split-tunnel bypass и direct egress |
| H1 | Выбранный hide-метод | Сравнение с B1/B2 и поиск новых hook/root сигналов |
| R1 | Внешний роутер, локальный VPN выключен | Лучший non-root архитектурный baseline |
| P1 | Work/private/clone profile | Изоляция отдельно от сетевого пути |

Для root дополнительно прогоните H1 с framework-only, native-only и combined. Это быстро показывает, какой слой не работает.

## Что записывать перед запуском

- модель устройства и build fingerprint;
- Android, версия ядра `uname -r`, SELinux;
- текущий userId/profile;
- root manager/framework и точные версии модулей;
- VPN-клиент, режим TUN/proxy, MTU, IPv4/IPv6, package route;
- Wi‑Fi/мобильная сеть и время;
- ожидаемый egress и DNS;
- идентификатор network epoch, если он показан приложением.

Не публикуйте SuperKey, подписки, API secret, полный VPN config и приватные IP/hostnames без редактирования.

## Без root: сбор состояния

```bash
adb shell getprop ro.build.fingerprint
adb shell uname -a
adb shell getenforce
adb shell pm list users
adb shell am get-current-user
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell dumpsys connectivity
adb shell ip -details addr
adb shell ip -details route show table all
adb shell ip rule
adb shell settings get global http_proxy
```

На некоторых ROM обычный shell не видит все policy rules или `/proc/net` файлы. Это ограничение прав диагностики, не доказательство чистоты.

Force-stop между прогонами:

```bash
adb shell am force-stop com.notcvnt.rknhardering
adb shell monkey -p com.notcvnt.rknhardering 1
```

`monkey` запускает launcher activity, но может не сработать, если приложение не имеет launcher entry или устройство заблокировано. Тогда запустите вручную.

## С root: дополнительная диагностика

```bash
adb shell su -c 'id'
adb shell su -c 'ls -la /data/adb/modules'
adb shell su -c 'cat /data/system/vpnhide_config.json 2>/dev/null'
adb shell su -c 'cat /proc/vpnhide_ctl 2>/dev/null || cat /proc/vpnhide_targets 2>/dev/null'
adb logcat -c
# Запустите один тест вручную
adb logcat -d | grep -iE 'RKNHardering|VpnHide|Vector|LSPosed|Zygisk'
```

Не запускайте `chmod 777`, не отключайте SELinux и не меняйте ownership ради чтения. Это повреждает модель безопасности и создаёт дополнительные детекты.

## Проверка localhost без полного сканирования

RKNHardering уже выполняет скан. Для ручной проверки известных controller endpoint достаточно конкретных адресов:

```bash
adb shell 'toybox nc -z -w 1 127.0.0.1 9090; echo exit=$?'
adb shell 'toybox nc -z -w 1 127.0.0.1 19090; echo exit=$?'
```

Наличие `nc` зависит от ROM. `connection refused` означает, что listener на этом адресе/порту не принимает соединение; `timeout` — ответа не было вовремя; `not found` — в shell нет команды. Shell UID и UID RKNHardering могут видеть разные firewall правила, поэтому финальный критерий — результат приложения.

## Приёмочные критерии по слоям

### Сетевой путь

- ожидаемый IP стабилен минимум в двух запусках;
- RU/non-RU группы не расходятся необъяснимо;
- IPv4/IPv6 и DNS не идут разными политиками;
- STUN/UDP соответствует выбранной модели;
- смена сети создаёт новый ожидаемый epoch, а не случайную смесь результатов.

### Framework

- нет `TRANSPORT_VPN`, `IS_VPN`, `VpnTransportInfo`;
- `NOT_VPN` и активная сеть согласованы;
- LinkProperties не содержит VPN iface/routes/DNS;
- callback и binder β-пути не противоречат обычному API.

### Native

- нет TUN/TAP по имени и типу;
- `getifaddrs`, ioctl, netlink, route/proc/sysfs согласованы;
- ifindex и SIOCGIFCONF не оставляют оракулов;
- socket identity, MTU/MSS/PMTU/qdisc не противоречат заявленному физическому интерфейсу.

### Integrity

- target process не получает Xposed/Zygisk backend без необходимости;
- нет новых RWX/maps/linker/library mismatch;
- SELinux enforcing, system read-only;
- root paths/mounts не видны целевому UID;
- user/profile соответствует запланированному сценарию.

## Как локализовать причину

| Наблюдение | Наиболее вероятная причина | Исправление |
|---|---|---|
| Java чистый, native грязный | Native backend не активен/не тот UID/неподдерживаемый hook | Проверить backend, UID, версию ядра; не добавлять второй backend |
| Native чистый, `TRANSPORT_VPN` остаётся | Framework module не загрузился в `system_server` | Проверить Vector/LSPosed, `System Framework`, reboot |
| VPN скрыт, localhost найден | Ports роль/API listener не закрыт | Выключить API либо UID firewall/portshide |
| Всё локально чисто, итог detected | GeoIP/IP consensus/CDN/STUN/location | Исправлять маршрут/egress, а не hooks |
| После Zygisk появились RWX/linker | In-process backend обнаружен | Перейти на kernel backend, убрать target из injection |
| Только work-profile строки | Сценарий действительно в userId > 0 | Запустить в owner либо принять review как правдивый сигнал |
| `permission denied` в shell | Недостаточные права/SELinux | Не считать чистотой; использовать доступную диагностику, не ослаблять SELinux |
| `address already in use` | Порт занят другим listener | Найти владельца/отключить API; смена порта не решает полный скан |
| `invalid config` | Ошибка JSON/схемы | Восстановить backup, проверить валидатором, применить через UI |

## Риски и план отката

Перед root/kernel тестом подготовьте документированный откат:

1. Где лежит стоковый boot/init_boot и рабочий patched image.
2. Как войти в bootloader/recovery.
3. Как включить safe mode выбранного root manager.
4. Какой последний модуль был установлен.
5. Где сохранена копия `/data/system/vpnhide_config.json` и VPN config.
6. Какие данные находятся в work/private profile и как они экспортированы.

При сбое отключайте последнее изменение. Не устанавливайте новый модуль поверх неисправного состояния. Если потеряна сеть, сначала верните native backend/ports к исходному состоянию, затем проверяйте framework. Если bootloop начался после kernel ZIP, не загружайте другой kernel module «для исправления» — восстановите известный рабочий образ или отключите виновный модуль официальным способом.

## Контроль полноты этой инструкции

Файл [полной матрицы](../matrix/) составлен по текущим enum/registry исходникам и проверяется скриптом `docs/help/ru/anti-detection/_validate.py`. Скрипт должен подтверждать:

- 65/65 `EvidenceSource`;
- 85/85 `NativeSignalId`;
- 41/41 β-ID;
- заполненные колонки «без root» и «с root» у каждой строки;
- отсутствие битых внутренних Markdown-ссылок.

Скрипт намеренно не делает сетевых запросов и не сравнивает проект с внешним архивом. Неизменность файлов вне `docs` проверяется отдельно при сборке готового архива по хэшу дерева.

[Назад к оглавлению](../)
