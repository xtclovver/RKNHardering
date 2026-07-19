---
title: Сетевой путь — GeoIP, DNS, CDN, STUN и звонки
permalink: /help/ru/anti-detection/network-path/
---

# Сетевой путь — GeoIP, DNS, CDN, STUN и звонки

Этот раздел нужен даже при идеальном VPNHide. Kernel- и framework-хуки меняют локальные ответы Android, но удалённые серверы продолжают видеть реальный адрес, ASN, задержку и доступность транспорта.

## Что проверяет RKNHardering

Проверено проектом: сетевой слой включает `GEO_IP`, IP-консенсус между RU/non-RU сервисами, DNS-сопоставление, `CdnPullingChecker`, STUN и транспорт звонков Telegram/WhatsApp, underlying-network probes, RTT-триангуляцию, ICMP spoofing и доменную доступность. Часть результатов диагностическая, но расхождение независимых каналов может участвовать в итоговом `DETECTED`.

Ключевые признаки:

- иностранная страна, hosting/datacenter или proxy/VPN по GeoIP;
- разные канонические IP у RU и non-RU групп;
- разные IPv4/IPv6 пути;
- DNS разрешает адреса иначе на VPN и underlying network;
- CDN/redirector видит другой канал;
- STUN раскрывает отдельный UDP egress;
- приложение находится физически в России, а сетевой выход выглядит иностранным, либо наоборот;
- соединение, привязанное к underlying network, даёт другой адрес;
- локальный proxy возвращает иной внешний IP, чем прямой путь.

## Без root

### Вариант A: внешний роутер или отдельный шлюз

Это наиболее чистый non-root сценарий. VPN/прокси работает на роутере, а телефон подключён к обычной Wi‑Fi сети. Локальных `VpnService`/TUN артефактов на Android нет. Для RKNHardering остаётся только внешний сетевой путь, поэтому его нужно сделать непротиворечивым.

Сообщено сообществом: проект [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense) предлагает сценарии для роутера и отдельно предупреждает, что один роутерный TUN не решает CDN pulling. Их готовые материалы: [Sub-Store](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md) и [S-UI](https://github.com/jinndi/RKNHardering-defense/blob/main/S-UI.md). Используйте их как пример маршрутизации, а не как доказательство прохождения текущей версии приложения.

Практически проверьте три вещи: HTTP(S), DNS и UDP должны выходить через один ожидаемый канал; IPv6 либо настроен так же, либо осознанно отключён в конкретном лабораторном профиле; телефон не должен иметь запасной мобильный путь, который внезапно становится underlying network.

### Вариант B: per-app split tunneling

Android официально поддерживает allow/disallow списки через `VpnService.Builder.addAllowedApplication()` и `addDisallowedApplication()`. В sing-box для Android это можно настроить через интерфейс **Параметры → Перезапись профиля → Прокси для отдельных приложений**. Документация правил: [sing-box route rule](https://sing-box.sagernet.org/configuration/route/rule/).

Минимальная идея для актуального синтаксиса sing-box выглядит так:

```json
{
  "route": {
    "rules": [
      {
        "package_name": ["com.notcvnt.rknhardering"],
        "action": "route",
        "outbound": "direct"
      }
    ]
  }
}
```

Это не готовый полный конфиг: тег `direct`, DNS-правила и версия схемы должны совпадать с вашей установкой. Перед заменой рабочего профиля проверьте конфигурацию встроенной проверкой клиента и сохраните копию.

**Ограничение:** текущий `TUN_ACTIVE_PROBE` специально замечает ситуацию, когда TUN существует, а `vpnActive` для RKNHardering ложен. Поэтому per-app bypass может убрать иностранный IP, но одновременно подтвердить явное исключение пакета. Для чистого non-root результата его обычно сочетают не с локальным `VpnService`, а с внешним шлюзом.

### DNS должен следовать тому же пути

Не оставляйте схему «HTTP direct, DNS через VPN» или наоборот. RKNHardering сравнивает путь разрешения и сетевые результаты. Для исключённого приложения используйте DNS underlying-сети либо отдельный resolver, который идёт тем же outbound. Не выставляйте системный HTTP proxy ради DNS-маршрутизации: он создаёт отдельный `SYSTEM_PROXY` сигнал.

В конфигурациях sing-box правило DNS следует отделять от правила трафика, но оба должны приводить к одному ожидаемому каналу. Большой пример сообщества есть в [SUB-STORE.md](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md); не копируйте его целиком без проверки своих тегов, rule-set и доверенных пакетов.

### STUN, звонки и UDP

TCP-only proxy часто выглядит чисто по HTTP, но UDP/STUN уходит напрямую. Исправление выбирается по задаче:

- если приложению нужен direct-путь, direct должны быть и HTTP, и DNS, и UDP;
- если нужен единый proxy/VPN egress, клиент должен реально поддерживать UDP, а не молча делать fallback;
- блокировка STUN убирает ответ, но отсутствие ответа не всегда равно чистому результату: RKNHardering умеет показывать `unsupported`, `no signal` и review;
- блокировка звонковых endpoint может сломать Telegram/WhatsApp. Делайте это только в тестовом профиле и с понятным откатом.

### Геолокация и роуминг

Не подделывайте GPS как основную стратегию. Проверка использует MCC/MNC, SIM, cell/Wi‑Fi и серверные данные; несогласованная подмена создаёт больше противоречий. Нормальная конфигурация должна объяснять наблюдаемую пару «местоположение — egress». Домашний роуминг может быть легитимным, и код хранит отдельный `HOME_ROUTED_ROAMING` контекст.

## С root

Root не заменяет описанные выше действия. Он позволяет скрыть локальный факт VPN после того, как сетевой путь уже приведён в порядок.

Рабочая последовательность:

1. Настройте package routing в VPN-клиенте или на шлюзе.
2. Добейтесь одинакового ожидаемого HTTP/DNS/UDP egress.
3. Закройте Binder/native признаки через VPNHide или VPNHide Next.
4. Запретите целевому UID доступ к localhost control API.
5. Проверьте, что root/hook след не стал новым основанием для review.

Если RKNHardering должен идти напрямую, kernel/framework hide нужен именно потому, что локальный TUN продолжает существовать. Если RKNHardering должен идти внутри туннеля, учтите архитектурное ограничение VPNHide upstream: подмена активной VPN-сети физической наиболее логична при split tunnel. Проект прямо отмечает server-side сигналы как находящиеся вне области локального сокрытия. Подробности: [VPNHide detection vectors](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).

Для localhost лучше всего не поднимать API вообще. Если он нужен другим приложениям, VPNHide `portshide` или kernel-блокировка VPNHide Next должны применяться к UID RKNHardering. Пароль на Clash API полезен для безопасности, но не скрывает открытый порт и сам факт протокола; RKNHardering сканирует loopback и известные REST endpoints.

## Настройка control plane

Mihomo/Clash `external-controller` и sing-box/Xray API не должны слушать `0.0.0.0` без необходимости. Для лабораторного телефона безопаснее:

- отключить controller/API;
- либо привязать его к Unix socket, если клиент и панель поддерживают это;
- либо оставить loopback с сильным secret и дополнительно закрыть доступ целевому UID на уровне root;
- не использовать типовые порты `9090`, `9091`, `9097`, `19090` как единственную «защиту»: смена порта не мешает полному сканированию.

Официальная документация Mihomo: [general configuration](https://wiki.metacubex.one/en/config/general/). Официальная документация sing-box: [configuration](https://sing-box.sagernet.org/configuration/).

## Проверка результата

Сначала снимите сетевую контрольную точку без root-команд:

```bash
adb shell dumpsys connectivity
adb shell ip addr
adb shell ip route
adb shell ip rule
adb shell settings get global http_proxy
adb shell pm list users
```

На Android часть `/proc` может быть закрыта SELinux; `permission denied` означает недостаточные права, а не отсутствие маршрута или сокета. Не превращайте SELinux в permissive ради диагностики — это ухудшает безопасность и создаёт прямой `ROOT_SELINUX` сигнал.

После изменения:

```bash
adb shell am force-stop com.notcvnt.rknhardering
adb shell monkey -p com.notcvnt.rknhardering 1
```

Запустите не менее двух проверок в одной сети. Затем отдельно повторите после переключения Wi‑Fi/мобильной сети: изменение network epoch должно объяснять изменение результатов, а не маскироваться как «случайный успех».

## Остаточные сигналы

Даже при правильном внешнем IP могут остаться hosting/proxy базы, ASN датацентра, RTT, CDN и server fingerprint. Даже при внешнем роутере RKNHardering может обоснованно видеть иностранный выход. И наоборот, локальный hide не исправит split-DNS и утечку IPv6.

[Назад к оглавлению](../)
