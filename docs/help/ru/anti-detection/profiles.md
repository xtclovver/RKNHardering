---
title: Вторые пространства, рабочие профили, Private Space и клоны
permalink: /help/ru/anti-detection/profiles/
---

# Вторые пространства, рабочие профили, Private Space и клоны

Профиль хорошо разделяет данные и пакеты, но плохо подходит для полного сокрытия факта изоляции. Android реализует work profile как отдельного пользователя: UID вычисляется как `100000 * userId + appId`, данные лежат отдельно, а системные API знают текущий user/profile. RKNHardering проверяет это явно.

Официальные источники: [AOSP Work profiles](https://source.android.com/docs/devices/admin/managed-profiles) и [AOSP Private space](https://source.android.com/docs/security/features/private-space).

## Что различает RKNHardering

Стабильные native-сигналы:

- `ISOLATION_PROFILE` — общий профильный контекст;
- `ISOLATION_CLONE` — характерные clone-user диапазоны, включая MIUI-подобные ID;
- `ISOLATION_SECONDARY_USER` — любой `userId > 0`;
- `ISOLATION_WORK_PROFILE` — managed/profile owner признаки.

β-слой добавляет `beta.user_profile`, `beta.foreground_user`, sandbox process/filesystem/namespace identity и fscrypt identity. По отдельности они обычно review, но профиль плюс независимое сетевое расхождение может сформировать β-кворум.

## Без root

### Рабочий профиль: Shelter и Insular

[Shelter](https://gitea.angry.im/PeterCxy/Shelter) и [Insular](https://gitlab.com/secure-system/Insular) используют официальный managed profile. Они могут:

- установить отдельную копию RKNHardering или VPN-клиента;
- разделить app data и accounts;
- скрыть от приложения пакеты, установленные только в другом профиле;
- дать отдельные per-profile VPN настройки на поддерживаемых ROM.

Но сеть и ядро устройства остаются общими, а userId видим. Поэтому профиль полезен для конкретного package-visibility сценария, но не заменяет kernel/Binder hide.

Наиболее чистый сценарий без root: RKNHardering остаётся в основном пользователе, VPN вынесен на внешний роутер. Профиль тогда вообще не нужен и не создаёт isolation-сигнал.

Если RKNHardering запущен в work profile, а VPN только в owner profile, приложение может получить прямой путь и не видеть VPN-пакет. Цена — явный `userId > 0`, work-profile состояние и возможное расхождение сетевых политик. Рассматривайте это как эксперимент, не как гарантированный pass.

### Private Space Android 15+

Private Space — отдельный private profile. Когда пространство заблокировано, профиль остановлен и приложения скрыты; когда разблокировано, это обычная отдельная копия приложения в другом user context. Запустить проверку внутри заблокированного пространства невозможно, а после разблокировки профильная идентичность остаётся.

Private Space хорошо скрывает приложения от повседневного package enumeration, но не меняет TUN/system network модели автоматически. Если VPN работает в основном профиле на уровне всего устройства, приложение в Private Space может всё равно видеть общие сетевые признаки.

### OEM Dual Apps / Second Space

Xiaomi/MIUI, Samsung Dual Messenger, Huawei PrivateSpace и другие OEM-реализации используют разные user/profile модели. В текущем native-коде RKNHardering отдельно распознаются clone-диапазоны вроде user 999 и 950–959. Переименование ярлыка или package alias это не меняет.

### Проверка профиля

```bash
adb shell pm list users
adb shell am get-current-user
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell dumpsys user
```

`dumpsys user` может содержать личные сведения об аккаунтах/профилях; не публикуйте полный вывод без очистки. Для конкретного пользователя:

```bash
adb shell cmd package list packages --user 0 | grep com.notcvnt.rknhardering
```

Замените `0` на ID из `pm list users` только для чтения. Установка/удаление профиля может уничтожить его данные.

## С root

Root не делает профиль невидимым сам по себе. Он помогает правильно применить VPNHide к UID каждой копии приложения.

VPNHide upstream разрешает package names в UID через `packages.list`/`pm list packages -U`; современные версии должны учитывать user/appId. VPNHide Next заявляет полноценную поддержку рабочих профилей. После сохранения целей проверьте, что в kernel control list присутствует UID именно той копии RKNHardering, которую вы запускаете.

Пример чтения UID:

```bash
adb shell cmd package list packages -U --user 0 | grep com.notcvnt.rknhardering
adb shell cmd package list packages -U --user 10 | grep com.notcvnt.rknhardering
```

Не копируйте UID вручную между перезагрузками/переустановками без повторной проверки. AppId обычно стабилен, но profile/user часть отличается.

Если framework-хук использует только appId, он может примениться ко всем профилям; если backend использует полный UID, каждую копию нужно добавить отдельно. Сверяйтесь с README конкретной версии и её диагностикой.

Root-hiding модуль также должен выполнять unmount для UID/profile копии, а не только для owner instance. Иначе основное приложение выглядит чисто, а work-profile копия видит `/data/adb`/mount следы.

## Практические сценарии

### Сценарий 1: чистый non-root

- RKNHardering в owner user.
- VPN на внешнем роутере.
- На телефоне нет VPN-приложения, системного proxy и local controller.

Это минимизирует локальные и isolation признаки. Остаются server-side GeoIP/CDN/DNS/RTT.

### Сценарий 2: разделение пакетов без root

- VPN-клиент только в work profile.
- RKNHardering только в owner user.
- Проверить, применяет ли ROM VPN только к профилю или ко всему устройству.

Может убрать package visibility и локальный VpnService из owner context, но поведение OEM различается. Снимите `dumpsys connectivity` в обоих профилях и проверьте egress.

### Сценарий 3: RKNHardering в профиле

- RKNHardering в work/private/secondary profile.
- VPN в owner или на роутере.

Профиль сам становится сигналом. Применимо только для исследования чувствительности `ISOLATION_*` и β-кворума.

### Сценарий 4: root + VPNHide для нескольких пользователей

- Цель добавлена в VPNHide для каждой копии.
- Framework scope только `System Framework`.
- Kernel backend фильтрует полные UID.
- Ports/App роли проверены отдельно.

Это покрывает локальную сеть, но `ISOLATION_*` остаётся правдивым. Не пытайтесь ломать `UserManager` глобально: это может нарушить launcher, package manager и политики устройства.

## Риски и откат

Удаление work profile/Private Space стирает приложения, ключи, аккаунты и локальные файлы внутри профиля. Перед удалением экспортируйте нужные данные через штатные механизмы. Shelter/Insular имеют собственные инструкции teardown — следуйте им, а не удаляйте DPC принудительно.

Не создавайте/удаляйте системных пользователей командами `pm create-user`/`pm remove-user` на основном устройстве без резервной копии. В этой инструкции команды ограничены чтением состояния.

[Назад к оглавлению](../)
