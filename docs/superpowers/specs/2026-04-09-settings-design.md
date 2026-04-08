# Экран настроек RKN Hardering

## Обзор

Добавить экран настроек (SettingsActivity) с навигацией через иконку шестерёнки в Material 3 TopAppBar на главном экране. Все элементы стилизованы в единой серой палитре приложения.

## Изменения главного экрана (MainActivity)

- Заменить текущий заголовок/подзаголовок на Material 3 TopAppBar.
- Заголовок "RKN Hardering" в TopAppBar.
- Подзаголовок "Самопроверка на обнаружение VPN/Proxy" под TopAppBar (или как subtitle).
- Иконка шестерёнки справа в TopAppBar — навигация в SettingsActivity.
- Удалить кнопку GitHub и кнопку "Разрешения" с главного экрана (перенесены в настройки).

## SettingsActivity

### Архитектура

- Отдельная Activity с Toolbar и ручной вёрсткой.
- Кнопка "назад" в Toolbar для возврата на MainActivity.
- SharedPreferences (`rknhardering_prefs`) для хранения всех настроек.
- При возврате на MainActivity настройки читаются и применяются к текущей сессии.

### Секции и элементы

#### 1. Проверки

**Split tunnel bypass** (MaterialSwitch)
- Ключ: `pref_split_tunnel_enabled`, по умолчанию `true`.
- Описание: "Сканирование портов занимает много времени".
- При отключении: BypassChecker полностью пропускается в VpnCheckRunner.
- Карточка Bypass на главном экране не отображается если отключено.

**Диапазон портов** (Chip group)
- Ключ: `pref_port_range`, значения: `popular`, `extended`, `full`, `custom`.
- По умолчанию: `full` (текущее поведение).
- Пресеты:
  - **Популярные**: только популярные порты (1080, 2080, 1081, 10808, 10809, 12334, 7890). Без полного сканирования.
  - **Расширенный**: популярные + диапазон 1024-15000.
  - **Полный**: 1024-65535 (текущее поведение).
  - **Кастомный**: два поля ввода "От" и "До". Ключи `pref_port_range_start`, `pref_port_range_end`.
- При выборе "Кастомный" появляются поля ввода под чипами.
- Валидация: min 1024, max 65535, start <= end.
- Когда Split tunnel отключён — секция видима, но задизейблена (alpha 0.5, некликабельна).

**Сетевые запросы** (MaterialSwitch)
- Ключ: `pref_network_requests_enabled`, по умолчанию `true`.
- Описание: "GeoIP, IP сравнение, BeaconDB".
- При отключении — диалог подтверждения с перечнем последствий:
  - "GeoIP проверка не будет выполнена"
  - "Сравнение IP-адресов через внешние сервисы отключится"
  - "Геолокация через BeaconDB (вышки/Wi-Fi) отключится"
  - "Будут работать только локальные проверки: прямые признаки, косвенные признаки, сканирование портов"
- Кнопки диалога: "Отключить" / "Отмена".
- При отключении: GeoIpChecker, IpComparisonChecker пропускаются. LocationSignalsChecker работает без BeaconDB запроса (только MCC из TelephonyManager). Карточки GeoIP и IP Comparison не отображаются.

#### 2. Приватность

**Приватный режим** (MaterialSwitch)
- Ключ: `pref_privacy_mode`, по умолчанию `false`.
- Описание: "IP отображается как 185.22.\*.\*".
- Маскировка только на уровне UI (отображение в карточках результатов).
- Внутренняя логика сравнения IP работает с полными адресами.
- Маскируются последние 2 октета IPv4 (например `185.22.*.*`).
- Для IPv6: маскируются последние 4 группы (например `2001:db8:*:*:*:*:*:*`).
- Применяется ко всем местам в UI где отображается IP: карточка GeoIP (поле IP), карточка IP Comparison (все IP-адреса), карточка Bypass (IP через прокси).

#### 3. Оформление

**Тема** (Chip group, single selection)
- Ключ: `pref_theme`, значения: `light`, `dark`, `system`.
- По умолчанию: `system`.
- Применяется немедленно через `AppCompatDelegate.setDefaultNightMode()`:
  - `light` → `MODE_NIGHT_NO`
  - `dark` → `MODE_NIGHT_YES`
  - `system` → `MODE_NIGHT_FOLLOW_SYSTEM`
- Тема применяется также при запуске приложения в `Application.onCreate()` или `MainActivity.onCreate()` до `setContentView`.

#### 4. О приложении

**Разрешения** (кликабельный элемент)
- Стрелка вправо.
- По нажатию: вызывает текущую логику запроса разрешений из MainActivity (перенести в общий utility).
- Описание: "Управление разрешениями приложения".

**GitHub** (кликабельный элемент)
- Стрелка "внешняя ссылка".
- По нажатию: открывает `https://github.com/xtclovver/RKNHardering` в браузере.
- Подпись: "xtclovver/RKNHardering".

## Стилизация

- Фоновый цвет экрана: `md_surface` (серая палитра приложения).
- Карточки настроек: `md_surface_container` с `md_outline_variant` border.
- Текст: `?android:attr/textColorPrimary` для заголовков, `?android:attr/textColorSecondary` для описаний.
- Заголовки секций: `md_primary` цвет, uppercase, letter-spacing.
- MaterialSwitch: стандартная Material 3 стилизация (`?attr/colorPrimary` для active state).
- Chip group: Material 3 FilterChip или аналог с `md_primary` для selected state.
- Все элементы поддерживают light/dark mode через текущую систему тем.
- TopAppBar на MainActivity: `TopAppBarDefaults.topAppBarColors()` с текущей палитрой.
- Toolbar на SettingsActivity: аналогичная стилизация, кнопка "назад" как navigationIcon.

## Хранение настроек

Единый файл SharedPreferences `rknhardering_prefs` (уже используется для permission tracking).

| Ключ | Тип | По умолчанию |
|------|-----|-------------|
| `pref_split_tunnel_enabled` | Boolean | true |
| `pref_port_range` | String | "full" |
| `pref_port_range_start` | Int | 1024 |
| `pref_port_range_end` | Int | 65535 |
| `pref_network_requests_enabled` | Boolean | true |
| `pref_privacy_mode` | Boolean | false |
| `pref_theme` | String | "system" |

## Интеграция с логикой проверок

### VpnCheckRunner

Читает настройки перед запуском:
- Если `pref_split_tunnel_enabled == false`: не запускать BypassChecker.
- Если `pref_network_requests_enabled == false`: не запускать GeoIpChecker, IpComparisonChecker. LocationSignalsChecker работает без BeaconDB.

### BypassChecker

Читает `pref_port_range` и определяет набор портов:
- `popular`: только список POPULAR_PORTS, без полного скана.
- `extended`: POPULAR_PORTS + range 1024-15000.
- `full`: текущее поведение (POPULAR_PORTS + 1024-65535).
- `custom`: POPULAR_PORTS + range (pref_port_range_start..pref_port_range_end).

### MainActivity (отображение)

- Если `pref_privacy_mode == true`: все IP-адреса в UI маскируются утилитой `maskIp(ip: String): String`.
- Скрытые карточки: если чекер не запускался из-за настроек, его карточка не показывается (аналогично текущему поведению — карточки initially hidden).

## Утилита maskIp

```
fun maskIp(ip: String): String
```

- IPv4 `a.b.c.d` → `a.b.*.*`
- IPv6 `a:b:c:d:e:f:g:h` → `a:b:c:d:*:*:*:*`
- Если формат не распознан — вернуть `*.*.*.*`.

## Файлы для создания

- `app/src/main/java/com/notcvnt/rknhardering/SettingsActivity.kt`
- `app/src/main/res/layout/activity_settings.xml`
- `app/src/main/res/drawable/ic_settings.xml` (иконка шестерёнки, 24dp)

## Файлы для изменения

- `app/src/main/java/com/notcvnt/rknhardering/MainActivity.kt` — TopAppBar, удаление GitHub/Permissions кнопок, чтение настроек, maskIp, скрытие карточек
- `app/src/main/res/layout/activity_main.xml` — TopAppBar вместо текущего header, удаление кнопок GitHub и Permissions
- `app/src/main/java/com/notcvnt/rknhardering/VpnCheckRunner.kt` — условный запуск чекеров
- `app/src/main/java/com/notcvnt/rknhardering/checker/BypassChecker.kt` — чтение настройки портов
- `app/src/main/AndroidManifest.xml` — регистрация SettingsActivity
- `app/src/main/res/values/strings.xml` — новые строки
