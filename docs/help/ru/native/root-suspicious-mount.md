---
title: "Mount-строки с Magisk/core-only и root-маркерами"
permalink: /help/ru/native/root-suspicious-mount/
---

# Mount-строки с Magisk/core-only и root-маркерами

> **ID:** `ROOT_SUSPICIOUS_MOUNT`
> **Категория:** Root и состояние системы
> **Статус в RKNHardering 2.10.0:** Активная проверка
> **Роль в вердикте:** Средняя

Эта страница описывает фактическую реализацию RKNHardering 2.10.0. Здесь отдельно указано, что можно сделать без root, что требует root, а также где способ только уменьшает один сигнал, но не скрывает VPN целиком.

## Что проверяется и зачем

C++ читает `/proc/self/mounts` и формирует `suspicious_mount`, если строка содержит `magisk` или `core-only`. Kotlin дополнительно оценивает detail по marker `magisk`, `zygisk`, `lsposed`, `riru`, `kernelsu`, `apatch`, `/data/adb`, `core-only`: при совпадении confidence high, иначе medium.

### Точное условие срабатывания

В mount namespace процесса видна строка с фиксированным C++ marker. В текущем producer фактически это `magisk` или `core-only`.

## Что означает результат

Сильный признак systemless/root mount. Важно, что проверяется namespace самого приложения, поэтому глобальный `mount` из shell может не совпасть.

**Как строка влияет на отчёт:** Строка не даёт самостоятельный окончательный вердикт, но выставляет `needsReview=true` и добавляет доказательство средней уверенности.

## Ограничения и возможные ложные срабатывания

KernelSU/APatch без слова magisk могут не попасть в C++ producer, хотя Kotlin готов распознать их в detail. Bind mount легитимного sandbox также может выглядеть необычно.

Важно оценивать эту строку вместе с соседними сигналами. Один чистый API не перекрывает Java Binder, libc, raw netlink/syscall, procfs/sysfs, локальные сокеты и серверные признаки одновременно.

## Рекомендации для этого вектора

### Без root

Если root не нужен, надёжное исправление — вернуть устройство к штатному состоянию официальным способом: удалить root через его менеджер либо прошить заводские boot/init_boot и системные разделы именно от установленной сборки. Разблокированный загрузчик, кастомное ядро и оставшиеся каталоги могут продолжить выдавать модификацию даже после удаления менеджера. Перед восстановлением сделайте резервную копию; повторная блокировка загрузчика на изменённой прошивке способна привести к потере данных или неработоспособности устройства.

### С root

С root можно лишь уменьшать наблюдаемую поверхность, а не доказать отсутствие root. Ограничьте выдачу `su` минимальным числом приложений, не давайте её RKNHardering, отключите ненужные модули и не переводите SELinux в permissive. App Profile/DenyList и mount-изоляция проверяются на конкретной прошивке. SUSFS и сходные решения относятся к экспериментальным: они требуют совместимого ядра и могут сами добавлять следы. Для эталонного теста всё равно нужен отдельный стоковый телефон. Проверяйте, что App Profile/mount isolation действительно применена до старта процесса. После изменения нужен force-stop, а иногда reboot.

### Как проверить результат

```bash
adb shell cat /proc/self/mounts | grep -Ei 'magisk|core-only|zygisk|lsposed|riru|kernelsu|apatch|/data/adb'
```
Это mounts процесса shell. Для точного app namespace используйте встроенный detail или debuggable `run-as`.

После любого изменения сделайте `force-stop` RKNHardering и VPN-клиента, запустите их заново и повторите полный scan. Для Zygisk/Xposed/kernel-модулей обычно нужна перезагрузка. Сравнивайте не только эту строку, но и соседние сигналы: частичный hook часто создаёт несогласованность между API.

## Необходимые права и риски

Сама проба выполняется с обычными правами приложения и не запрашивает root. ADB-команды ниже служат только для ориентира: `adb shell` работает под другим UID и может видеть больше или меньше, чем процесс приложения. Решающий тест — повторный запуск самой проверки после `force-stop`.

### Риски

Ручной `umount` mount points root manager может повесить процессы или сломать систему. Не применяйте lazy unmount вслепую.

### Откат

Верните последнее изменение: отключите добавленный модуль или правило через штатный менеджер, перезагрузите устройство и повторите baseline. Не накладывайте новый hook поверх неизвестного состояния.

## Уровень доказательности

**Средняя.** Проверено по чтению `/proc/self/mounts` и двум уровням marker-логики.

Статус стороннего решения не переносится автоматически на это устройство. Заявление разработчика модуля — это исходная гипотеза; подтверждением служит повторяемый результат RKNHardering на конкретной версии Android, прошивки и ядра.

## Источники и дата последней проверки

- Проверено по коду проекта: [`native_signs_probe.cpp` — нативная реализация проб](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Проверено по коду проекта: [`NativeSignsChecker.kt` — основной native/legacy verdict](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Проверено по коду проекта: [`NativeSignalId.kt` — полный реестр ID](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Проверено по коду проекта: [`NativeSignalCatalog.kt` — категория, slug и mapping строк](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Внешняя первичная документация или официальный проект: [/proc/pid/mounts namespaces](https://man7.org/linux/man-pages/man5/proc_pid_mounts.5.html).
- Внешняя первичная документация или официальный проект: [mount namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html).
- Последняя сверка реализации и ссылок: **19 июля 2026 года**.

Связанные сигналы: `root-overlay-mount`, `root-management`, `hook-markers`.

[К справочнику Native signs](../)
