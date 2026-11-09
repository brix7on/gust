<a id="english"></a>

# Gust

**English** · [Русский](#russian)

DPI bypass for Discord, YouTube and other services on Windows. A single executable with a built-in interface: no installation, picks a working strategy automatically and keeps it working.

## Quick start

1. Download `Gust-…-windows-x64.zip` from [Releases](../../releases/latest).
2. Unpack it and run `Gust.exe`. Accept the administrator prompt: the WinDivert driver requires it.
3. Click **Download components**. Gust fetches the zapret build once and tunes a strategy on its own.

## How it works

1. **Bypass.** Traffic is processed by `winws` from [zapret](https://github.com/bol-van/zapret) with the [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) build. Gust tries the build's strategies plus its own `GU-xx` set and keeps the one under which the most services open.
2. **Monitoring.** Services are checked in the background. When access degrades, Gust re-tunes automatically.
3. **Telegram.** Telegram is restricted by IP, so `winws` can't help it. Gust runs a local MTProto proxy that tunnels traffic over WebSocket to Telegram's web endpoints. One click connects Telegram Desktop. Encryption is preserved.
4. **Discord.** Separate checks, switching strategies for voice, launching Discord outside a proxy-mode VPN, and restarting a stuck client.

Discord and YouTube are checked by default. Roblox, Instagram, Facebook, X, WhatsApp, Signal, Viber, Snapchat, LinkedIn, Twitch, SoundCloud, Patreon, Medium, Steam Community, RuTracker, NNM-Club, Tor Project, Proton and Telegram web can be enabled in the **More** tab: their domains are added to the bypass list automatically.

Gust ships its own packet engine written in Rust as an alternative to `winws`: choose it under **Settings → Bypass engine** (zapret / Gust / both). It runs the same strategies; it is experimental.

The interface is available in English and Russian. The language follows Windows and can be changed in Settings.

## Data and startup

Settings, the zapret build and the log are kept in `C:\ProgramData\Gust`, accessible only to administrators and SYSTEM. **Start with Windows** creates a scheduled task, so there is no elevation prompt at sign-in. Closing the window keeps Gust in the tray; **Quit** disables the bypass.

## Building from source

Requires Go 1.24+. Run `./build.sh`: tests with the race detector, then `dist/Gust.exe`. The Rust engine lives in `engine/` and is embedded into `Gust.exe` at build time. Releases are built by GitHub Actions on every `v*` tag. Details are in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Disclaimer

Some services are blocked by IP, and DPI bypass can't help those. Use the tool in accordance with the laws of your country. Provided as is, without warranty. License: MIT, third-party code: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

<a id="russian"></a>

# Gust

[English](#english) · **Русский**

Обход DPI-блокировок Discord, YouTube и других сервисов в Windows. Один исполняемый файл со встроенным интерфейсом: без установки, сам подбирает рабочую стратегию и следит, чтобы она не переставала работать.

## Быстрый старт

1. Скачайте `Gust-…-windows-x64.zip` из [Releases](../../releases/latest).
2. Распакуйте и запустите `Gust.exe`. Согласитесь на запрос прав администратора: они нужны драйверу WinDivert.
3. Нажмите **Загрузить компоненты**. Gust один раз скачает сборку zapret и сам подберёт стратегию.

## Как это работает

1. **Обход.** Трафик обрабатывает `winws` из [zapret](https://github.com/bol-van/zapret) со сборкой [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube). Gust перебирает стратегии сборки и собственный набор `GU-xx` и оставляет ту, при которой открывается больше всего сервисов.
2. **Контроль.** Сервисы проверяются в фоне. Если доступ пропадает, Gust подбирает стратегию заново.
3. **Telegram.** Telegram ограничен по IP, поэтому `winws` ему не помогает. Gust поднимает локальный MTProto-прокси, который ведёт трафик через WebSocket на веб-адреса Telegram. Telegram Desktop подключается одной кнопкой. Шифрование сохраняется.
4. **Discord.** Отдельные проверки, смена стратегии для голоса, запуск Discord в обход VPN в режиме прокси и перезапуск зависшего клиента.

По умолчанию проверяются Discord и YouTube. Roblox, Instagram, Facebook, X, WhatsApp, Signal, Viber, Snapchat, LinkedIn, Twitch, SoundCloud, Patreon, Medium, Steam Community, RuTracker, NNM-Club, Tor Project, Proton и сайт Telegram включаются во вкладке **Прочее**: их домены автоматически добавляются в список обхода.

В Gust встроен собственный движок на Rust как альтернатива `winws`: выбирается в **Настройки → Движок обхода** (zapret / Gust / оба). Запускает те же стратегии; пока экспериментальный.

Интерфейс доступен на русском и английском. Язык берётся из Windows и меняется в настройках.

## Данные и автозапуск

Настройки, сборка zapret и журнал хранятся в `C:\ProgramData\Gust`, доступ только у администраторов и SYSTEM. **Автозапуск с Windows** создаёт задачу планировщика, поэтому при входе запрос прав не появляется. Закрытое окно оставляет Gust в трее; **Выйти** отключает обход.

## Сборка из исходников

Нужен Go 1.24+. Команда `./build.sh`: тесты с детектором гонок, затем `dist/Gust.exe`. Движок на Rust — в папке `engine/`, при сборке вшивается в `Gust.exe`. Релизы собирает GitHub Actions на каждый тег `v*`. Подробности — в [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Отказ от ответственности

Часть сервисов заблокирована по IP, и обход DPI им не поможет. Используйте программу в соответствии с законами своей страны. Предоставляется «как есть», без гарантий. Лицензия: MIT, сторонний код: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
