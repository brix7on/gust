# Gust — разработка

## Структура

```
app/             Gust.exe (Rust): вся логика, без async, потоки и свой HTTP/1.1-сервер
  src/main.rs          запуск: флаги, права, папка данных, веб-сервер, автозапуск, трей
  src/state.rs         состояние, настройки, журнал; settings.rs — поля настроек
  src/engine.rs        процесс winws/gust-engine (запуск, watchdog, остановка), распаковка вшитых файлов
  src/zapret.rs        разбор .bat сборки, скачивание/распаковка, безопасность путей
  src/strategies.rs    собственные стратегии GU-xx и удалённый strategies.json
  src/tuner.rs         проверка доступности и автоподбор
  src/server.rs        HTTP-API и выдача страницы; http.rs — разбор запросов, SSE
  src/tg.rs            прокси Telegram: процесс gust-tg.exe tgproxy, секрет, ссылка tg://proxy, счётчики
  src/pages.rs         открытые вкладки: повторный запуск обновляет страницу
  src/discord.rs       вкладка Discord: свои проверки, переключение для голоса, перезапуск клиента
  src/update.rs        самообновление с GitHub Releases (проверка SHA256SUMS)
  src/ui.rs            открыть окно или запасной путь через браузер; ui.html — интерфейс (вшит в exe)
  src/platform/        всё, что зависит от Windows (win.rs: права, процессы, трей, автозапуск); other.rs — заглушки для тестов
  src/tests.rs         тесты API и логики (Linux, поддельное дерево zapret)
window/          gust-window.exe: окно WebView2 (wry + tao), отдельный процесс
engine/          gust-engine.exe: собственный движок обхода и прокси Telegram
```

Не-Windows сборка компилируется (platform-заглушки) — это нужно для тестов; в бою работает только Windows.

## Окно и трей

Интерфейс открывается во встроенном окне WebView2. Окно — отдельный процесс `gust-window.exe`
(`--window URL --wdata DIR --parent PID`): `wry` на windows-gnu жёстко импортирует `WebView2Loader.dll`,
а `Gust.exe` обязан запускаться без неё. Поэтому и окно, и загрузчик вшиты в `Gust.exe` и распаковываются
в `C:\ProgramData\Gust\engine`. Код выхода 3 — нет WebView2, 4 — окно не создалось: тогда интерфейс открывается в браузере.
Закрыли окно — программа остаётся в трее («Открыть Gust» — открыть снова, «Выход» — выйти и выключить обход).
При автозапуске (`--background`) окна нет, только значок в трее. Окно закрывается само, если закрылась основная программа.

Иконка и манифест — `gust.ico`, `gust.manifest`, `gust.rc` (встраивает `embed-resource` в `build.rs`).

## Сборка и тесты

```sh
./build.sh            # тесты + dist/Gust.exe и dist/gust-engine.exe (нужны cargo и x86_64-w64-mingw32-gcc)
```

Порядок: движок → окно → копия `gust-engine.exe`, `gust-window.exe`, `WebView2Loader.dll` в `app/enginebin/` →
тесты и сборка `Gust.exe`. Версия берётся из `Cargo.toml`, либо из переменной `GUST_VERSION` (так делает CI по тегу).
Тесты приложения идут на Linux; для проверки стратегий нужен `GUST_ENGINE_CHECK=<путь к gust-engine>`.

## Безопасность

- Папка данных (`C:\ProgramData\Gust`) закрывается ACL только для админов и SYSTEM —
  из неё запускаются exe с повышенными правами, обычный пользователь не подменит файл и не подложит DLL.
- Запускается только `winws.exe` из папки сборки; подменённый `.bat` с чужим exe отклоняется.
- Локальный API защищён токеном (сверка в постоянное время) и проверкой заголовка Host (против DNS-rebinding).
- Скачивание — только с github.com и его CDN; распаковка защищена от zip-slip и zip-бомбы.

### Известные ограничения

- Окно интерфейса (процесс-потомок) наследует права администратора — как и сама программа (UAC-перезапуск под WinDivert).
  Показывает оно только `http://127.0.0.1:…` (другой адрес отклоняется), внешние ссылки открываются в браузере по умолчанию
  и только если это `https`.
- Голос Discord (UDP) автоматически не проверяется — только сайты и API.
- Telegram через `winws` не обходится (блокировка по IP) — для него встроенный прокси:
  Telegram Desktop → 127.0.0.1:1443 (MTProto, dd-секрет) → WebSocket `kwsN.web.telegram.org/apiws`
  на 149.154.167.220 → запасной путь — прямой TCP.
  Без HTTP/2-канала для медиа, который есть в оригинале.

## Сторонний код

Прокси Telegram — перенос на Rust проекта tg-ws-proxy (Flowseal, MIT). Подробнее — `THIRD_PARTY_NOTICES.md`.

## Движок gust-engine (Rust)

`engine/` — собственный движок вместо `winws`, понимает опции `winws` в том объёме, в каком их используют
`general.bat` сборки и стратегии GU-xx (контрактный тест `strategies_accepted_by_engine` прогоняет их все через
`gust-engine --check`). Неподдерживаемая опция — ошибка запуска, а не тихий пропуск.

- перехват через WinDivert: `WinDivert.dll` из сборки zapret грузится динамически;
- TCP: склейка ClientHello из двух сегментов, повтор обработки при ретрансмиссии, каждый HTTP-запрос в keep-alive;
- режимы `fake`, `syndata`, `multisplit`, `multidisorder`, `fakedsplit`, `fakeddisorder`, `hostfakesplit`, `seqovl`, `wssize`;
- фейки: свой ClientHello (517 байт), моды `rnd`, `rndsni`, `dupsid`, `sni=`, `padencap`; HTTP, QUIC, Discord, STUN, unknown;
- fooling: `ttl`, `autottl` (хопы по входящему SYN-ACK), `md5sig`, `badseq`, `badsum`, `ts`, `datanoack`, `--ip-id=zero`;
  фейк без рабочего fooling не отправляется (иначе он дошёл бы до сервера);
- UDP: расшифровка QUIC Initial v1/v2 (RFC 9001/9369, проверено на эталонных векторах) ради SNI, склейка CRYPTO из
  двух датаграмм, Discord IP Discovery и STUN, `any-protocol` и `cutoff`, ipset (CIDR, IPv4/IPv6).

Тот же бинарник умеет работать прокси Telegram: `gust-engine tgproxy --port 1443 --secret HEX --pool 4`
(`engine/src/tg`: obfs — рукопожатие и AES-CTR, splitter — нарезка потока на пакеты, ws — WebSocket поверх TLS на rustls,
pool — пул готовых соединений, mod — приёмник, мост и запасной TCP). Строки вывода: `ready`, `error: …`, `log: …`,
`stats: {json}`; закрылся stdin — процесс завершается. Совместимость шифрования с эталоном закреплена
тестом `matches_go_vector` (`engine/src/tg/vector.json`). Gust запускает его из копии `gust-tg.exe`, чтобы остановка
`gust-engine.exe` не трогала прокси.

Gust вшивает движок в exe (`app/enginebin`, `include_bytes!`), распаковывает в `C:\ProgramData\Gust\engine` и строит
для каждой стратегии двойника «Gust · имя». Настройка «Движок обхода»: zapret / Gust / оба.

```sh
cd engine
cargo test
cargo build --release --target x86_64-pc-windows-gnu   # нужен x86_64-w64-mingw32-gcc
gust-engine --check <аргументы>                        # проверить аргументы без запуска
```

## Релизы

`.github/workflows/release.yml`: на каждый push в `main` и pull request — тесты и сборка (архивы во вкладке Actions),
на тег `v*` — то же плюс релиз с `Gust-<версия>-windows-x64.zip` и `gust-engine-<версия>-windows-x64.zip`.

```sh
git tag v0.6.5 && git push origin v0.6.5
```
