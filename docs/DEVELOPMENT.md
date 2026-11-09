# Gust — разработка

## Структура

```
cmd/gust/        точка входа: разбор флагов → app.Run
internal/app/          вся логика
  run.go               запуск: права, папка данных, веб-сервер, автозапуск
  app.go               состояние, настройки, журнал
  engine.go            управление процессом winws (запуск, watchdog, остановка)
  zapret.go            разбор .bat сборки, скачивание/распаковка, безопасность путей
  strategies.go        собственные стратегии GU-xx
  tuner.go             проверка доступности и автоподбор
  server.go            HTTP-API и выдача страницы
  tg.go                встроенный прокси Telegram: запуск, секрет, ссылка tg://proxy
  pages.go             открытые вкладки: повторный запуск обновляет страницу, а не открывает новую
  discord.go           вкладка Discord: свои проверки, переключение для голоса, перезапуск клиента
  ui.go                окно интерфейса: открыть/вывести вперёд, запасной путь через браузер
  ui.html              интерфейс (встраивается в exe)
internal/tgproxy/      MTProto-прокси для Telegram через WebSocket (перенос tg-ws-proxy)
  obfs.go              рукопожатие и перешифровка (AES-CTR)
  ws.go                минимальный WebSocket-клиент поверх TLS
  pool.go              пул готовых WS к дата-центрам
  splitter.go          нарезка потока на пакеты MTProto (кадр WS = пакет)
internal/platform/     всё, что зависит от Windows (права, процессы, WinDivert, автозапуск)
  gui_windows.go       окно WebView2 (процесс --window), значок в трее, вывод окна вперёд
  child.go             дочерний процесс-окно: жив ли, код выхода
```

Не-Windows сборка компилируется (platform-заглушки) — это нужно для тестов; в бою работает только Windows.

## Окно и трей

Интерфейс открывается во встроенном окне (WebView2, библиотека `go-webview2`), а не во вкладке браузера.
Окно — отдельный процесс: та же программа с ключом `--window` (служебный, руками не нужен). Если WebView2 упадёт —
обход не заденет. Закрыли окно — программа остаётся в трее (щелчок или «Открыть Gust» — открыть снова,
«Выход» — выйти и выключить обход). При автозапуске (`--background`) окна нет, только значок в трее.
Нет WebView2 на ПК или окно не запустилось — интерфейс открывается в браузере по умолчанию (запись в журнале).

Зависимости: `go-webview2` и `go-winloader` (MIT). `golang.org/x/sys` подменён зеркалом `github.com/golang/sys` (директива
`replace` в `go.mod`) — на случай, если `golang.org` недоступен при сборке. Контрольные суммы в `go.sum` сверены с sum.golang.org.

## Сборка и тесты

```sh
./build.sh            # тесты с -race + exe под Windows в dist/
```

Вручную:

```sh
go test -race ./...
# значок exe: cmd/gust/rsrc_windows_amd64.syso (из cmd/gust/gust.ico, утилита rsrc)
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui -s -w" -o dist/Gust.exe ./cmd/gust
```

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

Прокси Telegram — перенос на Go проекта tg-ws-proxy (Flowseal, MIT). Подробнее — `THIRD_PARTY_NOTICES.md`.

## Движок gust-engine (Rust)

`engine/` — собственный движок вместо `winws`, понимает опции `winws` в том объёме, в каком их используют
`general.bat` сборки и стратегии GU-xx (контрактный тест `TestStrategiesAcceptedByEngine` прогоняет их все через
`gust-engine --check`). Неподдерживаемая опция — ошибка запуска, а не тихий пропуск.

- перехват через WinDivert: `WinDivert.dll` из сборки zapret грузится динамически;
- TCP: склейка ClientHello из двух сегментов, повтор обработки при ретрансмиссии, каждый HTTP-запрос в keep-alive;
- режимы `fake`, `syndata`, `multisplit`, `multidisorder`, `fakedsplit`, `fakeddisorder`, `hostfakesplit`, `seqovl`, `wssize`;
- фейки: свой ClientHello (517 байт), моды `rnd`, `rndsni`, `dupsid`, `sni=`, `padencap`; HTTP, QUIC, Discord, STUN, unknown;
- fooling: `ttl`, `autottl` (хопы по входящему SYN-ACK), `md5sig`, `badseq`, `badsum`, `ts`, `datanoack`, `--ip-id=zero`;
  фейк без рабочего fooling не отправляется (иначе он дошёл бы до сервера);
- UDP: расшифровка QUIC Initial v1/v2 (RFC 9001/9369, проверено на эталонных векторах) ради SNI, склейка CRYPTO из
  двух датаграмм, Discord IP Discovery и STUN, `any-protocol` и `cutoff`, ipset (CIDR, IPv4/IPv6).

Gust вшивает движок в exe (`internal/app/enginebin`, go:embed), распаковывает в `C:\ProgramData\Gust\engine` и строит
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
