# Сторонний код

## tg-ws-proxy

`engine/src/tg` — перенос на Rust логики проекта [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)
(обфускация MTProto, перешифровка, пул WebSocket, запасной путь через TCP).

```
MIT License

Copyright (c) 2026 Flowseal

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## zapret / zapret-discord-youtube

Gust не содержит их кода: сборка [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)
(движок [zapret](https://github.com/bol-van/zapret)) скачивается отдельно, при первом запуске.

## wry, tao, WebView2

Окно интерфейса (`window/`) построено на [wry](https://github.com/tauri-apps/wry) и [tao](https://github.com/tauri-apps/tao)
(MIT / Apache-2.0). В `Gust.exe` вшит `WebView2Loader.dll` — Microsoft Edge WebView2 Loader (BSD-3-Clause, входит в крейт
`webview2-com-sys`). Сам WebView2 Runtime устанавливается в Windows отдельно.
