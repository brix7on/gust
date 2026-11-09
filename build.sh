#!/bin/sh
# Тесты и сборка Gust.exe под Windows: движок и окно собираются первыми, их вшивает основной exe.
set -e
cd "$(dirname "$0")"
T=x86_64-pc-windows-gnu
mkdir -p dist app/enginebin
rm -f app/enginebin/*

echo ">> движок gust-engine: тесты и сборка"
(cd engine && cargo test -q --locked && cargo build -q --locked && cargo build -q --release --locked --target $T)

echo ">> окно gust-window: сборка"
(cd window && cargo build -q --release --locked --target $T)
loader=$(ls "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/webview2-com-sys-*/x64/WebView2Loader.dll | tail -n1)

cp engine/target/$T/release/gust-engine.exe window/target/$T/release/gust-window.exe app/enginebin/
cp "$loader" app/enginebin/WebView2Loader.dll
cp engine/target/$T/release/gust-engine.exe dist/

echo ">> Gust: тесты"
(cd app && GUST_ENGINE_CHECK="$PWD/../engine/target/debug/gust-engine" cargo test -q --locked)

echo ">> Gust.exe: сборка"
(cd app && ${GUST_VERSION:+env GUST_VERSION=$GUST_VERSION} cargo build -q --release --locked --target $T)
cp app/target/$T/release/Gust.exe dist/

echo ">> готово: dist/"
