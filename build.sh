#!/bin/sh
# Тесты и сборка exe под Windows: сначала движок (Rust), он вшивается в Gust.exe.
set -e
cd "$(dirname "$0")"
mkdir -p dist
rm -f internal/app/enginebin/gust-engine.exe

if command -v cargo >/dev/null 2>&1; then
	echo ">> движок gust-engine (Rust): тесты и сборка"
	(cd engine && cargo test -q && cargo build -q && cargo build -q --release --target x86_64-pc-windows-gnu)
	cp engine/target/x86_64-pc-windows-gnu/release/gust-engine.exe internal/app/enginebin/
	cp engine/target/x86_64-pc-windows-gnu/release/gust-engine.exe dist/
	check="$PWD/engine/target/debug/gust-engine"
else
	echo ">> cargo не найден: Gust соберётся без собственного движка"
	check=""
fi

echo ">> go vet (linux + windows)"
go vet ./...
GOOS=windows GOARCH=amd64 go vet ./...

echo ">> тесты с детектором гонок"
GUST_ENGINE_CHECK="$check" go test -race ./...

echo ">> сборка Gust.exe"
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui -s -w" \
	-o dist/Gust.exe ./cmd/gust
rm -f internal/app/enginebin/gust-engine.exe

echo ">> готово: dist/"
