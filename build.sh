#!/bin/sh
# Тесты и сборка exe под Windows.
set -e
cd "$(dirname "$0")"

echo ">> go vet (linux + windows)"
go vet ./...
GOOS=windows GOARCH=amd64 go vet ./...

echo ">> тесты с детектором гонок"
go test -race ./...

echo ">> сборка Gust.exe"
mkdir -p dist
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui -s -w" \
	-o dist/Gust.exe ./cmd/gust

if command -v cargo >/dev/null 2>&1; then
	echo ">> движок gust-engine (Rust)"
	(cd engine && cargo test -q && cargo build -q --release --target x86_64-pc-windows-gnu)
	cp engine/target/x86_64-pc-windows-gnu/release/gust-engine.exe dist/
fi

echo ">> готово: dist/"
