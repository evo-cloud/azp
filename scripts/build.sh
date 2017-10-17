#!/bin/bash

TARGET_OS="$1"

case "$TARGET_OS" in
    darwin) TARGET_ARCH=amd64 ;;
    linux) TARGET_ARCH="$2" ;;
    *)
        echo "unsupported OS $TARGET_OS"
        exit 1
    ;;
esac

OUTDIR="bin/$TARGET_OS/$TARGET_ARCH"
mkdir -p "$OUTDIR"

GOOS=$TARGET_OS GOARCH=$TARGET_ARCH \
    exec go build -o "$OUTDIR/azp" ./cmd/azp
