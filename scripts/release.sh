#!/bin/sh

set -eu

PROGRAM=gitctx
DEFAULT_VERSION=0.1.0

usage() {
	cat <<'EOF'
Usage: ./scripts/release.sh [options]

Build local release archives and SHA-256 checksums. Nothing is uploaded.

Options:
  --version <value>     Version embedded in each binary (default: 0.1.0)
  --output-dir <path>   Artifact directory (default: ./dist)
  --help                Show this help

The output directory must not already contain files for the requested version.
This prevents a failed rebuild from mixing old and new release artifacts.
EOF
}

die() {
	printf 'release gitctx: %s\n' "$*" >&2
	exit 1
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1"
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1"
	else
		die "sha256sum or shasum is required"
	fi
}

clean_go_env() {
	env \
		-u GOOS \
		-u GOARCH \
		-u GO386 \
		-u GOAMD64 \
		-u GOARM \
		-u GOARM64 \
		-u GOMIPS \
		-u GOMIPS64 \
		-u GOPPC64 \
		-u GORISCV64 \
		-u GOWASM \
		-u GOEXPERIMENT \
		-u GOFIPS140 \
		-u CGO_ENABLED \
		"$@"
}

valid_version() {
	case "$1" in
		''|*[!A-Za-z0-9._+-]*|*[.][.]*|[!0-9]*) return 1 ;;
		*) return 0 ;;
	esac
}

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || die "cannot locate scripts directory"
ROOT_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd -P) || die "cannot locate project directory"

VERSION=$DEFAULT_VERSION
OUTPUT_DIR=$ROOT_DIR/dist

while [ "$#" -gt 0 ]; do
	case "$1" in
		--version)
			[ "$#" -ge 2 ] || die "--version requires a value"
			VERSION=$2
			shift 2
			;;
		--output-dir)
			[ "$#" -ge 2 ] || die "--output-dir requires a path"
			OUTPUT_DIR=$2
			shift 2
			;;
		--help|-h)
			usage
			exit 0
			;;
		*) die "unknown option: $1" ;;
	esac
done

valid_version "$VERSION" || die "version must start with a number, contain only letters, numbers, '.', '_', '+', and '-', and must not contain '..'"
command -v go >/dev/null 2>&1 || die "Go is required to build releases"

mkdir -p "$OUTPUT_DIR" || die "cannot create output directory: $OUTPUT_DIR"
CDPATH= cd "$OUTPUT_DIR" || die "cannot enter output directory: $OUTPUT_DIR"
OUTPUT_LABEL=$(pwd -P) || die "cannot resolve output directory"
[ "$OUTPUT_LABEL" != / ] || die "refusing to write release files directly into /"
# Stay in this directory for every output operation. The process working
# directory remains attached to the same directory if a pathname component is
# renamed or a symlink is retargeted while cross-compilation is running.
OUTPUT_DIR=.

DARWIN_AMD64=$PROGRAM-$VERSION-darwin-amd64.tar.gz
DARWIN_ARM64=$PROGRAM-$VERSION-darwin-arm64.tar.gz
LINUX_AMD64=$PROGRAM-$VERSION-linux-amd64.tar.gz
LINUX_ARM64=$PROGRAM-$VERSION-linux-arm64.tar.gz
WINDOWS_AMD64=$PROGRAM-$VERSION-windows-amd64.zip
CHECKSUMS=$PROGRAM-$VERSION-checksums.txt
FILES="$DARWIN_AMD64 $DARWIN_ARM64 $LINUX_AMD64 $LINUX_ARM64 $WINDOWS_AMD64 $CHECKSUMS"

for FILE in $FILES; do
	TARGET=$OUTPUT_DIR/$FILE
	if [ -L "$TARGET" ]; then
		die "release target is a symbolic link, refusing to replace it: $TARGET"
	fi
	if [ -e "$TARGET" ] && [ ! -f "$TARGET" ]; then
		die "release target is not a regular file, refusing to replace it: $TARGET"
	fi
	if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
		die "release file already exists: $OUTPUT_LABEL/$FILE (choose an empty output directory or remove the exact old release files first)"
	fi
done

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gitctx-release.XXXXXX") || die "cannot create temporary release directory"
WORK_DIR=$(CDPATH= cd "$WORK_DIR" && pwd -P) || die "cannot resolve temporary release directory"
PUBLISH_DIR=
PUBLISHED_FILES=
cleanup() {
	STATUS=$?
	trap - EXIT HUP INT TERM
	if [ -n "$PUBLISH_DIR" ]; then
		for PUBLISHED_FILE in $PUBLISHED_FILES; do
			if [ -e "$OUTPUT_DIR/$PUBLISHED_FILE" ] && [ "$OUTPUT_DIR/$PUBLISHED_FILE" -ef "$PUBLISH_DIR/$PUBLISHED_FILE" ]; then
				rm -f "$OUTPUT_DIR/$PUBLISHED_FILE" || :
			fi
		done
		rm -rf "$PUBLISH_DIR" || :
	fi
	rm -rf "$WORK_DIR" || :
	exit "$STATUS"
}
on_signal() {
	SIGNAL_STATUS=$1
	trap - HUP INT TERM
	exit "$SIGNAL_STATUS"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

mkdir -p "$WORK_DIR/artifacts" "$WORK_DIR/go-cache"
HOST_OS=$(clean_go_env TMPDIR="$WORK_DIR" GOTMPDIR="$WORK_DIR" GO111MODULE=on GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go env GOHOSTOS) || die "cannot determine host operating system"
HOST_ARCH=$(clean_go_env TMPDIR="$WORK_DIR" GOTMPDIR="$WORK_DIR" GO111MODULE=on GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go env GOHOSTARCH) || die "cannot determine host architecture"
case "$HOST_OS/$HOST_ARCH" in
	*[!A-Za-z0-9_./-]*|/|*/) die "Go reported an invalid host platform: $HOST_OS/$HOST_ARCH" ;;
esac
clean_go_env \
	CGO_ENABLED=0 \
	GOOS="$HOST_OS" \
	GOARCH="$HOST_ARCH" \
	GOAMD64=v1 \
	GOARM64=v8.0 \
	GOFIPS140=off \
	GO111MODULE=on \
	GOENV=off \
	GOFLAGS= \
	GOWORK=off \
	GOTOOLCHAIN=local \
	GOPROXY=off \
	GOSUMDB=off \
	GOCACHE="$WORK_DIR/go-cache" \
	TMPDIR="$WORK_DIR" \
	GOTMPDIR="$WORK_DIR" \
	go build -mod=readonly -buildvcs=false -trimpath -o "$WORK_DIR/package-release" "$SCRIPT_DIR/package.go" || die "cannot build deterministic archive helper"
clean_go_env \
	CGO_ENABLED=0 \
	GOOS="$HOST_OS" \
	GOARCH="$HOST_ARCH" \
	GOAMD64=v1 \
	GOARM64=v8.0 \
	GOFIPS140=off \
	GO111MODULE=on \
	GOENV=off \
	GOFLAGS= \
	GOWORK=off \
	GOTOOLCHAIN=local \
	GOPROXY=off \
	GOSUMDB=off \
	GOCACHE="$WORK_DIR/go-cache" \
	TMPDIR="$WORK_DIR" \
	GOTMPDIR="$WORK_DIR" \
	go build -mod=readonly -buildvcs=false -trimpath -o "$WORK_DIR/fileops" "$SCRIPT_DIR/fileops.go" || die "cannot build exact-path publication helper"

build_target() {
	TARGET_OS=$1
	TARGET_ARCH=$2
	ARCHIVE=$3
	FORMAT=$4
	BINARY_NAME=$PROGRAM
	[ "$TARGET_OS" != windows ] || BINARY_NAME=$PROGRAM.exe

	STAGE=$WORK_DIR/$TARGET_OS-$TARGET_ARCH
	mkdir -p "$STAGE"
	LDFLAGS="-s -w -X main.version=$VERSION"
	(
		cd "$ROOT_DIR"
		clean_go_env TMPDIR="$WORK_DIR" GOTMPDIR="$WORK_DIR" CGO_ENABLED=0 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" GOAMD64=v1 GOARM64=v8.0 GOFIPS140=off GO111MODULE=on GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE="$WORK_DIR/go-cache" \
			go build -mod=readonly -buildvcs=false -trimpath -ldflags "$LDFLAGS" -o "$STAGE/$BINARY_NAME" ./cmd/gitctx
	) || die "build failed for $TARGET_OS/$TARGET_ARCH"
	chmod 0755 "$STAGE/$BINARY_NAME"
	"$WORK_DIR/package-release" \
		--source "$STAGE/$BINARY_NAME" \
		--name "$BINARY_NAME" \
		--output "$WORK_DIR/artifacts/$ARCHIVE" \
		--format "$FORMAT" || die "archive failed for $TARGET_OS/$TARGET_ARCH"
}

build_target darwin amd64 "$DARWIN_AMD64" tar.gz
build_target darwin arm64 "$DARWIN_ARM64" tar.gz
build_target linux amd64 "$LINUX_AMD64" tar.gz
build_target linux arm64 "$LINUX_ARM64" tar.gz
build_target windows amd64 "$WINDOWS_AMD64" zip

: >"$WORK_DIR/artifacts/$CHECKSUMS"
for FILE in "$DARWIN_AMD64" "$DARWIN_ARM64" "$LINUX_AMD64" "$LINUX_ARM64" "$WINDOWS_AMD64"; do
	HASH_OUTPUT=$(sha256 "$WORK_DIR/artifacts/$FILE") || die "cannot checksum $FILE"
	HASH=${HASH_OUTPUT%% *}
	case "$HASH" in
		*[!0-9A-Fa-f]*|'') die "checksum tool returned an invalid SHA-256 value for $FILE" ;;
	esac
	[ "${#HASH}" -eq 64 ] || die "checksum tool returned an invalid SHA-256 value for $FILE"
	printf '%s  %s\n' "$HASH" "$FILE" >>"$WORK_DIR/artifacts/$CHECKSUMS"
done

if [ ! -d "$OUTPUT_LABEL" ] || [ ! "$OUTPUT_LABEL" -ef "$OUTPUT_DIR" ]; then
	die "the requested output pathname changed while builds were running; refusing to publish"
fi

PUBLISH_DIR=$(mktemp -d "$OUTPUT_DIR/.gitctx-publish.XXXXXX") || die "cannot stage release files in $OUTPUT_DIR"
for FILE in $FILES; do
	cp "$WORK_DIR/artifacts/$FILE" "$PUBLISH_DIR/$FILE" || die "cannot stage $FILE"
done
for FILE in $FILES; do
	TARGET=$OUTPUT_DIR/$FILE
	if [ -L "$TARGET" ] || { [ -e "$TARGET" ] && [ ! -f "$TARGET" ]; }; then
		die "release target became unsafe while builds were running: $TARGET"
	fi
	PUBLISHED_FILES="$PUBLISHED_FILES $FILE"
	"$WORK_DIR/fileops" link-new "$PUBLISH_DIR/$FILE" "$TARGET" || die "release target appeared while builds were running; no existing file was replaced: $TARGET"
done
PUBLISHED_FILES=
rm -rf "$PUBLISH_DIR"
PUBLISH_DIR=

if FINAL_OUTPUT_LABEL=$(pwd -P 2>/dev/null); then
	printf 'Created gitctx %s release artifacts in %s\n' "$VERSION" "$FINAL_OUTPUT_LABEL"
else
	printf 'Created gitctx %s release artifacts in the pinned output directory (its pathname is no longer available).\n' "$VERSION"
fi
for FILE in $FILES; do
	printf '  %s\n' "$FILE"
done
printf 'Nothing was uploaded.\n'
