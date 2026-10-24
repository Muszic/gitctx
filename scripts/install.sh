#!/bin/sh

set -eu

PROGRAM=gitctx
DEFAULT_VERSION=0.2.0
MANIFEST_NAME=.gitctx-install-manifest
MANIFEST_MAGIC=gitctx-managed-install-v1

usage() {
	cat <<'EOF'
Usage: ./scripts/install.sh [options]

Build and install gitctx for the current user. The default destination is
$HOME/.local/bin. This script does not use sudo and does not edit shell, Git,
SSH, or Git-hosting settings.

Options:
  --bin-dir <path>   Installation directory (default: $HOME/.local/bin)
  --version <value>  Version embedded in the binary (default: 0.2.0)
  --force            Replace an existing binary or installation marker
  --help             Show this help
EOF
}

die() {
	printf 'install gitctx: %s\n' "$*" >&2
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

valid_version() {
	case "$1" in
		''|*[!A-Za-z0-9._+-]*|*[.][.]*|[!0-9]*) return 1 ;;
		*) return 0 ;;
	esac
}

BIN_DIR=
BIN_DIR_SET=0
VERSION=$DEFAULT_VERSION
FORCE=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--bin-dir)
			[ "$#" -ge 2 ] || die "--bin-dir requires a path"
			BIN_DIR=$2
			BIN_DIR_SET=1
			shift 2
			;;
		--version)
			[ "$#" -ge 2 ] || die "--version requires a value"
			VERSION=$2
			shift 2
			;;
		--force)
			FORCE=1
			shift
			;;
		--help|-h)
			usage
			exit 0
			;;
		*) die "unknown option: $1" ;;
	esac
done

valid_version "$VERSION" || die "version must start with a number, contain only letters, numbers, '.', '_', '+', and '-', and must not contain '..'"
CLIENT_ID=${GITCTX_GITHUB_CLIENT_ID:-}
case "$CLIENT_ID" in *[!A-Za-z0-9._-]*) die "invalid public GitHub Client ID" ;; esac
if [ -n "$CLIENT_ID" ]; then [ "${#CLIENT_ID}" -ge 8 ] && [ "${#CLIENT_ID}" -le 128 ] || die "invalid public GitHub Client ID"; fi
command -v go >/dev/null 2>&1 || die "Go is required to build gitctx"

if [ "$BIN_DIR_SET" -eq 0 ]; then
	[ -n "${HOME:-}" ] || die "HOME is not set; pass --bin-dir explicitly"
	BIN_DIR=$HOME/.local/bin
fi
[ -n "$BIN_DIR" ] || die "installation directory must not be empty"

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || die "cannot locate scripts directory"
ROOT_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd -P) || die "cannot locate project directory"

mkdir -p "$BIN_DIR" || die "cannot create installation directory: $BIN_DIR"
cd "$BIN_DIR" || die "cannot enter installation directory: $BIN_DIR"
BIN_DIR=$(pwd -P) || die "cannot resolve installation directory"
[ "$BIN_DIR" != / ] || die "refusing to install directly into /"

# Destination operations stay relative to this pinned cwd. Renaming the
# directory and replacing its old pathname with a symlink cannot retarget the
# later writes into a different directory.
TARGET=./$PROGRAM
MANIFEST=./$MANIFEST_NAME
LOCK=./.gitctx-install-lock
TARGET_PATH=$BIN_DIR/$PROGRAM
MANIFEST_PATH=$BIN_DIR/$MANIFEST_NAME
LOCK_PATH=$BIN_DIR/.gitctx-install-lock

if ! mkdir "$LOCK" 2>/dev/null; then
	die "another install or uninstall is active, or a stale lock exists at $LOCK_PATH"
fi

WORK_DIR=
STAGED_BINARY=
STAGED_MANIFEST=
BACKUP_BINARY=
BACKUP_MANIFEST=
NEW_BINARY_INSTALLED=0
NEW_MANIFEST_INSTALLED=0
COMMITTED=0

cleanup() {
	STATUS=$?
	trap - EXIT HUP INT TERM
	set +e
	if [ "$COMMITTED" -ne 1 ]; then
		if [ "$NEW_MANIFEST_INSTALLED" -eq 1 ] && [ -n "$STAGED_MANIFEST" ] && [ -e "$STAGED_MANIFEST" ] && [ -e "$MANIFEST" ] && [ "$STAGED_MANIFEST" -ef "$MANIFEST" ]; then
			rm -f "$MANIFEST"
		fi
		if [ "$NEW_BINARY_INSTALLED" -eq 1 ] && [ -n "$STAGED_BINARY" ] && [ -e "$STAGED_BINARY" ] && [ -e "$TARGET" ] && [ "$STAGED_BINARY" -ef "$TARGET" ]; then
			rm -f "$TARGET"
		fi
		if [ -n "$BACKUP_BINARY" ] && [ -e "$BACKUP_BINARY" ]; then
			if "$WORK_DIR/fileops" move-new "$BACKUP_BINARY" "$TARGET"; then
				BACKUP_BINARY=
			else
				printf 'install gitctx: warning: could not restore %s from %s\n' "$TARGET_PATH" "$BACKUP_BINARY" >&2
			fi
		fi
		if [ -n "$BACKUP_MANIFEST" ] && [ -e "$BACKUP_MANIFEST" ]; then
			if "$WORK_DIR/fileops" move-new "$BACKUP_MANIFEST" "$MANIFEST"; then
				BACKUP_MANIFEST=
			else
				printf 'install gitctx: warning: could not restore %s from %s\n' "$MANIFEST_PATH" "$BACKUP_MANIFEST" >&2
			fi
		fi
	fi
	[ -z "$STAGED_BINARY" ] || rm -f "$STAGED_BINARY"
	[ -z "$STAGED_MANIFEST" ] || rm -f "$STAGED_MANIFEST"
	if [ "$COMMITTED" -eq 1 ]; then
		[ -z "$BACKUP_BINARY" ] || rm -f "$BACKUP_BINARY"
		[ -z "$BACKUP_MANIFEST" ] || rm -f "$BACKUP_MANIFEST"
	fi
	[ -z "$WORK_DIR" ] || rm -rf "$WORK_DIR"
	rmdir "$LOCK" 2>/dev/null || :
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

if [ -L "$TARGET" ]; then
	die "target is a symbolic link, refusing to replace it: $TARGET_PATH"
fi
if [ -e "$TARGET" ] && [ ! -f "$TARGET" ]; then
	die "target is not a regular file, refusing to replace it: $TARGET_PATH"
fi
if { [ -e "$TARGET" ] || [ -e "$MANIFEST" ] || [ -L "$MANIFEST" ]; } && [ "$FORCE" -ne 1 ]; then
	die "an existing target or installation marker was found at $TARGET_PATH; inspect it, then rerun with --force to replace it"
fi
if [ -L "$MANIFEST" ]; then
	die "installation marker is a symbolic link, refusing to replace it: $MANIFEST_PATH"
fi
if [ -e "$MANIFEST" ] && [ ! -f "$MANIFEST" ]; then
	die "installation marker is not a regular file, refusing to replace it: $MANIFEST_PATH"
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gitctx-install.XXXXXX") || die "cannot create temporary build directory"
WORK_DIR=$(CDPATH= cd "$WORK_DIR" && pwd -P) || die "cannot resolve temporary build directory"
mkdir -p "$WORK_DIR/go-cache" || die "cannot create private Go build cache"
LDFLAGS="-s -w -X main.version=$VERSION -X gitctx/internal/githubkeys.OAuthClientID=$CLIENT_ID"
(
	cd "$ROOT_DIR"
	env TMPDIR="$WORK_DIR" GOTMPDIR="$WORK_DIR" CGO_ENABLED=0 GOOS= GOARCH= GOAMD64= GOARM64= GOEXPERIMENT= GOFIPS140=off GO111MODULE=on GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE="$WORK_DIR/go-cache" \
		go build -mod=readonly -buildvcs=false -trimpath -ldflags "$LDFLAGS" -o "$WORK_DIR/$PROGRAM" ./cmd/gitctx
	env TMPDIR="$WORK_DIR" GOTMPDIR="$WORK_DIR" CGO_ENABLED=0 GOOS= GOARCH= GOAMD64= GOARM64= GOEXPERIMENT= GOFIPS140=off GO111MODULE=on GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE="$WORK_DIR/go-cache" \
		go build -mod=readonly -buildvcs=false -trimpath -o "$WORK_DIR/fileops" "$SCRIPT_DIR/fileops.go"
) || die "build failed"

ACTUAL_VERSION=$("$WORK_DIR/$PROGRAM" version 2>/dev/null) || die "built binary failed its version check"
[ "$ACTUAL_VERSION" = "$PROGRAM $VERSION" ] || die "built binary reported an unexpected version: $ACTUAL_VERSION"

STAGED_BINARY=$(mktemp "./.gitctx-install.XXXXXX") || die "cannot stage binary in $BIN_DIR"
cp "$WORK_DIR/$PROGRAM" "$STAGED_BINARY" || die "cannot stage binary"
chmod 0755 "$STAGED_BINARY" || die "cannot make staged binary executable"

HASH_OUTPUT=$(sha256 "$STAGED_BINARY") || die "cannot calculate binary checksum"
HASH=${HASH_OUTPUT%% *}
case "$HASH" in
	*[!0-9A-Fa-f]*|'') die "checksum tool returned an invalid SHA-256 value" ;;
esac
[ "${#HASH}" -eq 64 ] || die "checksum tool returned an invalid SHA-256 value"

STAGED_MANIFEST=$(mktemp "./.gitctx-manifest.XXXXXX") || die "cannot stage installation marker"
{
	printf '%s\n' "$MANIFEST_MAGIC"
	printf 'binary=%s\n' "$PROGRAM"
	printf 'version=%s\n' "$VERSION"
	printf 'sha256=%s\n' "$HASH"
} >"$STAGED_MANIFEST"
chmod 0644 "$STAGED_MANIFEST" || die "cannot protect installation marker"

[ -d "$BIN_DIR" ] && [ "$BIN_DIR" -ef . ] || die "installation directory moved or changed during the build; nothing was installed"
[ ! -L "$TARGET" ] || die "target became a symbolic link during the build; refusing to replace it: $TARGET_PATH"
[ ! -e "$TARGET" ] || [ -f "$TARGET" ] || die "target became a non-regular file during the build; refusing to replace it: $TARGET_PATH"
[ ! -L "$MANIFEST" ] || die "installation marker became a symbolic link during the build; refusing to replace it: $MANIFEST_PATH"
[ ! -e "$MANIFEST" ] || [ -f "$MANIFEST" ] || die "installation marker became a non-regular file during the build; refusing to replace it: $MANIFEST_PATH"
if { [ -e "$TARGET" ] || [ -e "$MANIFEST" ]; } && [ "$FORCE" -ne 1 ]; then
	die "the destination changed during the build; refusing to overwrite it"
fi

if [ -e "$TARGET" ]; then
	BACKUP_BINARY=$(mktemp "./.gitctx-binary-backup.XXXXXX") || die "cannot reserve binary rollback path"
	rm -f "$BACKUP_BINARY"
	"$WORK_DIR/fileops" move-new "$TARGET" "$BACKUP_BINARY" || die "cannot preserve existing binary for rollback"
fi
if [ -e "$MANIFEST" ]; then
	BACKUP_MANIFEST=$(mktemp "./.gitctx-manifest-backup.XXXXXX") || die "cannot reserve marker rollback path"
	rm -f "$BACKUP_MANIFEST"
	"$WORK_DIR/fileops" move-new "$MANIFEST" "$BACKUP_MANIFEST" || die "cannot preserve existing installation marker for rollback"
fi

NEW_BINARY_INSTALLED=1
"$WORK_DIR/fileops" link-new "$STAGED_BINARY" "$TARGET" || die "installation target appeared while committing; the previous installation will be restored"
NEW_MANIFEST_INSTALLED=1
"$WORK_DIR/fileops" link-new "$STAGED_MANIFEST" "$MANIFEST" || die "installation marker appeared while committing; the previous installation will be restored"
COMMITTED=1

if FINAL_BIN_DIR=$(pwd -P 2>/dev/null); then
	FINAL_TARGET_PATH=$FINAL_BIN_DIR/$PROGRAM
else
	FINAL_BIN_DIR=
	FINAL_TARGET_PATH='the pinned installation directory'
fi
printf 'Installed gitctx %s at %s\n' "$VERSION" "$FINAL_TARGET_PATH"
printf 'No shell, Git, SSH, or Git-hosting settings were changed.\n'
if [ -n "$FINAL_BIN_DIR" ]; then
	case ":${PATH:-}:" in
		*":$FINAL_BIN_DIR:"*) ;;
		*)
			printf 'Note: %s is not currently on PATH. Add it using your preferred shell configuration.\n' "$FINAL_BIN_DIR"
			;;
	esac
fi
