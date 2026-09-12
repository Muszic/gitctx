#!/bin/sh

set -eu

PROGRAM=gitctx
MANIFEST_NAME=.gitctx-install-manifest
MANIFEST_MAGIC=gitctx-managed-install-v1

usage() {
	cat <<'EOF'
Usage: ./scripts/uninstall.sh [options]

Remove a user-local gitctx installation only after verifying its adjacent
gitctx installation marker and binary checksum.

Options:
  --bin-dir <path>  Installation directory (default: $HOME/.local/bin)
  --force           Remove a marked binary whose checksum has changed
  --help            Show this help
EOF
}

die() {
	printf 'uninstall gitctx: %s\n' "$*" >&2
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

BIN_DIR=
BIN_DIR_SET=0
FORCE=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--bin-dir)
			[ "$#" -ge 2 ] || die "--bin-dir requires a path"
			BIN_DIR=$2
			BIN_DIR_SET=1
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

if [ "$BIN_DIR_SET" -eq 0 ]; then
	[ -n "${HOME:-}" ] || die "HOME is not set; pass --bin-dir explicitly"
	BIN_DIR=$HOME/.local/bin
fi
[ -n "$BIN_DIR" ] || die "installation directory must not be empty"
[ -d "$BIN_DIR" ] || die "installation directory does not exist: $BIN_DIR"
cd "$BIN_DIR" || die "cannot enter installation directory: $BIN_DIR"
BIN_DIR=$(pwd -P) || die "cannot resolve installation directory"
[ "$BIN_DIR" != / ] || die "refusing to uninstall directly from /"

TARGET=./$PROGRAM
MANIFEST=./$MANIFEST_NAME
LOCK=./.gitctx-install-lock
TARGET_PATH=$BIN_DIR/$PROGRAM
MANIFEST_PATH=$BIN_DIR/$MANIFEST_NAME
LOCK_PATH=$BIN_DIR/.gitctx-install-lock

if ! mkdir "$LOCK" 2>/dev/null; then
	die "another install or uninstall is active, or a stale lock exists at $LOCK_PATH"
fi

TRANSACTION_DIR=
QUARANTINE_BINARY=
QUARANTINE_MANIFEST=
COMMITTED=0

cleanup() {
	STATUS=$?
	trap - EXIT HUP INT TERM
	set +e
	if [ "$COMMITTED" -ne 1 ]; then
		if [ -n "$QUARANTINE_BINARY" ] && { [ -e "$QUARANTINE_BINARY" ] || [ -L "$QUARANTINE_BINARY" ]; }; then
			if [ ! -e "$TARGET" ] && [ ! -L "$TARGET" ] && mv "$QUARANTINE_BINARY" "$TARGET"; then
				QUARANTINE_BINARY=
			else
				printf 'uninstall gitctx: warning: could not restore %s from %s\n' "$TARGET_PATH" "$QUARANTINE_BINARY" >&2
			fi
		fi
		if [ -n "$QUARANTINE_MANIFEST" ] && { [ -e "$QUARANTINE_MANIFEST" ] || [ -L "$QUARANTINE_MANIFEST" ]; }; then
			if [ ! -e "$MANIFEST" ] && [ ! -L "$MANIFEST" ] && mv "$QUARANTINE_MANIFEST" "$MANIFEST"; then
				QUARANTINE_MANIFEST=
			else
				printf 'uninstall gitctx: warning: could not restore %s from %s\n' "$MANIFEST_PATH" "$QUARANTINE_MANIFEST" >&2
			fi
		fi
	else
		[ -z "$QUARANTINE_BINARY" ] || rm -f "$QUARANTINE_BINARY"
		[ -z "$QUARANTINE_MANIFEST" ] || rm -f "$QUARANTINE_MANIFEST"
	fi
	if [ -n "$TRANSACTION_DIR" ] && ! rmdir "$TRANSACTION_DIR" 2>/dev/null; then
		printf 'uninstall gitctx: warning: retained recovery data in %s\n' "$BIN_DIR/${TRANSACTION_DIR#./}" >&2
	fi
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

[ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || die "no regular gitctx installation marker exists at $MANIFEST_PATH; refusing to remove $TARGET_PATH"
if [ -L "$TARGET" ]; then
	die "marked target is a symbolic link; refusing to remove it: $TARGET_PATH"
fi
if [ -e "$TARGET" ] && [ ! -f "$TARGET" ]; then
	die "marked target is not a regular file; refusing to remove it: $TARGET_PATH"
fi

[ -d "$BIN_DIR" ] && [ "$BIN_DIR" -ef . ] || die "installation directory moved or changed; nothing was removed"

TRANSACTION_DIR=$(mktemp -d "./.gitctx-uninstall.XXXXXX") || die "cannot create private uninstall transaction directory"
chmod 0700 "$TRANSACTION_DIR" || die "cannot protect uninstall transaction directory"
QUARANTINE_MANIFEST=$TRANSACTION_DIR/manifest
mv "$MANIFEST" "$QUARANTINE_MANIFEST" || die "installation marker changed before it could be verified"
[ -f "$QUARANTINE_MANIFEST" ] && [ ! -L "$QUARANTINE_MANIFEST" ] || die "installation marker became unsafe; the installation was restored"

if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
	QUARANTINE_BINARY=$TRANSACTION_DIR/binary
	mv "$TARGET" "$QUARANTINE_BINARY" || die "installed binary changed before it could be verified"
	[ -f "$QUARANTINE_BINARY" ] && [ ! -L "$QUARANTINE_BINARY" ] || die "installed binary became unsafe; the installation was restored"
fi

MAGIC=$(sed -n '1p' "$QUARANTINE_MANIFEST")
BINARY_LINE=$(sed -n '2p' "$QUARANTINE_MANIFEST")
VERSION_LINE=$(sed -n '3p' "$QUARANTINE_MANIFEST")
HASH_LINE=$(sed -n '4p' "$QUARANTINE_MANIFEST")
LINE_COUNT=$(wc -l <"$QUARANTINE_MANIFEST" | tr -d ' ')

[ "$MAGIC" = "$MANIFEST_MAGIC" ] || die "installation marker is not recognized; the installation was restored"
[ "$BINARY_LINE" = "binary=$PROGRAM" ] || die "installation marker names a different binary; the installation was restored"
case "$VERSION_LINE" in
	version=*) ;;
	*) die "installation marker has no valid version; the installation was restored" ;;
esac
case "$HASH_LINE" in
	sha256=*) EXPECTED_HASH=${HASH_LINE#sha256=} ;;
	*) die "installation marker has no valid checksum; the installation was restored" ;;
esac
[ "$LINE_COUNT" = 4 ] || die "installation marker has unexpected content; the installation was restored"
case "$EXPECTED_HASH" in
	*[!0-9A-Fa-f]*|'') die "installation marker has an invalid checksum; the installation was restored" ;;
esac
[ "${#EXPECTED_HASH}" -eq 64 ] || die "installation marker has an invalid checksum; the installation was restored"

if [ -z "$QUARANTINE_BINARY" ]; then
	[ -d "$BIN_DIR" ] && [ "$BIN_DIR" -ef . ] || die "the requested installation directory moved or changed during verification; the installation was restored in the pinned directory"
	COMMITTED=1
	if FINAL_BIN_DIR=$(pwd -P 2>/dev/null); then
		printf 'Removed stale gitctx installation marker at %s/%s; the binary was already absent.\n' "$FINAL_BIN_DIR" "$MANIFEST_NAME"
	else
		printf 'Removed the stale gitctx installation marker from the pinned directory; the binary was already absent.\n'
	fi
	exit 0
fi

HASH_OUTPUT=$(sha256 "$QUARANTINE_BINARY") || die "cannot calculate installed binary checksum; the installation was restored"
ACTUAL_HASH=${HASH_OUTPUT%% *}
HASH_MATCHED=1
if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
	HASH_MATCHED=0
	if [ "$FORCE" -ne 1 ]; then
		die "installed binary checksum differs from its marker; the installation was restored (use --force only after reviewing $TARGET_PATH)"
	fi
fi

[ -d "$BIN_DIR" ] && [ "$BIN_DIR" -ef . ] || die "the requested installation directory moved or changed during verification; the installation was restored in the pinned directory"
COMMITTED=1
if FINAL_BIN_DIR=$(pwd -P 2>/dev/null); then
	FINAL_TARGET_PATH=$FINAL_BIN_DIR/$PROGRAM
else
	FINAL_TARGET_PATH='the pinned installation directory'
fi
if [ "$HASH_MATCHED" -eq 1 ]; then
	printf 'Removed verified gitctx installation from %s\n' "$FINAL_TARGET_PATH"
else
	printf 'Removed marked gitctx installation from %s with --force after its checksum differed.\n' "$FINAL_TARGET_PATH"
fi
printf 'No shell, Git, SSH, or Git-hosting settings were changed.\n'
