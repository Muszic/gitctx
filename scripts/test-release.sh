#!/bin/sh

set -eu

die() {
	printf 'release workflow test: %s\n' "$*" >&2
	exit 1
}

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || die "cannot locate scripts directory"
ROOT_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd -P) || die "cannot locate project directory"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gitctx-release-test.XXXXXX") || die "cannot create temporary test directory"
WORK_DIR=$(CDPATH= cd "$WORK_DIR" && pwd -P) || die "cannot resolve temporary test directory"
RETARGET_PID=
RETARGET_CONTINUE=
UNINSTALL_RETARGET_PID=
UNINSTALL_RETARGET_CONTINUE=
cleanup() {
	STATUS=$?
	trap - EXIT HUP INT TERM
	if [ -n "$UNINSTALL_RETARGET_PID" ]; then
		[ -z "$UNINSTALL_RETARGET_CONTINUE" ] || : >"$UNINSTALL_RETARGET_CONTINUE"
		if kill -0 "$UNINSTALL_RETARGET_PID" 2>/dev/null; then
			kill -TERM "$UNINSTALL_RETARGET_PID" 2>/dev/null || :
		fi
		wait "$UNINSTALL_RETARGET_PID" 2>/dev/null || :
		UNINSTALL_RETARGET_PID=
	fi
	if [ -n "$RETARGET_PID" ]; then
		[ -z "$RETARGET_CONTINUE" ] || : >"$RETARGET_CONTINUE"
		if kill -0 "$RETARGET_PID" 2>/dev/null; then
			kill -TERM "$RETARGET_PID" 2>/dev/null || :
		fi
		wait "$RETARGET_PID" 2>/dev/null || :
		RETARGET_PID=
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

sh -n "$SCRIPT_DIR/install.sh"
sh -n "$SCRIPT_DIR/uninstall.sh"
sh -n "$SCRIPT_DIR/release.sh"
if "$SCRIPT_DIR/install.sh" --bin-dir '' >"$WORK_DIR/empty-install.out" 2>"$WORK_DIR/empty-install.err"; then
	die "installer accepted an explicitly empty installation directory"
fi
if "$SCRIPT_DIR/uninstall.sh" --bin-dir '' >"$WORK_DIR/empty-uninstall.out" 2>"$WORK_DIR/empty-uninstall.err"; then
	die "uninstaller accepted an explicitly empty installation directory"
fi
mkdir -p "$WORK_DIR/package-test-cache"
env TMPDIR="$WORK_DIR" GOTMPDIR="$WORK_DIR" CGO_ENABLED=0 GOOS= GOARCH= GOEXPERIMENT= GOFIPS140=off GO111MODULE=on GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE="$WORK_DIR/package-test-cache" \
	go test "$SCRIPT_DIR/package.go" "$SCRIPT_DIR/package_test.go"

MAKE_CANARY=$WORK_DIR/make-expansion-canary
MALICIOUS_VERSION="1.2.3\`touch $MAKE_CANARY\`"
if make -s -C "$ROOT_DIR" release VERSION="$MALICIOUS_VERSION" DIST_DIR="$WORK_DIR/make-injection-dist" >"$WORK_DIR/make-injection.out" 2>"$WORK_DIR/make-injection.err"; then
	die "Make accepted an unsafe version value"
fi
[ ! -e "$MAKE_CANARY" ] || die "Make evaluated shell syntax from a command-line variable"
MAKE_FUNCTION_CANARY=$WORK_DIR/make-function-canary
MAKE_FUNCTION_VERSION='$(shell touch '"$MAKE_FUNCTION_CANARY"')'
if make -s -C "$ROOT_DIR" release VERSION="$MAKE_FUNCTION_VERSION" DIST_DIR="$WORK_DIR/make-function-dist" >"$WORK_DIR/make-function.out" 2>"$WORK_DIR/make-function.err"; then
	die "Make accepted a version containing make syntax"
fi
[ ! -e "$MAKE_FUNCTION_CANARY" ] || die "Make evaluated a function from a command-line variable"

FILEOPS=$WORK_DIR/fileops
env TMPDIR="$WORK_DIR" GOTMPDIR="$WORK_DIR" CGO_ENABLED=0 GOOS= GOARCH= GOEXPERIMENT= GOFIPS140=off GO111MODULE=on GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE="$WORK_DIR/package-test-cache" \
	go build -mod=readonly -buildvcs=false -trimpath -o "$FILEOPS" "$SCRIPT_DIR/fileops.go"
FILEOPS_SOURCE=$WORK_DIR/fileops-source
FILEOPS_DESTINATION=$WORK_DIR/fileops-destination
FILEOPS_VICTIM=$WORK_DIR/fileops-victim
mkdir -p "$FILEOPS_VICTIM"
printf 'source\n' >"$FILEOPS_SOURCE"
ln -s "$FILEOPS_VICTIM" "$FILEOPS_DESTINATION"
if "$FILEOPS" link-new "$FILEOPS_SOURCE" "$FILEOPS_DESTINATION" >"$WORK_DIR/fileops.out" 2>"$WORK_DIR/fileops.err"; then
	die "exact-path helper followed a destination symlink"
fi
[ ! -e "$FILEOPS_VICTIM/$(basename "$FILEOPS_SOURCE")" ] || die "exact-path helper wrote inside a destination directory"

BIN_DIR=$WORK_DIR/bin
mkdir -p "$BIN_DIR/relative-tmp"
TMPDIR=relative-tmp GOTMPDIR=relative-tmp GOOS=windows GOARCH=amd64 GO111MODULE=off "$SCRIPT_DIR/install.sh" --bin-dir "$BIN_DIR" --version 9.8.7-test
rmdir "$BIN_DIR/relative-tmp" || die "relative TMPDIR install left private build data behind"
[ "$("$BIN_DIR/gitctx" version)" = "gitctx 9.8.7-test" ] || die "installed binary has the wrong version"
[ -f "$BIN_DIR/.gitctx-install-manifest" ] || die "install marker was not created"

DANGLING_MV_WRAPPER_DIR=$WORK_DIR/dangling-mv-wrapper
DANGLING_SAVED_BINARY=$WORK_DIR/dangling-saved-binary
DANGLING_EXPECTED_MANIFEST=$WORK_DIR/dangling-expected-manifest
DANGLING_LINK_TARGET=gitctx-dangling-target-does-not-exist
REAL_MV=$(command -v mv) || die "cannot find mv for dangling-symlink rollback regression"
mkdir -p "$DANGLING_MV_WRAPPER_DIR"
cp "$BIN_DIR/.gitctx-install-manifest" "$DANGLING_EXPECTED_MANIFEST"
cat >"$DANGLING_MV_WRAPPER_DIR/mv" <<'EOF'
#!/bin/sh
if [ "$#" -eq 2 ] && [ "$1" = ./gitctx ]; then
	case "$2" in
		./.gitctx-uninstall.*/binary)
			"$GITCTX_DANGLING_REAL_MV" "$1" "$GITCTX_DANGLING_SAVED_BINARY" || exit
			ln -s "$GITCTX_DANGLING_LINK_TARGET" "$1" || exit
			;;
	esac
fi
exec "$GITCTX_DANGLING_REAL_MV" "$@"
EOF
chmod 0755 "$DANGLING_MV_WRAPPER_DIR/mv"
if GITCTX_DANGLING_REAL_MV="$REAL_MV" \
	GITCTX_DANGLING_SAVED_BINARY="$DANGLING_SAVED_BINARY" \
	GITCTX_DANGLING_LINK_TARGET="$DANGLING_LINK_TARGET" \
	PATH="$DANGLING_MV_WRAPPER_DIR:$PATH" \
	"$SCRIPT_DIR/uninstall.sh" --bin-dir "$BIN_DIR" >"$WORK_DIR/dangling-uninstall.out" 2>"$WORK_DIR/dangling-uninstall.err"; then
	die "uninstaller accepted a binary replaced by a dangling symlink during quarantine"
fi
[ -L "$BIN_DIR/gitctx" ] || die "uninstall rollback did not restore the quarantined symbolic link"
[ ! -e "$BIN_DIR/gitctx" ] || die "restored quarantine test link is not dangling"
[ "$(readlink "$BIN_DIR/gitctx")" = "$DANGLING_LINK_TARGET" ] || die "uninstall rollback changed the dangling link target"
cmp "$BIN_DIR/.gitctx-install-manifest" "$DANGLING_EXPECTED_MANIFEST" >/dev/null || die "dangling-link rollback did not restore the installation manifest"
[ -f "$DANGLING_SAVED_BINARY" ] || die "controlled quarantine race did not preserve the original binary"
[ "$("$DANGLING_SAVED_BINARY" version)" = "gitctx 9.8.7-test" ] || die "controlled quarantine race changed the preserved binary"
[ ! -e "$BIN_DIR/.gitctx-install-lock" ] || die "dangling-link rollback retained its transaction lock"
for DANGLING_LEFTOVER in "$BIN_DIR"/.gitctx-uninstall.*; do
	[ ! -e "$DANGLING_LEFTOVER" ] && [ ! -L "$DANGLING_LEFTOVER" ] || die "dangling-link rollback retained transaction data"
done
if grep -q 'could not restore' "$WORK_DIR/dangling-uninstall.err"; then
	die "uninstaller reported that the quarantined dangling link could not be restored"
fi
rm -f "$BIN_DIR/gitctx"
mv "$DANGLING_SAVED_BINARY" "$BIN_DIR/gitctx"
[ "$("$BIN_DIR/gitctx" version)" = "gitctx 9.8.7-test" ] || die "dangling-link regression did not restore its test fixture"

mkdir "$BIN_DIR/.gitctx-install-lock"
if "$SCRIPT_DIR/install.sh" --bin-dir "$BIN_DIR" --version 9.8.7-test --force >"$WORK_DIR/locked-install.out" 2>"$WORK_DIR/locked-install.err"; then
	die "installer ignored an active transaction lock"
fi
rmdir "$BIN_DIR/.gitctx-install-lock"
[ "$("$BIN_DIR/gitctx" version)" = "gitctx 9.8.7-test" ] || die "refused concurrent install changed the binary"

if "$SCRIPT_DIR/install.sh" --bin-dir "$BIN_DIR" --version 9.8.7-test >"$WORK_DIR/reinstall.out" 2>"$WORK_DIR/reinstall.err"; then
	die "installer overwrote an existing target without --force"
fi
[ -x "$BIN_DIR/gitctx" ] || die "refused reinstall damaged the existing binary"

printf '#!/bin/sh\nexit 42\n' >"$BIN_DIR/gitctx"
chmod 0755 "$BIN_DIR/gitctx"
if "$SCRIPT_DIR/uninstall.sh" --bin-dir "$BIN_DIR" >"$WORK_DIR/uninstall.out" 2>"$WORK_DIR/uninstall.err"; then
	die "uninstaller removed a checksum-mismatched binary without --force"
fi
[ -e "$BIN_DIR/gitctx" ] || die "refused uninstall removed the modified binary"
[ -f "$BIN_DIR/.gitctx-install-manifest" ] || die "refused uninstall removed the installation marker"
[ "$(sed -n '2p' "$BIN_DIR/gitctx")" = 'exit 42' ] || die "refused uninstall did not restore the same modified binary"

"$SCRIPT_DIR/uninstall.sh" --bin-dir "$BIN_DIR" --force >"$WORK_DIR/forced-mismatch.out" 2>"$WORK_DIR/forced-mismatch.err"
[ ! -e "$BIN_DIR/gitctx" ] || die "forced checksum-mismatch uninstall retained the binary"
[ ! -e "$BIN_DIR/.gitctx-install-manifest" ] || die "forced checksum-mismatch uninstall retained the marker"
grep -q 'Removed marked gitctx installation' "$WORK_DIR/forced-mismatch.out" || die "forced checksum-mismatch uninstall did not identify the installation as marked"
if grep -q 'Removed verified gitctx installation' "$WORK_DIR/forced-mismatch.out"; then
	die "forced checksum-mismatch uninstall incorrectly called the binary verified"
fi

"$SCRIPT_DIR/install.sh" --bin-dir "$BIN_DIR" --version 9.8.7-test
UNINSTALL_RETARGET_VISIBLE=$BIN_DIR
UNINSTALL_RETARGET_PINNED=$WORK_DIR/bin-pinned
UNINSTALL_RETARGET_READY=$WORK_DIR/uninstall-retarget-ready
UNINSTALL_RETARGET_CONTINUE=$WORK_DIR/uninstall-retarget-continue
EXPECTED_RETARGET_BINARY=$WORK_DIR/expected-retarget-binary
EXPECTED_RETARGET_MANIFEST=$WORK_DIR/expected-retarget-manifest
cp "$UNINSTALL_RETARGET_VISIBLE/gitctx" "$EXPECTED_RETARGET_BINARY"
cp "$UNINSTALL_RETARGET_VISIBLE/.gitctx-install-manifest" "$EXPECTED_RETARGET_MANIFEST"

CHECKSUM_WRAPPER_DIR=$WORK_DIR/checksum-wrapper
mkdir -p "$CHECKSUM_WRAPPER_DIR"
if REAL_CHECKSUM=$(command -v sha256sum 2>/dev/null); then
	CHECKSUM_PROGRAM=sha256sum
elif REAL_CHECKSUM=$(command -v shasum 2>/dev/null); then
	CHECKSUM_PROGRAM=shasum
else
	die "cannot find a SHA-256 tool for uninstall retarget regression"
fi
cat >"$CHECKSUM_WRAPPER_DIR/$CHECKSUM_PROGRAM" <<'EOF'
#!/bin/sh
: >"$GITCTX_UNINSTALL_RETARGET_READY"
while [ ! -e "$GITCTX_UNINSTALL_RETARGET_CONTINUE" ]; do
	sleep 0.05
done
exec "$GITCTX_UNINSTALL_REAL_CHECKSUM" "$@"
EOF
chmod 0755 "$CHECKSUM_WRAPPER_DIR/$CHECKSUM_PROGRAM"

GITCTX_UNINSTALL_RETARGET_READY="$UNINSTALL_RETARGET_READY" \
	GITCTX_UNINSTALL_RETARGET_CONTINUE="$UNINSTALL_RETARGET_CONTINUE" \
	GITCTX_UNINSTALL_REAL_CHECKSUM="$REAL_CHECKSUM" \
	PATH="$CHECKSUM_WRAPPER_DIR:$PATH" \
	"$SCRIPT_DIR/uninstall.sh" --bin-dir "$UNINSTALL_RETARGET_VISIBLE" >"$WORK_DIR/uninstall-retarget.out" 2>"$WORK_DIR/uninstall-retarget.err" &
UNINSTALL_RETARGET_PID=$!
UNINSTALL_RETARGET_ATTEMPTS=0
while [ ! -e "$UNINSTALL_RETARGET_READY" ]; do
	if ! kill -0 "$UNINSTALL_RETARGET_PID" 2>/dev/null; then
		wait "$UNINSTALL_RETARGET_PID" || :
		UNINSTALL_RETARGET_PID=
		die "uninstall retarget regression exited before its delayed checksum"
	fi
	UNINSTALL_RETARGET_ATTEMPTS=$((UNINSTALL_RETARGET_ATTEMPTS + 1))
	if [ "$UNINSTALL_RETARGET_ATTEMPTS" -gt 400 ]; then
		: >"$UNINSTALL_RETARGET_CONTINUE"
		kill -TERM "$UNINSTALL_RETARGET_PID" 2>/dev/null || :
		wait "$UNINSTALL_RETARGET_PID" || :
		UNINSTALL_RETARGET_PID=
		die "timed out waiting for delayed uninstall checksum"
	fi
	sleep 0.05
done

mv "$UNINSTALL_RETARGET_VISIBLE" "$UNINSTALL_RETARGET_PINNED"
mkdir -p "$UNINSTALL_RETARGET_VISIBLE"
printf 'replacement binary\n' >"$UNINSTALL_RETARGET_VISIBLE/gitctx"
printf 'replacement manifest\n' >"$UNINSTALL_RETARGET_VISIBLE/.gitctx-install-manifest"
: >"$UNINSTALL_RETARGET_CONTINUE"
if wait "$UNINSTALL_RETARGET_PID"; then
	UNINSTALL_RETARGET_STATUS=0
else
	UNINSTALL_RETARGET_STATUS=$?
fi
UNINSTALL_RETARGET_PID=
[ "$UNINSTALL_RETARGET_STATUS" -ne 0 ] || die "uninstaller committed after its requested directory was retargeted"
cmp "$UNINSTALL_RETARGET_PINNED/gitctx" "$EXPECTED_RETARGET_BINARY" >/dev/null || die "failed retarget uninstall did not restore the original binary"
cmp "$UNINSTALL_RETARGET_PINNED/.gitctx-install-manifest" "$EXPECTED_RETARGET_MANIFEST" >/dev/null || die "failed retarget uninstall did not restore the original manifest"
[ "$(sed -n '1p' "$UNINSTALL_RETARGET_VISIBLE/gitctx")" = 'replacement binary' ] || die "failed retarget uninstall touched the replacement binary"
[ "$(sed -n '1p' "$UNINSTALL_RETARGET_VISIBLE/.gitctx-install-manifest")" = 'replacement manifest' ] || die "failed retarget uninstall touched the replacement manifest"
[ ! -e "$UNINSTALL_RETARGET_PINNED/.gitctx-install-lock" ] || die "failed retarget uninstall retained its transaction lock"
grep -q 'moved or changed' "$WORK_DIR/uninstall-retarget.err" || die "retargeted uninstall did not explain its safe failure"

BIN_DIR=$UNINSTALL_RETARGET_PINNED
"$SCRIPT_DIR/uninstall.sh" --bin-dir "$BIN_DIR"
[ ! -e "$BIN_DIR/gitctx" ] || die "verified binary was not removed"
[ ! -e "$BIN_DIR/.gitctx-install-manifest" ] || die "install marker was not removed"
[ "$(sed -n '1p' "$UNINSTALL_RETARGET_VISIBLE/gitctx")" = 'replacement binary' ] || die "later pinned uninstall touched the replacement binary"
[ "$(sed -n '1p' "$UNINSTALL_RETARGET_VISIBLE/.gitctx-install-manifest")" = 'replacement manifest' ] || die "later pinned uninstall touched the replacement manifest"

printf '#!/bin/sh\nexit 0\n' >"$BIN_DIR/gitctx"
chmod 0755 "$BIN_DIR/gitctx"
if "$SCRIPT_DIR/uninstall.sh" --bin-dir "$BIN_DIR" --force >"$WORK_DIR/unrelated.out" 2>"$WORK_DIR/unrelated.err"; then
	die "uninstaller removed an unmarked binary"
fi
[ -e "$BIN_DIR/gitctx" ] || die "uninstaller damaged an unmarked binary"

UNRELATED_BIN_DIR=$WORK_DIR/unrelated-install
mkdir -p "$UNRELATED_BIN_DIR"
printf 'unrelated-content\n' >"$UNRELATED_BIN_DIR/gitctx"
if "$SCRIPT_DIR/install.sh" --bin-dir "$UNRELATED_BIN_DIR" --version 9.8.7-test >"$WORK_DIR/unrelated-install.out" 2>"$WORK_DIR/unrelated-install.err"; then
	die "installer replaced an unrelated binary without --force"
fi
[ "$(sed -n '1p' "$UNRELATED_BIN_DIR/gitctx")" = unrelated-content ] || die "refused install damaged an unrelated binary"

SYMLINK_BIN_DIR=$WORK_DIR/symlink-install
mkdir -p "$SYMLINK_BIN_DIR"
ln -s "$UNRELATED_BIN_DIR/gitctx" "$SYMLINK_BIN_DIR/gitctx"
if "$SCRIPT_DIR/install.sh" --bin-dir "$SYMLINK_BIN_DIR" --version 9.8.7-test --force >"$WORK_DIR/symlink-install.out" 2>"$WORK_DIR/symlink-install.err"; then
	die "installer replaced a symbolic-link target"
fi
[ -L "$SYMLINK_BIN_DIR/gitctx" ] || die "refused install damaged a symbolic-link target"

for BAD_VERSION in '../bad' 'bad version' 'v1.2.3' '1..2'; do
	if "$SCRIPT_DIR/release.sh" --version "$BAD_VERSION" --output-dir "$WORK_DIR/bad-version" >"$WORK_DIR/bad-version.out" 2>"$WORK_DIR/bad-version.err"; then
		die "release accepted unsafe version: $BAD_VERSION"
	fi
done

if "$SCRIPT_DIR/release.sh" --force --output-dir "$WORK_DIR/removed-force" >"$WORK_DIR/removed-force.out" 2>"$WORK_DIR/removed-force.err"; then
	die "release accepted the removed non-transactional --force option"
fi
if "$SCRIPT_DIR/release.sh" --help | grep -q -- '--force'; then
	die "release help still advertises the removed --force option"
fi

REAL_GO=$(command -v go) || die "cannot find Go for release regression tests"
HOST_OS=$($REAL_GO env GOHOSTOS) || die "cannot determine test host operating system"
HOST_ARCH=$($REAL_GO env GOHOSTARCH) || die "cannot determine test host architecture"
GO_WRAPPER_DIR=$WORK_DIR/go-wrapper
mkdir -p "$GO_WRAPPER_DIR"
cat >"$GO_WRAPPER_DIR/go" <<'EOF'
#!/bin/sh
case "${1:-}" in
	build)
		case " $* " in
			*package.go*)
				[ "${GOOS:-}" = "$GITCTX_TEST_HOST_OS" ] || exit 91
				[ "${GOARCH:-}" = "$GITCTX_TEST_HOST_ARCH" ] || exit 92
				case "$GITCTX_TEST_HOST_ARCH" in
					amd64) [ "${GOAMD64:-}" = v1 ] || exit 93 ;;
					arm64) [ "${GOARM64:-}" = v8.0 ] || exit 94 ;;
				esac
				: >"$GITCTX_TEST_READY"
				case "$GITCTX_TEST_MODE" in
					signal)
						kill -TERM "$PPID"
						exit 0
						;;
					retarget)
						while [ ! -e "$GITCTX_TEST_CONTINUE" ]; do
							sleep 0.05
						done
						;;
				esac
				;;
		esac
		;;
esac
exec "$GITCTX_TEST_REAL_GO" "$@"
EOF
chmod 0755 "$GO_WRAPPER_DIR/go"

SIGNAL_OUTPUT=$WORK_DIR/signal-output
SIGNAL_READY=$WORK_DIR/signal-ready
mkdir -p "$SIGNAL_OUTPUT"
if GITCTX_TEST_MODE=signal \
	GITCTX_TEST_READY="$SIGNAL_READY" \
	GITCTX_TEST_CONTINUE=$WORK_DIR/signal-continue \
	GITCTX_TEST_REAL_GO="$REAL_GO" \
	GITCTX_TEST_HOST_OS="$HOST_OS" \
	GITCTX_TEST_HOST_ARCH="$HOST_ARCH" \
	PATH="$GO_WRAPPER_DIR:$PATH" \
	"$SCRIPT_DIR/release.sh" --version 9.8.7-signal --output-dir "$SIGNAL_OUTPUT" >"$WORK_DIR/signal.out" 2>"$WORK_DIR/signal.err"; then
	die "release continued after receiving TERM"
else
	SIGNAL_STATUS=$?
fi
[ "$SIGNAL_STATUS" -eq 143 ] || die "release returned $SIGNAL_STATUS after TERM, expected 143"
[ -e "$SIGNAL_READY" ] || die "signal regression did not reach the host archive-helper build"
[ -z "$(ls -A "$SIGNAL_OUTPUT")" ] || die "terminated release left output artifacts behind"

RETARGET_PARENT=$WORK_DIR/retarget
RETARGET_VISIBLE=$RETARGET_PARENT/output
RETARGET_PINNED=$RETARGET_PARENT/pinned-output
RETARGET_READY=$WORK_DIR/retarget-ready
RETARGET_CONTINUE=$WORK_DIR/retarget-continue
mkdir -p "$RETARGET_VISIBLE"
GITCTX_TEST_MODE=retarget \
	GITCTX_TEST_READY="$RETARGET_READY" \
	GITCTX_TEST_CONTINUE="$RETARGET_CONTINUE" \
	GITCTX_TEST_REAL_GO="$REAL_GO" \
	GITCTX_TEST_HOST_OS="$HOST_OS" \
	GITCTX_TEST_HOST_ARCH="$HOST_ARCH" \
	PATH="$GO_WRAPPER_DIR:$PATH" \
	GOOS=windows \
	GOARCH=386 \
	GOAMD64=v4 \
	GOARM64=v9.9 \
	"$SCRIPT_DIR/release.sh" --version 9.8.7-retarget --output-dir "$RETARGET_VISIBLE" >"$WORK_DIR/retarget.out" 2>"$WORK_DIR/retarget.err" &
RETARGET_PID=$!
RETARGET_ATTEMPTS=0
while [ ! -e "$RETARGET_READY" ]; do
	if ! kill -0 "$RETARGET_PID" 2>/dev/null; then
		wait "$RETARGET_PID" || :
		RETARGET_PID=
		die "retarget regression release exited before its host helper build"
	fi
	RETARGET_ATTEMPTS=$((RETARGET_ATTEMPTS + 1))
	if [ "$RETARGET_ATTEMPTS" -gt 400 ]; then
		: >"$RETARGET_CONTINUE"
		kill -TERM "$RETARGET_PID" 2>/dev/null || :
		wait "$RETARGET_PID" || :
		RETARGET_PID=
		die "timed out waiting for retarget regression release"
	fi
	sleep 0.05
done
mv "$RETARGET_VISIBLE" "$RETARGET_PINNED"
mkdir -p "$RETARGET_VISIBLE"
: >"$RETARGET_CONTINUE"
if wait "$RETARGET_PID"; then
	RETARGET_STATUS=0
else
	RETARGET_STATUS=$?
fi
RETARGET_PID=
[ "$RETARGET_STATUS" -ne 0 ] || die "release published after its requested output pathname was retargeted"
[ -z "$(ls -A "$RETARGET_PINNED")" ] || die "failed retarget release left artifacts in the pinned directory"
[ -z "$(ls -A "$RETARGET_VISIBLE")" ] || die "release followed a retargeted output pathname"
if grep -q 'Created gitctx' "$WORK_DIR/retarget.out"; then
	die "failed retarget release claimed that it created artifacts at a stale pathname"
fi

DIST_DIR=$WORK_DIR/dist
mkdir -p "$DIST_DIR/relative-tmp"
TMPDIR=relative-tmp GOTMPDIR=relative-tmp GO111MODULE=off GOFIPS140=latest GOEXPERIMENT=fieldtrack \
	"$SCRIPT_DIR/release.sh" --version 9.8.7-test --output-dir "$DIST_DIR"
rmdir "$DIST_DIR/relative-tmp" || die "relative TMPDIR release left private build data behind"

for FILE in \
	gitctx-9.8.7-test-darwin-amd64.tar.gz \
	gitctx-9.8.7-test-darwin-arm64.tar.gz \
	gitctx-9.8.7-test-linux-amd64.tar.gz \
	gitctx-9.8.7-test-linux-arm64.tar.gz \
	gitctx-9.8.7-test-windows-amd64.zip \
	gitctx-9.8.7-test-checksums.txt; do
	[ -f "$DIST_DIR/$FILE" ] || die "missing release artifact: $FILE"
done

if "$SCRIPT_DIR/release.sh" --version 9.8.7-test --output-dir "$DIST_DIR" >"$WORK_DIR/release-again.out" 2>"$WORK_DIR/release-again.err"; then
	die "release script overwrote existing artifacts"
fi

CHECKSUM_COUNT=$(wc -l <"$DIST_DIR/gitctx-9.8.7-test-checksums.txt" | tr -d ' ')
[ "$CHECKSUM_COUNT" = 5 ] || die "checksum manifest must contain exactly five archives"

case "$(uname -s)" in
	Darwin)
		(
			cd "$DIST_DIR"
			shasum -a 256 -c gitctx-9.8.7-test-checksums.txt
		) >/dev/null
		;;
	*)
		(
			cd "$DIST_DIR"
			sha256sum -c gitctx-9.8.7-test-checksums.txt
		) >/dev/null
		;;
esac

SECOND_DIST_DIR=$WORK_DIR/dist-second
"$SCRIPT_DIR/release.sh" --version 9.8.7-test --output-dir "$SECOND_DIST_DIR" >/dev/null
for FILE in \
	gitctx-9.8.7-test-darwin-amd64.tar.gz \
	gitctx-9.8.7-test-darwin-arm64.tar.gz \
	gitctx-9.8.7-test-linux-amd64.tar.gz \
	gitctx-9.8.7-test-linux-arm64.tar.gz \
	gitctx-9.8.7-test-windows-amd64.zip \
	gitctx-9.8.7-test-checksums.txt; do
	cmp "$DIST_DIR/$FILE" "$SECOND_DIST_DIR/$FILE" >/dev/null || die "release artifact is not reproducible: $FILE"
done

HOST_ARCHIVE=
case "$HOST_OS/$HOST_ARCH" in
	darwin/amd64) HOST_ARCHIVE=gitctx-9.8.7-test-darwin-amd64.tar.gz ;;
	darwin/arm64) HOST_ARCHIVE=gitctx-9.8.7-test-darwin-arm64.tar.gz ;;
	linux/amd64) HOST_ARCHIVE=gitctx-9.8.7-test-linux-amd64.tar.gz ;;
	linux/arm64) HOST_ARCHIVE=gitctx-9.8.7-test-linux-arm64.tar.gz ;;
esac
if [ -n "$HOST_ARCHIVE" ]; then
	EXTRACT_DIR=$WORK_DIR/extract
	mkdir -p "$EXTRACT_DIR"
	tar -xzf "$DIST_DIR/$HOST_ARCHIVE" -C "$EXTRACT_DIR"
	[ "$("$EXTRACT_DIR/gitctx" version)" = "gitctx 9.8.7-test" ] || die "release binary has the wrong version"
fi

printf 'Release workflow integration test passed.\n'
