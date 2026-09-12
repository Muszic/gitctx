# gitctx

`gitctx` keeps a repository's Git commit identity and authentication context aligned. It is designed for machines where work is the global default but personal or client repositories need their own identity.

The current MVP stores profile metadata, applies profiles to repository-local Git config, supports repository-specific SSH and signing settings, and explains what it can and cannot verify. It never asks for or manages GitHub tokens or passwords; profile fields are intended only for non-secret metadata.

## Install

Building or installing from source requires Go 1.22 or newer. The user-local
installer defaults to `~/.local/bin`, does not
use `sudo`, and never edits shell, Git, SSH, profile, or Git-hosting settings:

```sh
./scripts/install.sh
hash -r
command -v gitctx
gitctx version
```

If `~/.local/bin` is not already on `PATH`, the installer reports that fact but
does not modify a shell startup file automatically. Pass an absolute custom
directory with `--bin-dir <path>`. An existing target or installation marker is
never replaced implicitly; inspect it first and use `--force` only for an
intentional replacement.

The adjacent installation marker records the installed binary's checksum. The
uninstaller verifies that marker before removing exactly the installed binary
and marker:

```sh
./scripts/uninstall.sh
```

Uninstalling the executable deliberately retains profiles, automatic-rule
files, repository configuration, and SSH keys. It never changes global Git or
shell settings. By default, modified or unrecognized installations are refused
for manual review. After reviewing a checksum-mismatched binary, `--force` can
remove it only when the adjacent marker is otherwise valid and the target is a
regular file; it never bypasses missing, malformed, or unsafe markers or targets.

The equivalent default-location Make targets are `make install` and
`make uninstall`. Call the scripts directly with `--bin-dir /absolute/path`
when using a custom location.

## Build from source

```sh
make build
./bin/gitctx version
```

For a simple development build in the project root:

```sh
go build -o ./gitctx ./cmd/gitctx
```

## Quick start

From inside the repository you want to configure, start the guided setup:

```sh
gitctx setup personal
```

The setup flow explains three pieces in plain language: the identity recorded in commits, the SSH key used for pushes, and the key used to sign commits. It detects the repository's default remote and transport, validates identity fields and an existing key before previewing the plan, then applies the repository settings. SSH authentication and signing stay limited to the target repository. If that profile already has automatic identity rules, setup discloses and synchronizes their name/email snapshots after confirmation. Global work identity and signing defaults stay unchanged. The profile itself is saved in gitctx's user configuration. Key generation happens in a protected temporary directory; after validation, the finished key pair is moved to the destination shown in the preview. In an interactive terminal, `gitctx setup` without a profile name suggests `personal`. Use `--repo <path>` to configure a different repository.

When a saved profile already exists, setup offers to apply it unchanged, edit and apply it, or cancel. When an edited profile is also used by automatic directory rules, the preview lists those directories and setup synchronizes their identity snapshots too.

Authentication has three choices:

- `generate` creates a new Ed25519 SSH key pair without overwriting existing files, with a suggested path of `~/.ssh/id_ed25519_gitctx_<profile>`. `ssh-keygen` asks for the passphrase directly.
- `existing` uses a private key you already have and validates it against the adjacent matching `<private-key>.pub` file.
- `identity-only` applies the commit identity without managing or verifying push authentication.

With generated or existing SSH authentication, setup also requires an explicit signing choice: `same-key` enables repository-local SSH commit signing with that key's public half, while `disabled` installs a local guard that blocks automatic signing and a bare `git commit -S` from falling back to an inherited work key. Identity-only setup uses the guarded policy. gitctx also pins the resolved SSH signing executable and its SHA-256 integrity marker in repository-local config, so an inherited custom signer or later executable replacement cannot silently substitute another key. Like any local Git setting, the guard can still be replaced by a deliberate command-scoped `git -c ...` override. Existing global work identity and signing values are preserved. Explicit SSH/signing settings are local to the selected repository; when existing automatic rules use the profile, their identity snapshots are refreshed as shown in the preview.

To avoid accidental cross-account key reuse, setup refuses an authentication key that matches the inherited signing key unless you intentionally pass `--allow-key-reuse`; that override is reported as a warning.

For either SSH option, setup prints the public-key path, fingerprint, a platform-appropriate copy command, and account-registration links for the detected hosts. Register that public key manually with every intended Git hosting account. GitHub requires one Authentication Key entry and, when using `same-key`, a second Signing Key entry for the same public key. Other hosts may use a different signing-registration model. gitctx never uploads the key or opens a browser automatically.

If a default push destination is configured, the SSH options require every push URL to use SSH. An HTTPS remote is identified before key questions; setup shows the exact SSH conversion command only when it can derive the same known-provider repository URL safely. gitctx never rewrites the remote itself.

After setup, inspect the selected context and its local verification results:

```sh
gitctx current
gitctx doctor
```

`doctor` is intentionally offline. After registering the public key and configuring an SSH remote, run the opt-in live check:

```sh
gitctx verify
```

`verify` first requires the local profile checks to be safe, then runs a bounded, non-interactive, read-only `git ls-remote` against every effective SSH push URL using only the repository-managed key. It preserves strict host-key verification and will not add or update `known_hosts`; a host must already be trusted. A passphrase-protected key must be available through `ssh-agent`. Success proves that the key can read the configured remotes at that moment. It does not push, prove write permission, or prove which hosting account owns the key.

To reuse the saved profile in another repository, run `gitctx use personal` there. To select only its commit identity automatically for conventional repositories below a directory, use `gitctx auto add <directory> personal` as described below.

For manual, non-interactive profile creation, use `add`:

```sh
gitctx add personal \
  --name "Sangeet" \
  --email "personal@example.com" \
  --github "sangeet" \
  --ssh-key ~/.ssh/id_ed25519_personal
```

Then apply it from inside a repository:

```sh
gitctx use personal
```

This writes `user.name`, `user.email`, and a profile marker to that repository's local Git config. When the profile has an SSH key, it also sets a repository-local `core.sshCommand` that allows public-key authentication only, selects that one identity, and disables SSH config files so another configured key cannot be tried as a fallback. A signing key is similarly scoped to that repository.

Inspect and verify the result:

```sh
gitctx current
gitctx doctor
```

`doctor` compares effective author and committer settings with the selected profile. For an SSH profile it validates the private-key file with `ssh-keygen`, detects SSH environment overrides, resolves Git's effective default push remote, and checks all of that remote's push URLs. Authentication managed by an external HTTPS credential helper or a globally active `gh` account is reported as unverified rather than assumed safe.

To select a commit identity automatically by directory while keeping work as the global default:

```sh
gitctx auto add ~/personal personal
```

Automatic rules use Git's `includeIf` support and require Git 2.30 or newer. They do not replace global `user.name` or `user.email`. Each sync writes a new immutable snapshot, activates it at the end of the global settings, and only then removes the previous include, so concurrent Git readers do not see a half-written rule set or an identity gap. Old snapshots are retained because a Git process may still be reading them, and they can contain previous profile names and emails. After removing every automatic rule and completing `gitctx auto sync`, the generated `stores/.../generations` directories can be deleted manually if that history should not remain on disk. Automatic rules select identity only; run `gitctx use personal` inside a repository when its SSH or signing key should also be applied. Filesystem-root rules and directory names containing Git pattern metacharacters (`*`, `?`, `[`, `]`, or a literal backslash) are rejected in v0.1.

`gitctx auto list` shows the saved rules and verifies that Git's active generated snapshot still matches them. A visible warning tells you to run `gitctx auto sync` if an update was interrupted or a generated file was removed or changed.

Git evaluates `includeIf gitdir` against repository metadata, not the visible working-tree path. The v0.1 pattern is intentionally narrow: it matches metadata directories ending exactly in `.git` below the selected directory. This covers conventional repositories with their own `.git` directory and normally leaves linked worktrees, submodules, bare repositories, and separately stored Git directories on the usual global identity. A specially arranged separate Git directory that is itself named `.git` below the selected directory can still match even when its working tree is elsewhere; Git's conditional-include mechanism cannot prove that those two locations are colocated. Avoid automatic rules for such repository layouts and use `gitctx current` or `gitctx doctor` before committing when the topology is uncertain.

## Commands

```text
gitctx setup <profile> [options]
gitctx add <profile> [options]
gitctx list [--json]
gitctx use <profile> [--repo <path>] [--json]
gitctx current [--repo <path>] [--json]
gitctx doctor [--repo <path>] [--strict] [--json]
gitctx verify [--repo <path>] [--json]
gitctx fix [--repo <path>] [--json]
gitctx auto add <directory> <profile> [--force] [--json]
gitctx auto list [--json]
gitctx auto remove <directory> [--json]
gitctx auto sync [--json]
```

`status` is an alias for `current`, and running `gitctx` without arguments shows the current repository context. Within a command, options can appear before or after positional arguments; options are placed after the command name. Every command that reads or writes profiles accepts `--config <path>`; `GITCTX_CONFIG` provides the same override through the environment. Help and version output are plain text rather than JSON.

Every core command supports JSON output for a future editor integration:

```sh
gitctx current --json
gitctx doctor --json
```

`setup --json` is fully non-interactive and requires `--name`, `--email`, `--auth`, and `--signing` (plus `--ssh-key` for `--auth existing`). It refuses `--auth generate` because `ssh-keygen` needs an interactive passphrase prompt. Create the key pair outside JSON mode, then select it with `--auth existing --ssh-key <private-key-path>`; add `--force` when replacing an existing profile.

JSON responses use a versioned envelope with `command`, `ok`, and either `data` or `error`. `ok: true` means the command completed and returned structured data; it does not by itself mean the reported repository state is healthy. `setup`, `doctor`, `verify`, `use`, and `fix` can therefore return `ok: true` data while exiting with status `1` for an unsafe or not-ready result. A successful `verify` has `data.status` set to `ready`; a completed failed check uses `not_ready` plus a structured `reason`. Warnings exit successfully unless `doctor --strict` is used. Invalid usage exits `2`; missing profiles, rules, and profile-state conflicts exit `3`; Git failures exit `4`; and configuration failures exit `5`.

## Profile storage

Profiles contain only:

- Git author name and email
- optional GitHub username metadata
- optional SSH private-key path and public-key fingerprint
- optional signing-key identifier with its required format, or an explicit guarded-signing policy

The profile store contains key paths and fingerprints, not private- or public-key contents.

The config file lives in the operating system's user config directory under `gitctx/config.json`. On macOS that is normally `~/Library/Application Support/gitctx/config.json`. `XDG_CONFIG_HOME` is respected when set. When `GIT_CONFIG_GLOBAL` is used with automatic rules, it must name an absolute path.

## Scope and safety

Version 0.1 supports repository isolation through local Git configuration and SSH. Its supported targets are macOS and Linux, and it requires Git 2.30 or newer plus `ssh-keygen` when SSH profiles are used. Windows builds are experimental because Windows ACL protection and atomic file-replacement behavior are not yet verified. For strict key isolation, an applied SSH profile ignores user and system SSH config; use a fully qualified host in the Git remote rather than an SSH `Host` alias, and note that custom proxy and port settings are not inherited. Unix file modes are checked for private-key exposure. Literal `${` is rejected in SSH-key paths because OpenSSH may treat it as environment-variable syntax. It does not perform browser login, manage credentials, rewrite remotes, or switch the machine-wide active `gh` account. Offline checks validate a resolvable named default push remote; `verify` is the explicit live connectivity check. Direct URL selectors are reported as unverifiable, and an explicitly supplied destination such as `git push other-remote` is outside that check. The optional `auto` feature changes global Git config only through its generated include and short-lived staging section; unrelated includes and global identity values are preserved.

gitctx trusts the `git`, `ssh`, and initial `ssh-keygen` executables resolved from the environment in which it runs, just as Git and OpenSSH normally do. Run setup and profile application from a trusted shell with a trusted `PATH`. The signing-program integrity marker detects replacement after gitctx selects the executable; it cannot prove that an executable was benign before that initial selection.

Existing repository-local SSH and signing settings—including `gpg.ssh.program`—are restored when a later profile stops managing them. Updates are serialized and a failed multi-key change is rolled back. If a managed value or pinned signing executable changes, `current` and `doctor` report the mismatch; after reviewing a legitimate executable update, run `gitctx fix` to accept and pin the current resolved `ssh-keygen`. If a repository-local managed value itself was manually edited, gitctx refuses to overwrite or remove it; inspect it with `doctor` before cleaning up stale local settings. `fix` repairs only an explicitly pinned local profile; for an automatically selected identity, use `auto sync` or explicitly `use` the profile to pin it. Git's local config is shared by linked worktrees, so v0.1 refuses explicit profile application in repositories with multiple worktrees. If another linked worktree is created after a profile was applied, `current` and `doctor` mark that shared local profile unsafe.

Only one profile store's automatic rules may be active at a time. Disable the first store before enabling a portable or alternate `--config` store. Before moving the profile store to a different directory, remove its automatic rules; if it has already moved, keep or recreate the old config-file path as a symlink to the new file and run `gitctx auto sync` or `gitctx auto remove` through that old path once. gitctx fails closed when it detects an active manifest whose ownership it cannot establish.

The MVP uses small lock files while changing its profile store or repository settings. If a process is force-quit or interrupted during a mutation, a later command may time out and print the exact leftover lock path. After confirming that no `gitctx` process is running, remove only that reported lock file and retry.

Guided browser login, automatic key upload, remote rewriting, hooks, and the VS Code extension are later milestones. The versioned JSON output is the intended integration surface for that extension.

## Automated checks

GitHub Actions runs the test suite on Linux, macOS, and Windows for every pull
request targeting `main` and every push to `main`. Linux also runs the race
detector, `go vet`, the module-file check, and the full installer/release
contract. The release contract runs on macOS as well. Pull-request jobs receive
a read-only token and do not receive release permissions.

The workflow uses Go 1.22.12 to preserve the documented minimum-version check
and Go 1.27.1 for current builds. Release binaries are built only with the
explicitly pinned, supported Go 1.27.1 toolchain; the runner's preinstalled Go
version is not used implicitly.

## Build release artifacts

Create version-injected local archives for macOS and Linux on `amd64` and
`arm64`, plus the experimental Windows `amd64` build:

```sh
make release VERSION=0.1.0
```

The command writes normalized `.tar.gz` and `.zip` archives plus a SHA-256
checksum manifest under `dist/`. Existing release files are refused unless an
empty output directory is selected or those exact old artifacts are removed
first; release replacement has no force mode. This local command does not
publish, upload, sign, tag, or change Git configuration.
Checksums detect accidental corruption; they do not authenticate a publisher.

Run the end-to-end installer and release test with:

```sh
./scripts/test-release.sh
```

## Publish a private release

The release workflow runs only when an intentional tag in canonical
`vMAJOR.MINOR.PATCH` form is pushed. The tagged commit must already be contained
in `origin/main`. The workflow retests that exact commit, creates and verifies
the six expected artifacts, stages a draft GitHub Release, checks the asset
count, and only then publishes it. Build and test steps run with read-only
permissions. Only the final publication job receives `contents: write`; it
downloads the exact staged artifact, rechecks it, does not check out source,
and does not execute a built binary.

For example, after CI has passed on `main`:

```sh
git switch main
git pull --ff-only
git tag -s v0.1.0 -m "gitctx v0.1.0"
git push origin v0.1.0
```

The tag command above creates a signed tag using the signing identity selected
for this repository. Pushing the tag publishes downloadable archives in this
repository's GitHub Releases page; it does not make a private repository or its
assets public. No tag or release is created merely by pushing an ordinary
commit. The publisher re-resolves the remote tag immediately before creating
the draft and again before publication. Before the first release, protect `v*`
tags from force updates or deletion and enable immutable releases in the GitHub
repository settings to enforce that boundary on the server too.

This repository does not yet contain a software license. Choose and add one
before distributing public release archives.

## Development

Tests use temporary repositories with global and system Git configuration disabled.

```sh
make check
./scripts/test-release.sh
```
