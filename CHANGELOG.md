# Changelog

## 0.2.0 — 2026-10-25

### Browser-based onboarding

- Add `gitctx login [profile]` to register a reusable GitHub account from any
  directory, without installing GitHub CLI or copying SSH keys manually.
- Authorize through GitHub's device flow, verify the intended account, and
  automatically register the public key for authentication and commit signing.
- Default to the account's private GitHub noreply commit email.
- Generate a separate encrypted Ed25519 key and protect its random passphrase
  with macOS Keychain or Linux Secret Service. No GitHub token is saved.

### Fewer password prompts

- Reuse a fingerprint-matched key already loaded in the existing SSH agent,
  without reading Keychain again on repeated login/profile selection.
- Use one approved vault read when generating/loading or unlocking a key;
  briefly pass it to OpenSSH through owner-only local IPC, never plaintext
  files, command arguments, or environment variables.
- Allow five minutes for local vault approval, support cancellation, and
  explain that macOS needs the login keychain password rather than an SSH or
  GitHub password.

### Safety and distribution

- Pin native profiles to the authenticated numeric GitHub account ID.
- Preserve pending keys for safe retry and refuse incomplete registrations
  before repository changes.
- Preserve existing manual profiles, work-agent keys, global Git settings,
  GitHub CLI accounts, and repository remotes.
- Embed the distributor's public OAuth Client ID in release downloads and
  refuse release publication without its configuration.
- Add the MIT license and include it in every platform archive.

### Requirements and limits

Native login supports macOS and Linux desktop sessions with Git/OpenSSH, an
existing SSH agent, and a working OS password vault. Linux additionally needs
`secret-tool` and Secret Service. Windows binaries remain experimental;
native browser/vault login is not supported there. Advanced setup remains
available. SSH remotes and trusted host keys are required. `verify` checks read
access; it does not prove write permission, key ownership, or organization SSO.

Existing v0.1.0 downloads do not include native browser login. Existing
profiles and keys are retained; use a new profile name for native login rather
than replacing a manually managed profile.
