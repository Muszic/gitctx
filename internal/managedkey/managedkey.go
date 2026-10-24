// Package managedkey keeps generated SSH keys encrypted on disk, with random
// passphrases held only by the operating system's password vault. It adds only
// the chosen key to the existing session agent; it never removes other keys,
// starts/replaces a user's agent, or changes global SSH/Git configuration.
package managedkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gitctx/internal/profile"
	"gitctx/internal/sshkey"
)

type vault interface {
	put(string, string) error
	get(string) (string, error)
}

type Manager struct{ vault vault }
type Key struct {
	ID   string
	Pair sshkey.Pair
}

func New() *Manager { return &Manager{} }

// Preflight does not write a credential or change the agent. Unsupported or
// unavailable secure storage fails before browser authorization or key upload.
func (m *Manager) Preflight() error {
	if m.vault == nil {
		switch runtime.GOOS {
		case "darwin":
			if _, err := os.Stat("/usr/bin/security"); err != nil {
				return errors.New("macOS Keychain is unavailable")
			}
			m.vault = commandVault{program: "/usr/bin/security", mac: true}
		case "linux":
			program, err := exec.LookPath("secret-tool")
			if err != nil || os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
				return errors.New("native login requires a running desktop Secret Service and secret-tool; no plaintext fallback is used; advanced setup remains available")
			}
			m.vault = commandVault{program: program}
		default:
			return errors.New("native secure-key login is supported on macOS and Linux desktop sessions; use advanced setup on this platform")
		}
	}
	for _, program := range []string{"ssh-keygen", "ssh-add"} {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("native login requires %s", program)
		}
	}
	_, err := agentContains("")
	return err
}

func (m *Manager) Create(name, configPath string) (Key, error) {
	if err := profile.ValidateName(name); err != nil {
		return Key{}, err
	}
	if m.vault == nil {
		return Key{}, errors.New("secure storage must be checked before key creation")
	}
	base := filepath.Join(filepath.Dir(configPath), "keys")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return Key{}, errors.New("cannot create the managed key directory")
	}
	if err := protectedDirectory(base); err != nil {
		return Key{}, err
	}
	id, err := randomHex(16)
	if err != nil {
		return Key{}, err
	}
	secret, err := randomHex(32)
	if err != nil {
		return Key{}, err
	}
	if err := m.vault.put(id, secret); err != nil {
		return Key{}, err
	}
	stored, err := m.vault.get(id)
	if err != nil {
		return Key{}, fmt.Errorf("could not verify secure passphrase storage; no SSH key was generated: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(stored)) != 1 {
		return Key{}, errors.New("could not verify secure passphrase storage: the saved value did not match; no SSH key was generated")
	}
	// The approved read-back is reused only for this operation. OpenSSH gets
	// it over private local IPC, not another vault read or a plaintext file.
	helper, cleanup, err := newAskpassRelay(stored, 2)
	if err != nil {
		return Key{}, err
	}
	defer cleanup()
	pair, err := sshkey.GenerateWithAskpass(name, filepath.Join(base, id), helper, askpassEnvironment(helper))
	if err != nil {
		return Key{}, errors.New("encrypted SSH key generation failed; secure storage was retained; no public key was uploaded")
	}
	// Load with the same approved value, so login's subsequent Unlock finds
	// this exact key already in the agent without another vault prompt.
	if err := loadIntoAgent(pair, stored); err != nil {
		// Return non-secret metadata too, allowing login to persist this same
		// encrypted key as pending instead of generating another on retry.
		return Key{ID: id, Pair: pair}, fmt.Errorf("the encrypted key and vault record were retained, but its agent unlock failed; no public key was uploaded: %w", err)
	}
	return Key{ID: id, Pair: pair}, nil
}

// Unlock adds just this validated key. Work keys already in the agent remain.
func (m *Manager) Unlock(selected profile.Profile) error {
	if selected.ManagedKeyID == "" {
		return nil
	}
	if err := selected.Validate(); err != nil {
		return err
	}
	pair, err := sshkey.InspectPair(selected.SSHKey)
	if err != nil || pair.Fingerprint != selected.SSHFingerprint {
		return errors.New("the managed SSH key no longer matches its saved fingerprint; no agent key was added")
	}
	base := filepath.Dir(pair.PrivatePath)
	if err := protectedDirectory(base); err != nil {
		return err
	}
	// Never bypass on-disk key validation or match a key mentioned only in an
	// agent comment. A loaded, fingerprint-matched key needs no vault access.
	loaded, err := agentContains(pair.Fingerprint)
	if err != nil {
		return err
	}
	if loaded {
		return nil
	}
	if err := m.Preflight(); err != nil {
		return err
	}
	secret, err := m.vault.get(selected.ManagedKeyID)
	if err != nil {
		return fmt.Errorf("could not unlock the managed passphrase; the key was not replaced: %w", err)
	}
	if !validHex(secret, 64) {
		return errors.New("the managed passphrase is unavailable in the OS password vault; unlock the vault and retry; the key was not replaced")
	}
	return loadIntoAgent(pair, secret)
}

func loadIntoAgent(pair sshkey.Pair, secret string) error {
	helper, cleanup, err := newAskpassRelay(secret, 1)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := vaultApprovalContext()
	defer cancel()
	command := exec.CommandContext(ctx, "ssh-add", pair.PrivatePath)
	command.Env = askpassEnvironment(helper)
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("timed out waiting for OS vault approval to unlock this SSH key; retry and answer the vault prompt; other agent keys were kept")
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return errors.New("SSH key unlock was cancelled; other agent keys were kept")
		}
		return errors.New("the OS vault could not unlock this key into the existing SSH agent; unlock the vault and retry 'gitctx use'; other keys were kept")
	}
	loaded, err := agentContains(pair.Fingerprint)
	if err != nil || !loaded {
		return errors.New("the SSH agent did not retain the selected key; other keys were kept; retry when the agent is available")
	}
	return nil
}

func agentContains(fingerprint string) (bool, error) {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return false, errors.New("no SSH session agent is available; start your desktop SSH agent before login; gitctx will not replace your work agent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "ssh-add", "-l", "-E", "sha256")
	command.WaitDelay = time.Second
	command.Env = askpassEnvironment("")
	output := boundedOutput{limit: 64 * 1024}
	command.Stdout = &output
	err := command.Run()
	if err != nil {
		var exit *exec.ExitError
		if ctx.Err() == nil && errors.As(err, &exit) && exit.ExitCode() == 1 {
			return false, nil // Empty, but usable, agent.
		}
		return false, errors.New("the SSH session agent is unavailable; unlock/start your existing agent and retry; no other agent keys were changed")
	}
	return agentListingContains(output.String(), fingerprint), nil
}

func agentListingContains(listing, fingerprint string) bool {
	if fingerprint == "" {
		return false
	}
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == fingerprint {
			return true
		}
	}
	return false
}

func askpassEnvironment(helper string) []string {
	var env []string
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		if name != "SSH_ASKPASS" && name != "SSH_ASKPASS_REQUIRE" {
			env = append(env, variable)
		}
	}
	if helper == "" {
		return append(env, "SSH_ASKPASS_REQUIRE=never")
	}
	env = append(env, "SSH_ASKPASS="+helper, "SSH_ASKPASS_REQUIRE=force")
	if os.Getenv("DISPLAY") == "" {
		env = append(env, "DISPLAY=gitctx:0")
	}
	return env
}

func protectedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("managed keys require an owner-only, non-symlink directory (mode 0700)")
	}
	return checkOwner(info)
}

func randomHex(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("secure randomness is unavailable")
	}
	return hex.EncodeToString(value), nil
}

func validHex(value string, length int) bool {
	return len(value) == length && strings.Trim(value, "0123456789abcdef") == ""
}

type commandVault struct {
	program string
	mac     bool
}

func (v commandVault) put(id, secret string) error {
	if !validHex(id, 32) || !validHex(secret, 64) {
		return errors.New("invalid managed vault record")
	}
	var args []string
	input := secret
	if v.mac {
		// Interactive security commands are delivered on a pipe, NOT argv. -T
		// "" removes security's implicit trusted-app access; the OS can ask the
		// user to approve reads. Never use -A or update an existing item with -U.
		args = []string{"-i"}
		input = "add-generic-password -a " + id + " -s gitctx.ssh-passphrase -T \"\" -w " + secret + "\n"
	} else {
		args = []string{"store", "--label=gitctx encrypted SSH key", "application", "gitctx", "key-id", id}
	}
	if _, err := vaultCommand(v.program, args, input); err != nil {
		return fmt.Errorf("the OS password vault could not store the passphrase; no plaintext fallback was used: %w", err)
	}
	return nil
}

func (v commandVault) get(id string) (string, error) {
	if !validHex(id, 32) {
		return "", errors.New("invalid vault identifier")
	}
	var args []string
	if v.mac {
		args = []string{"find-generic-password", "-a", id, "-s", "gitctx.ssh-passphrase", "-w"}
	} else {
		args = []string{"lookup", "application", "gitctx", "key-id", id}
	}
	output, err := vaultCommand(v.program, args, "")
	if err != nil {
		return "", fmt.Errorf("cannot read the managed passphrase from the OS vault: %w", err)
	}
	value := strings.TrimSpace(string(output))
	if !validHex(value, 64) {
		return "", errors.New("the OS vault returned an invalid managed passphrase; its value was not displayed")
	}
	return value, nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

var errVaultTimeout = errors.New("timed out waiting for OS password vault approval; retry and answer the vault prompt (on macOS, use the login keychain password, not the SSH passphrase or GitHub password)")
var errVaultCancelled = errors.New("OS password vault access was cancelled; retry when ready to approve the vault prompt")
var errVaultAccess = errors.New("OS password vault access failed or was not granted; unlock the vault and approve its prompt (on macOS, use the login keychain password, not the SSH passphrase or GitHub password)")

func vaultCommand(program string, args []string, input string) ([]byte, error) {
	ctx, cancel := vaultApprovalContext()
	defer cancel()
	return vaultCommandContext(ctx, program, args, input)
}

func vaultApprovalContext() (context.Context, context.CancelFunc) {
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	ctx, cancel := context.WithTimeout(parent, sshkey.ManagedKeyPromptTimeout)
	return ctx, func() { cancel(); stop() }
}

func vaultCommandContext(ctx context.Context, program string, args []string, input string) ([]byte, error) {
	command := exec.CommandContext(ctx, program, args...)
	command.WaitDelay = time.Second
	command.Stdin = strings.NewReader(input)
	var output boundedOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		// Never include subprocess output or the supplied secret in an error.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errVaultTimeout
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, errVaultCancelled
		}
		return nil, errVaultAccess
	}
	return output.Bytes(), nil
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(value []byte) (int, error) {
	limit := b.limit
	if limit == 0 {
		limit = 4096
	}
	if b.Len()+len(value) > limit {
		return 0, errors.New("vault response exceeded its limit")
	}
	return b.Buffer.Write(value)
}
