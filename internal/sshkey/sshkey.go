// Package sshkey safely creates and inspects SSH key pairs used by gitctx.
package sshkey

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"gitctx/internal/filelock"
	"gitctx/internal/profile"
)

// Pair identifies a validated SSH private/public key pair. Fingerprint is the
// canonical SHA256 fingerprint reported by OpenSSH for both files.
type Pair struct {
	PrivatePath string `json:"private_path"`
	PublicPath  string `json:"public_path"`
	Fingerprint string `json:"fingerprint"`
}

// ManagedKeyPromptTimeout leaves time for a person to answer an OS password
// vault prompt. It bounds local key operations, not network requests.
const ManagedKeyPromptTimeout = 5 * time.Minute

// DefaultPath returns the default private-key path for a profile.
func DefaultPath(profileName string) (string, error) {
	if err := profile.ValidateName(profileName); err != nil {
		return "", err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".ssh", "id_ed25519_gitctx_"+profileName), nil
}

// Generate creates a new Ed25519 key pair without ever overwriting an existing
// private key, public key, or symbolic link. ssh-keygen owns the supplied
// streams so that it can securely perform any passphrase prompting itself.
func Generate(profileName, destination string, stdin io.Reader, stdout, stderr io.Writer) (Pair, error) {
	return generate(profileName, destination, stdin, stdout, stderr, systemExecutor{})
}

// InspectPair validates an existing private key and its adjacent .pub file,
// returning canonical absolute paths and their shared SHA256 fingerprint.
func InspectPair(privatePath string) (Pair, error) {
	return inspectPair(privatePath, systemExecutor{})
}

// Fingerprint returns the canonical SHA256 fingerprint of one stable private
// or public SSH key file, or of Git's key::<public-key> inline SSH form. It is
// useful for comparing an inherited signing key with a proposed authentication
// key without exposing key contents.
func Fingerprint(path string) (string, error) {
	if strings.HasPrefix(path, "key::") {
		literal := strings.TrimSpace(strings.TrimPrefix(path, "key::"))
		if literal == "" || len(literal) > 16*1024 || strings.IndexFunc(literal, unicode.IsControl) >= 0 {
			return "", fmt.Errorf("inline SSH signing key is empty or malformed")
		}
		command := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", "-")
		command.Stdin = strings.NewReader(literal + "\n")
		output, err := command.Output()
		if err != nil {
			return "", fmt.Errorf("ssh-keygen could not read inline SSH signing key: %w", err)
		}
		return fingerprintFromOutput(output, "inline SSH signing key")
	}
	resolved, err := resolvePath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect SSH key %s: %w", resolved, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err = filepath.EvalSymlinks(resolved)
		if err != nil {
			return "", fmt.Errorf("resolve SSH key symbolic link: %w", err)
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return "", fmt.Errorf("resolve SSH key path: %w", err)
		}
		info, err = os.Lstat(resolved)
		if err != nil {
			return "", fmt.Errorf("inspect resolved SSH key %s: %w", resolved, err)
		}
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("SSH key %s is not a regular file", resolved)
	}
	value, err := fingerprint(resolved, systemExecutor{})
	if err != nil {
		return "", err
	}
	if err := requireSameFile(resolved, info, "SSH key changed during fingerprint inspection"); err != nil {
		return "", err
	}
	return value, nil
}

type executor interface {
	Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error
	Output(args []string) ([]byte, error)
}

type systemExecutor struct{ env []string }

func (runner systemExecutor) Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	command := exec.Command("ssh-keygen", args...)
	if runner.env != nil {
		parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		ctx, cancel := context.WithTimeout(parent, ManagedKeyPromptTimeout)
		defer cancel()
		command = exec.CommandContext(ctx, "ssh-keygen", args...)
		command.WaitDelay = time.Second
	}
	command.Env = runner.env
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

// GenerateWithAskpass creates an encrypted key using a private, non-secret
// askpass helper that receives an approved, in-memory random passphrase. The
// passphrase never appears in process arguments or the profile store.
func GenerateWithAskpass(profileName, destination, helper string, env []string) (Pair, error) {
	if helper == "" || !filepath.IsAbs(helper) {
		return Pair{}, errors.New("an absolute managed askpass helper is required")
	}
	return generate(profileName, destination, nil, io.Discard, io.Discard, systemExecutor{env: env})
}

func (systemExecutor) Output(args []string) ([]byte, error) {
	command := exec.Command("ssh-keygen", args...)
	return command.Output()
}

func generate(profileName, destination string, stdin io.Reader, stdout, stderr io.Writer, runner executor) (pair Pair, err error) {
	if err := profile.ValidateName(profileName); err != nil {
		return Pair{}, err
	}
	if runner == nil {
		return Pair{}, fmt.Errorf("SSH key generator is required")
	}
	if destination == "" {
		destination, err = DefaultPath(profileName)
		if err != nil {
			return Pair{}, err
		}
	}
	destination, err = prepareDestination(destination)
	if err != nil {
		return Pair{}, err
	}
	publicPath := destination + ".pub"

	lock, err := filelock.Acquire(destination+".gitctx-generate.lock", 10*time.Second)
	if err != nil {
		return Pair{}, fmt.Errorf("serialize SSH key generation: %w", err)
	}
	defer func() {
		if releaseErr := lock.Release(); releaseErr != nil {
			err = errors.Join(err, fmt.Errorf("release SSH key generation lock: %w", releaseErr))
		}
	}()

	if err := requireMissing(destination, "private key"); err != nil {
		return Pair{}, err
	}
	if err := requireMissing(publicPath, "public key"); err != nil {
		return Pair{}, err
	}

	tempDir, err := os.MkdirTemp(filepath.Dir(destination), ".gitctx-keygen-*")
	if err != nil {
		return Pair{}, fmt.Errorf("create SSH key staging directory: %w", err)
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return Pair{}, fmt.Errorf("protect SSH key staging directory: %w", err)
	}
	tempPrivate := filepath.Join(tempDir, "key")
	args := []string{"-q", "-t", "ed25519", "-f", tempPrivate, "-C", "gitctx:" + profileName}
	if err := runner.Run(args, stdin, stdout, stderr); err != nil {
		return Pair{}, fmt.Errorf("generate SSH key: %w", err)
	}
	tempPublic := tempPrivate + ".pub"
	if err := requireRegularNoSymlink(tempPrivate, "generated private key"); err != nil {
		return Pair{}, err
	}
	if err := requireRegularNoSymlink(tempPublic, "generated public key"); err != nil {
		return Pair{}, err
	}
	if err := os.Chmod(tempPrivate, 0o600); err != nil {
		return Pair{}, fmt.Errorf("protect generated private key: %w", err)
	}
	if err := os.Chmod(tempPublic, 0o644); err != nil {
		return Pair{}, fmt.Errorf("protect generated public key: %w", err)
	}
	if _, err := inspectPair(tempPrivate, runner); err != nil {
		return Pair{}, fmt.Errorf("validate generated SSH key pair: %w", err)
	}
	if err := syncFile(tempPrivate); err != nil {
		return Pair{}, err
	}
	if err := syncFile(tempPublic); err != nil {
		return Pair{}, err
	}

	// Publish the public key first and the private key last. Hard links provide
	// atomic no-clobber behavior on the destination filesystem. If publishing
	// the private key fails, cleanup removes the public link only when it still
	// names the staging inode created by this invocation.
	if err := os.Link(tempPublic, publicPath); err != nil {
		return Pair{}, fmt.Errorf("publish public key without overwriting %s: %w", publicPath, err)
	}
	publishedPublic := true
	defer func() {
		if err != nil && publishedPublic {
			_ = removeIfSameFile(publicPath, tempPublic)
		}
	}()
	if err := os.Link(tempPrivate, destination); err != nil {
		return Pair{}, fmt.Errorf("publish private key without overwriting %s: %w", destination, err)
	}
	publishedPrivate := true
	defer func() {
		if err != nil && publishedPrivate {
			_ = removeIfSameFile(destination, tempPrivate)
		}
	}()
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return Pair{}, err
	}

	pair, err = inspectPair(destination, runner)
	if err != nil {
		return Pair{}, fmt.Errorf("verify published SSH key pair: %w", err)
	}
	publishedPublic = false
	publishedPrivate = false
	return pair, nil
}

func prepareDestination(path string) (string, error) {
	resolved, err := resolvePath(path)
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(strings.ToLower(resolved), ".pub") {
		return "", fmt.Errorf("SSH private-key destination must not end in .pub")
	}
	if strings.Contains(resolved, "${") {
		return "", fmt.Errorf("SSH key path contains unsupported OpenSSH environment-variable syntax '${'")
	}
	if filepath.Base(resolved) == "." || filepath.Base(resolved) == string(filepath.Separator) {
		return "", fmt.Errorf("SSH private-key destination must name a file")
	}
	parent := filepath.Dir(resolved)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create SSH key directory %s: %w", parent, err)
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return "", fmt.Errorf("inspect SSH key directory %s: %w", parent, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("SSH key directory %s must be a real directory, not a symbolic link", parent)
	}
	if err := checkOwnedByCurrentUser(parent, info); err != nil {
		return "", err
	}
	if posixPermissionChecks && info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("SSH key directory %s has permissions %04o; it must not be writable by group or others", parent, info.Mode().Perm())
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("canonicalize SSH key directory %s: %w", parent, err)
	}
	canonicalParent, err = filepath.Abs(canonicalParent)
	if err != nil {
		return "", fmt.Errorf("resolve SSH key directory %s: %w", canonicalParent, err)
	}
	return filepath.Join(canonicalParent, filepath.Base(resolved)), nil
}

func inspectPair(privatePath string, runner executor) (Pair, error) {
	if runner == nil {
		return Pair{}, fmt.Errorf("SSH key inspector is required")
	}
	privatePath, privateInfo, err := canonicalPrivatePath(privatePath)
	if err != nil {
		return Pair{}, err
	}
	if err := validatePrivateFile(privatePath, privateInfo); err != nil {
		return Pair{}, err
	}
	publicPath := privatePath + ".pub"
	publicInfo, err := os.Lstat(publicPath)
	if err != nil {
		return Pair{}, fmt.Errorf("inspect public key %s: %w", publicPath, err)
	}
	if publicInfo.Mode()&os.ModeSymlink != 0 || !publicInfo.Mode().IsRegular() {
		return Pair{}, fmt.Errorf("public key %s is not a regular non-symbolic-link file", publicPath)
	}
	if err := checkOwnedByCurrentUser(publicPath, publicInfo); err != nil {
		return Pair{}, err
	}
	if posixPermissionChecks && publicInfo.Mode().Perm()&0o022 != 0 {
		return Pair{}, fmt.Errorf("public key %s has permissions %04o; it must not be writable by group or others", publicPath, publicInfo.Mode().Perm())
	}

	privateFingerprint, err := fingerprint(privatePath, runner)
	if err != nil {
		return Pair{}, fmt.Errorf("inspect private-key fingerprint: %w", err)
	}
	publicFingerprint, err := fingerprint(publicPath, runner)
	if err != nil {
		return Pair{}, fmt.Errorf("inspect public-key fingerprint: %w", err)
	}
	if privateFingerprint != publicFingerprint {
		return Pair{}, fmt.Errorf("SSH public key %s does not match private key %s", publicPath, privatePath)
	}
	if err := requireSameFile(privatePath, privateInfo, "private key changed during inspection"); err != nil {
		return Pair{}, err
	}
	if err := requireSameFile(publicPath, publicInfo, "public key changed during inspection"); err != nil {
		return Pair{}, err
	}
	return Pair{PrivatePath: privatePath, PublicPath: publicPath, Fingerprint: privateFingerprint}, nil
}

func canonicalPrivatePath(path string) (string, os.FileInfo, error) {
	resolved, err := resolvePath(path)
	if err != nil {
		return "", nil, err
	}
	if strings.HasSuffix(strings.ToLower(resolved), ".pub") {
		return "", nil, fmt.Errorf("%s appears to be a public key; provide the private key path", resolved)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("inspect private key %s: %w", resolved, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if err := checkOwnedByCurrentUser(resolved, info); err != nil {
			return "", nil, err
		}
		resolved, err = filepath.EvalSymlinks(resolved)
		if err != nil {
			return "", nil, fmt.Errorf("resolve private-key symbolic link: %w", err)
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return "", nil, fmt.Errorf("resolve private-key path: %w", err)
		}
		info, err = os.Lstat(resolved)
		if err != nil {
			return "", nil, fmt.Errorf("inspect resolved private key %s: %w", resolved, err)
		}
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("private key %s is not a regular file", resolved)
	}
	return filepath.Clean(resolved), info, nil
}

func validatePrivateFile(path string, info os.FileInfo) error {
	if err := checkOwnedByCurrentUser(path, info); err != nil {
		return err
	}
	if posixPermissionChecks && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key %s has permissions %04o; it must not be accessible by group or others", path, info.Mode().Perm())
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open private key %s: %w", path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened private key %s: %w", path, err)
	}
	if !os.SameFile(info, openedInfo) {
		return fmt.Errorf("private key %s changed during inspection", path)
	}
	header, readErr := bufio.NewReader(file).ReadString('\n')
	if readErr != nil && header == "" {
		return fmt.Errorf("private key %s is empty or unreadable", path)
	}
	switch strings.TrimSpace(header) {
	case "-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----":
		return nil
	default:
		return fmt.Errorf("private key %s does not have a recognized private-key header", path)
	}
}

func fingerprint(path string, runner executor) (string, error) {
	output, err := runner.Output([]string{"-l", "-E", "sha256", "-f", path})
	if err != nil {
		return "", fmt.Errorf("ssh-keygen could not read %s: %w", path, err)
	}
	return fingerprintFromOutput(output, path)
}

func fingerprintFromOutput(output []byte, label string) (string, error) {
	for _, field := range strings.Fields(string(output)) {
		if strings.HasPrefix(field, "SHA256:") && len(field) > len("SHA256:") {
			return field, nil
		}
	}
	return "", fmt.Errorf("ssh-keygen returned no SHA256 fingerprint for %s", label)
}

func resolvePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("SSH private-key path is required")
	}
	if strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("SSH private-key path cannot contain control characters")
	}
	if isHomeRelativePath(path) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("find home directory: %w", err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve SSH private-key path: %w", err)
	}
	return filepath.Clean(abs), nil
}

func isHomeRelativePath(path string) bool {
	return path == "~" || (len(path) >= 2 && path[0] == '~' && os.IsPathSeparator(path[1]))
}

func requireMissing(path, label string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("%s already exists at %s; refusing to overwrite it", label, path)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("inspect %s at %s: %w", label, path, err)
}

func requireRegularNoSymlink(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular non-symbolic-link file", label)
	}
	return nil
}

func requireSameFile(path string, expected os.FileInfo, message string) error {
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(expected, current) {
		return fmt.Errorf("%s", message)
	}
	return nil
}

func removeIfSameFile(path, expectedPath string) error {
	actual, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	expected, err := os.Lstat(expectedPath)
	if err != nil || !os.SameFile(actual, expected) {
		return nil
	}
	return os.Remove(path)
}

func syncFile(path string) error {
	// FlushFileBuffers requires a write-capable handle on Windows. These are
	// newly generated staging files and were made owner-writable just above.
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open generated SSH key for sync: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync generated SSH key: %w", err)
	}
	return nil
}
