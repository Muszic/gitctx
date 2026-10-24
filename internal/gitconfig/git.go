// Package gitconfig reads and applies repository-scoped Git identity settings.
package gitconfig

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gitctx/internal/filelock"
	"gitctx/internal/profile"
	"gitctx/internal/sshkey"
)

const (
	profileKey                      = "gitctx.profile"
	managedSSHKey                   = "gitctx.managedSshCommand"
	previousSSHKey                  = "gitctx.previousSshCommand"
	managedVariantKey               = "gitctx.managedSshVariant"
	previousVariantKey              = "gitctx.previousSshVariant"
	managedSigningKey               = "gitctx.managedSigningKey"
	previousSigningKey              = "gitctx.previousSigningKey"
	managedSigningFormatKey         = "gitctx.managedSigningFormat"
	previousSigningFormatKey        = "gitctx.previousSigningFormat"
	managedCommitSigningKey         = "gitctx.managedCommitSigning"
	previousCommitSigningKey        = "gitctx.previousCommitSigning"
	managedSigningProgramKey        = "gitctx.managedSshSigningProgram"
	previousSigningProgramKey       = "gitctx.previousSshSigningProgram"
	signingProgramDigestKey         = "gitctx.sshSigningProgramDigest"
	managedSigningProgramDigestKey  = "gitctx.managedSshSigningProgramDigest"
	previousSigningProgramDigestKey = "gitctx.previousSshSigningProgramDigest"
)

var (
	identityPattern = regexp.MustCompile(`^(.*) <([^<>]*)> [0-9]+ [+-][0-9]{4}$`)
)

// Client executes the system Git command with a controllable environment.
type Client struct {
	Env                       []string
	remoteVerificationTimeout time.Duration
}

// State is the effective Git state for a working repository. GitName and
// GitEmail reflect the identity Git would use, including environment overrides.
type State struct {
	Repository                               string   `json:"repository"`
	OrdinaryRepository                       bool     `json:"ordinary_repository"`
	MultipleWorktrees                        bool     `json:"multiple_worktrees,omitempty"`
	Profile                                  string   `json:"profile,omitempty"`
	ProfileSource                            string   `json:"profile_source,omitempty"`
	ProfileOrigin                            string   `json:"profile_origin,omitempty"`
	GitName                                  string   `json:"git_name,omitempty"`
	GitEmail                                 string   `json:"git_email,omitempty"`
	CommitterName                            string   `json:"committer_name,omitempty"`
	CommitterEmail                           string   `json:"committer_email,omitempty"`
	AuthorIdentityErr                        string   `json:"author_identity_error,omitempty"`
	CommitterIdentErr                        string   `json:"committer_identity_error,omitempty"`
	ConfigName                               string   `json:"config_name,omitempty"`
	ConfigEmail                              string   `json:"config_email,omitempty"`
	LocalName                                string   `json:"-"`
	LocalEmail                               string   `json:"-"`
	LocalNameCount                           int      `json:"-"`
	LocalEmailCount                          int      `json:"-"`
	SigningKey                               string   `json:"signing_key,omitempty"`
	SigningKeyManaged                        bool     `json:"signing_key_managed,omitempty"`
	SigningManagementPresent                 bool     `json:"signing_management_present,omitempty"`
	SigningFormat                            string   `json:"signing_format,omitempty"`
	SigningFormatManaged                     bool     `json:"signing_format_managed,omitempty"`
	SigningFormatManagementPresent           bool     `json:"signing_format_management_present,omitempty"`
	CommitSigningEnabled                     bool     `json:"commit_signing_enabled"`
	CommitSigningSet                         bool     `json:"commit_signing_set"`
	CommitSigningLocal                       bool     `json:"commit_signing_local,omitempty"`
	CommitSigningOrigin                      string   `json:"commit_signing_origin,omitempty"`
	CommitSigningManaged                     bool     `json:"commit_signing_managed,omitempty"`
	CommitSigningManagementPresent           bool     `json:"commit_signing_management_present,omitempty"`
	SSHSigningProgram                        string   `json:"-"`
	SSHSigningProgramManaged                 bool     `json:"ssh_signing_program_managed,omitempty"`
	SSHSigningProgramManagementPresent       bool     `json:"ssh_signing_program_management_present,omitempty"`
	SSHSigningProgramExecutable              bool     `json:"ssh_signing_program_executable,omitempty"`
	SSHSigningProgramDigest                  string   `json:"-"`
	SSHSigningProgramDigestManaged           bool     `json:"ssh_signing_program_digest_managed,omitempty"`
	SSHSigningProgramDigestManagementPresent bool     `json:"ssh_signing_program_digest_management_present,omitempty"`
	SSHSigningProgramIntegrity               bool     `json:"ssh_signing_program_integrity,omitempty"`
	SigningDisabled                          bool     `json:"signing_disabled,omitempty"`
	SSHCommand                               string   `json:"-"`
	SSHCommandManaged                        bool     `json:"ssh_command_managed,omitempty"`
	SSHVariant                               string   `json:"ssh_variant,omitempty"`
	SSHVariantManaged                        bool     `json:"ssh_variant_managed,omitempty"`
	SSHManagementPresent                     bool     `json:"ssh_management_present,omitempty"`
	SSHRouteIssue                            string   `json:"ssh_route_issue,omitempty"`
	SSHOverride                              string   `json:"ssh_override,omitempty"`
	SSHOverrideSet                           bool     `json:"ssh_override_set,omitempty"`
	Origin                                   string   `json:"origin,omitempty"`
	PushRemote                               string   `json:"push_remote,omitempty"`
	PushRemoteExplicit                       bool     `json:"push_remote_explicit,omitempty"`
	PushURL                                  string   `json:"push_url,omitempty"`
	PushURLs                                 []string `json:"push_urls,omitempty"`
}

// EffectivePushURLs returns only the URLs that Git's selected push remote can
// actually reach. An explicit selector is authoritative even when it is empty
// or does not name a configured remote, so those cases must not fall back to
// origin.
func (s State) EffectivePushURLs() []string {
	if len(s.PushURLs) > 0 {
		return s.PushURLs
	}
	if s.PushURL != "" {
		return []string{s.PushURL}
	}
	if s.PushRemoteExplicit || s.PushRemote != "" {
		return nil
	}
	if s.Origin != "" {
		return []string{s.Origin}
	}
	return nil
}

// NewClient returns a client that inherits the current process environment.
func NewClient() *Client {
	return &Client{Env: os.Environ()}
}

// RepoRoot resolves path to the top level of a non-bare Git working tree.
func (c *Client) RepoRoot(path string) (string, error) {
	if path == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve repository path: %w", err)
	}
	out, err := c.run(abs, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("%s is not inside a Git working repository: %w", abs, err)
	}
	return trimOutputLine(out), nil
}

// Inspect reads the effective identity and origin for a repository.
func (c *Client) Inspect(path string) (State, error) {
	root, err := c.RepoRoot(path)
	if err != nil {
		return State{}, err
	}

	state := State{Repository: root}
	if state.OrdinaryRepository, err = c.isOrdinaryRepository(root); err != nil {
		return State{}, err
	}
	if state.MultipleWorktrees, err = c.hasMultipleWorktrees(root); err != nil {
		return State{}, err
	}
	if value, origin, found, err := c.getWithOrigin(root, profileKey); err != nil {
		return State{}, err
	} else if found {
		state.Profile = value
		state.ProfileOrigin = origin
	}
	for key, target := range map[string]*string{
		"user.name":             &state.ConfigName,
		"user.email":            &state.ConfigEmail,
		"user.signingKey":       &state.SigningKey,
		"gpg.format":            &state.SigningFormat,
		"gpg.ssh.program":       &state.SSHSigningProgram,
		signingProgramDigestKey: &state.SSHSigningProgramDigest,
		"core.sshCommand":       &state.SSHCommand,
		"ssh.variant":           &state.SSHVariant,
	} {
		value, found, err := c.get(root, key, false)
		if err != nil {
			return State{}, err
		}
		if found {
			*target = value
		}
	}
	if localProfiles, err := c.getLocalAll(root, profileKey); err != nil {
		return State{}, err
	} else if state.Profile != "" {
		if len(localProfiles) == 1 && localProfiles[0] == state.Profile {
			state.ProfileSource = "local"
		} else {
			state.ProfileSource = "nonlocal"
		}
	}
	if values, err := c.getLocalAll(root, "user.name"); err != nil {
		return State{}, err
	} else {
		state.LocalNameCount = len(values)
		if len(values) == 1 {
			state.LocalName = values[0]
		}
	}
	if values, err := c.getLocalAll(root, "user.email"); err != nil {
		return State{}, err
	} else {
		state.LocalEmailCount = len(values)
		if len(values) == 1 {
			state.LocalEmail = values[0]
		}
	}
	if value, origin, found, err := c.getBoolWithOrigin(root, "commit.gpgSign"); err != nil {
		return State{}, err
	} else if found {
		state.CommitSigningEnabled = value
		state.CommitSigningSet = true
		state.CommitSigningOrigin = origin
	}
	if values, err := c.getLocalAll(root, "commit.gpgSign"); err != nil {
		return State{}, err
	} else {
		state.CommitSigningLocal = len(values) > 0
	}
	if state.SigningKeyManaged, err = c.isLocallyManaged(root, "user.signingKey", managedSigningKey); err != nil {
		return State{}, err
	}
	if state.SigningFormatManaged, err = c.isLocallyManaged(root, "gpg.format", managedSigningFormatKey); err != nil {
		return State{}, err
	}
	if state.CommitSigningManaged, err = c.isLocallyManaged(root, "commit.gpgSign", managedCommitSigningKey); err != nil {
		return State{}, err
	}
	if state.SSHSigningProgramManaged, err = c.isLocallyManaged(root, "gpg.ssh.program", managedSigningProgramKey); err != nil {
		return State{}, err
	}
	if state.SSHSigningProgramDigestManaged, err = c.isLocallyManaged(root, signingProgramDigestKey, managedSigningProgramDigestKey); err != nil {
		return State{}, err
	}
	if state.SSHCommandManaged, err = c.isLocallyManaged(root, "core.sshCommand", managedSSHKey); err != nil {
		return State{}, err
	}
	if state.SSHVariantManaged, err = c.isLocallyManaged(root, "ssh.variant", managedVariantKey); err != nil {
		return State{}, err
	}
	if state.SigningManagementPresent, err = c.hasAnyLocalValue(root, managedSigningKey, previousSigningKey); err != nil {
		return State{}, err
	}
	if state.SigningFormatManagementPresent, err = c.hasAnyLocalValue(root, managedSigningFormatKey, previousSigningFormatKey); err != nil {
		return State{}, err
	}
	if state.CommitSigningManagementPresent, err = c.hasAnyLocalValue(root, managedCommitSigningKey, previousCommitSigningKey); err != nil {
		return State{}, err
	}
	if state.SSHSigningProgramManagementPresent, err = c.hasAnyLocalValue(root, managedSigningProgramKey, previousSigningProgramKey); err != nil {
		return State{}, err
	}
	if state.SSHSigningProgramDigestManagementPresent, err = c.hasAnyLocalValue(root, signingProgramDigestKey, managedSigningProgramDigestKey, previousSigningProgramDigestKey); err != nil {
		return State{}, err
	}
	if state.SSHSigningProgramManaged {
		if digest, digestErr := executableFileDigest(state.SSHSigningProgram); digestErr == nil {
			state.SSHSigningProgramExecutable = true
			state.SSHSigningProgramIntegrity = state.SSHSigningProgramDigestManaged && state.SSHSigningProgramDigest == digest
		}
	}
	if state.SSHManagementPresent, err = c.hasAnyLocalValue(root, managedSSHKey, previousSSHKey, managedVariantKey, previousVariantKey); err != nil {
		return State{}, err
	}
	if state.SigningKeyManaged && state.SigningFormatManaged && state.CommitSigningManaged && state.SSHSigningProgramManaged && state.CommitSigningSet && !state.CommitSigningEnabled && state.SigningFormat == "ssh" {
		commonDir, commonErr := c.commonGitDir(root)
		if commonErr != nil {
			return State{}, commonErr
		}
		// A directory cannot be used as an SSH signing key. Managing the
		// repository's own Git directory makes a bare -S fail closed instead
		// of falling back to an inherited work key.
		state.SigningDisabled = state.SigningKey == commonDir && state.SSHSigningProgram == commonDir && !state.SSHSigningProgramDigestManagementPresent
	}

	state.GitName, state.GitEmail = state.ConfigName, state.ConfigEmail
	if name, email, found, issue := c.identity(root, "GIT_AUTHOR_IDENT"); issue != "" {
		state.AuthorIdentityErr = issue
	} else if found {
		state.GitName, state.GitEmail = name, email
	}
	state.CommitterName, state.CommitterEmail = state.ConfigName, state.ConfigEmail
	if name, email, found, issue := c.identity(root, "GIT_COMMITTER_IDENT"); issue != "" {
		state.CommitterIdentErr = issue
	} else if found {
		state.CommitterName, state.CommitterEmail = name, email
	}

	if value, found := c.environmentLookup("GIT_SSH_COMMAND"); found {
		state.SSHOverride = sshOverrideLabel("GIT_SSH_COMMAND", value)
		state.SSHOverrideSet = true
	} else if value, found := c.environmentLookup("GIT_SSH"); found {
		state.SSHOverride = sshOverrideLabel("GIT_SSH", value)
		state.SSHOverrideSet = true
	} else if value, found := c.environmentLookup("GIT_SSH_VARIANT"); found {
		state.SSHOverride = sshOverrideLabel("GIT_SSH_VARIANT", value)
		state.SSHOverrideSet = true
	}
	if origins, found, err := c.getRemoteURLs(root, "origin", false); err != nil {
		return State{}, err
	} else if found {
		state.Origin = origins[0]
	}
	pushRemote, pushRemoteExplicit, err := c.defaultPushRemote(root)
	if err != nil {
		return State{}, err
	}
	state.PushRemote = pushRemote
	state.PushRemoteExplicit = pushRemoteExplicit
	if pushURLs, found, err := c.getRemoteURLs(root, pushRemote, true); err != nil {
		return State{}, err
	} else if found {
		state.PushURLs = pushURLs
		state.PushURL = pushURLs[0]
	}
	state.SSHRouteIssue = c.sshRouteIssue(state.EffectivePushURLs())
	return state, nil
}

func sshOverrideLabel(name, value string) string {
	if value == "" {
		return name + " (empty)"
	}
	return name + " (set)"
}

// Apply writes a profile to repository-local Git config. It builds a complete
// candidate file first and, on supported Unix targets, swaps it atomically into
// place only if the original config did not change concurrently.
func (c *Client) Apply(path, profileName string, selected profile.Profile) error {
	return c.apply(path, profileName, selected, 10*time.Second)
}

func (c *Client) apply(path, profileName string, selected profile.Profile, lockTimeout time.Duration) (err error) {
	if err := profile.ValidateName(profileName); err != nil {
		return err
	}
	selected = selected.Normalize()
	if err := selected.Validate(); err != nil {
		return fmt.Errorf("profile %q: %w", profileName, err)
	}
	if selected.ManagedKeyID != "" && !selected.GitHubConnected {
		return fmt.Errorf("profile %q has incomplete native registration; finish 'gitctx login %s' before applying it", profileName, profileName)
	}
	root, err := c.RepoRoot(path)
	if err != nil {
		return err
	}
	commonDir, err := c.commonGitDir(root)
	if err != nil {
		return err
	}
	lock, err := filelock.Acquire(filepath.Join(commonDir, "gitctx.lock"), lockTimeout)
	if err != nil {
		return fmt.Errorf("lock repository Git config: %w", err)
	}
	defer func() {
		if releaseErr := lock.Release(); releaseErr != nil {
			err = errors.Join(err, fmt.Errorf("unlock repository Git config: %w", releaseErr))
		}
	}()
	if multiple, checkErr := c.hasMultipleWorktrees(root); checkErr != nil {
		return checkErr
	} else if multiple {
		return fmt.Errorf("repository has multiple linked worktrees; v0.1 will not change their shared local identity")
	}

	sshCommand := ""
	if selected.SSHKey != "" {
		sshPath := ""
		if selected.SSHFingerprint != "" {
			pair, inspectErr := sshkey.InspectPair(selected.SSHKey)
			if inspectErr != nil {
				return inspectErr
			}
			if pair.Fingerprint != selected.SSHFingerprint {
				return fmt.Errorf("SSH key fingerprint changed: expected %s, found %s", selected.SSHFingerprint, pair.Fingerprint)
			}
			if selected.SigningFormat == "ssh" && selected.SigningKey != "" && selected.SigningKey != pair.PublicPath {
				return fmt.Errorf("SSH signing key %s is not the public key paired with %s", selected.SigningKey, pair.PrivatePath)
			}
			sshPath = pair.PrivatePath
		} else {
			var validateErr error
			sshPath, validateErr = ValidateSSHPrivateKey(selected.SSHKey)
			if validateErr != nil {
				return validateErr
			}
		}
		sshCommand = isolatedSSHCommand(sshPath)
	}

	before, err := snapshotLocalConfig(commonDir)
	if err != nil {
		return err
	}
	workingPath, err := createWorkingConfig(before)
	if err != nil {
		return err
	}
	defer os.Remove(workingPath)
	defer os.Remove(workingPath + ".lock")

	committed := false
	var committedData []byte
	defer func() {
		if err == nil || !committed {
			return
		}
		if rollbackErr := replaceLocalConfig(before, committedData, before.data); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("restore previous Git config: %w", rollbackErr))
		} else {
			err = fmt.Errorf("%w; local changes were rolled back", err)
		}
	}()

	if err = c.setConfigFile(root, workingPath, "user.name", selected.GitName); err != nil {
		return err
	}
	if err = c.setConfigFile(root, workingPath, "user.email", selected.GitEmail); err != nil {
		return err
	}
	desiredSigningKey := selected.SigningKey
	desiredSigningFormat := selected.SigningFormat
	desiredSigningProgram := ""
	desiredSigningProgramDigest := ""
	if selected.DisableSigning {
		// The repository's Git directory is guaranteed to be a directory, not
		// a usable SSH key or executable. Managing both the signing key and
		// signing program prevents an inherited custom signer from bypassing
		// the guard. A deliberate command-scoped Git config override remains
		// possible, as it is for every repository-local Git setting.
		desiredSigningKey = commonDir
		desiredSigningFormat = "ssh"
		desiredSigningProgram = commonDir
	} else if selected.SigningKey != "" && selected.SigningFormat == "ssh" {
		desiredSigningProgram, desiredSigningProgramDigest, err = trustedSSHSigningProgram()
		if err != nil {
			return err
		}
	}
	if err = c.applyManagedValue(root, workingPath, "user.signingKey", managedSigningKey, previousSigningKey, desiredSigningKey); err != nil {
		return err
	}
	if err = c.applyManagedValue(root, workingPath, "gpg.format", managedSigningFormatKey, previousSigningFormatKey, desiredSigningFormat); err != nil {
		return err
	}
	commitSigning := ""
	if selected.SigningKey != "" {
		commitSigning = "true"
	} else if selected.DisableSigning {
		commitSigning = "false"
	}
	if err = c.applyManagedValue(root, workingPath, "commit.gpgSign", managedCommitSigningKey, previousCommitSigningKey, commitSigning); err != nil {
		return err
	}
	if err = c.applyManagedValue(root, workingPath, "gpg.ssh.program", managedSigningProgramKey, previousSigningProgramKey, desiredSigningProgram); err != nil {
		return err
	}
	if err = c.applyManagedValue(root, workingPath, signingProgramDigestKey, managedSigningProgramDigestKey, previousSigningProgramDigestKey, desiredSigningProgramDigest); err != nil {
		return err
	}
	if err = c.applyManagedValue(root, workingPath, "core.sshCommand", managedSSHKey, previousSSHKey, sshCommand); err != nil {
		return err
	}
	sshVariant := ""
	if sshCommand != "" {
		sshVariant = "ssh"
	}
	if err = c.applyManagedValue(root, workingPath, "ssh.variant", managedVariantKey, previousVariantKey, sshVariant); err != nil {
		return err
	}
	if err = c.setConfigFile(root, workingPath, profileKey, profileName); err != nil {
		return err
	}
	committedData, err = os.ReadFile(workingPath)
	if err != nil {
		return fmt.Errorf("read prepared local Git config: %w", err)
	}
	if err = replaceLocalConfig(before, before.data, committedData); err != nil {
		return err
	}
	committed = true

	state, inspectErr := c.Inspect(root)
	if inspectErr != nil {
		return inspectErr
	}
	if state.ConfigName != selected.GitName || state.ConfigEmail != selected.GitEmail ||
		state.GitName != selected.GitName || state.GitEmail != selected.GitEmail ||
		state.CommitterName != selected.GitName || state.CommitterEmail != selected.GitEmail ||
		state.AuthorIdentityErr != "" || state.CommitterIdentErr != "" {
		return fmt.Errorf("Git configuration or environment overrides the selected profile")
	}
	if state.LocalNameCount != 1 || state.LocalName != selected.GitName || state.LocalEmailCount != 1 || state.LocalEmail != selected.GitEmail {
		return fmt.Errorf("selected Git identity is not isolated in repository-local config")
	}
	if desiredSigningKey != "" && state.SigningKey != desiredSigningKey {
		return fmt.Errorf("Git configuration overrides the selected signing key")
	}
	if desiredSigningFormat != "" && state.SigningFormat != desiredSigningFormat {
		return fmt.Errorf("Git configuration overrides the selected signing format")
	}
	if commitSigning != "" {
		expectedEnabled := commitSigning == "true"
		if !state.CommitSigningSet || state.CommitSigningEnabled != expectedEnabled {
			return fmt.Errorf("Git configuration overrides the selected commit-signing policy")
		}
		if !state.CommitSigningManaged {
			return fmt.Errorf("selected commit-signing policy is not managed in repository-local config")
		}
	} else if state.CommitSigningManagementPresent {
		return fmt.Errorf("repository-local commit-signing management metadata remains after restoring the previous policy")
	}
	if desiredSigningProgram != "" {
		if state.SSHSigningProgram != desiredSigningProgram {
			return fmt.Errorf("Git configuration overrides the selected SSH signing program")
		}
		if !state.SSHSigningProgramManaged {
			return fmt.Errorf("selected SSH signing program is not managed in repository-local config")
		}
		if !selected.DisableSigning && (!state.SSHSigningProgramExecutable || !state.SSHSigningProgramDigestManaged || !state.SSHSigningProgramIntegrity) {
			return fmt.Errorf("selected SSH signing program is missing, not executable, or failed its integrity check")
		}
	} else if state.SSHSigningProgramManagementPresent {
		return fmt.Errorf("repository-local SSH signing-program management metadata remains after restoring the previous program")
	}
	if desiredSigningProgramDigest == "" {
		if state.SSHSigningProgramDigestManagementPresent {
			return fmt.Errorf("repository-local SSH signing-program integrity metadata remains after restoring the previous program")
		}
	} else if !state.SSHSigningProgramDigestManaged || state.SSHSigningProgramDigest != desiredSigningProgramDigest {
		return fmt.Errorf("repository-local SSH signing-program integrity marker does not match the selected executable")
	}
	if selected.SSHKey != "" {
		if state.SSHCommand != sshCommand {
			return fmt.Errorf("Git configuration overrides the selected SSH command")
		}
		if state.SSHVariant != "ssh" {
			return fmt.Errorf("Git configuration overrides the OpenSSH command variant")
		}
		if !state.SSHCommandManaged || !state.SSHVariantManaged {
			return fmt.Errorf("selected SSH settings are not managed in repository-local config")
		}
		if state.SSHOverrideSet {
			return fmt.Errorf("GIT_SSH_COMMAND, GIT_SSH, or GIT_SSH_VARIANT overrides the selected SSH key")
		}
	}
	if desiredSigningKey != "" && !state.SigningKeyManaged {
		return fmt.Errorf("selected signing key is not managed in repository-local config")
	}
	if desiredSigningFormat != "" && !state.SigningFormatManaged {
		return fmt.Errorf("selected signing format is not managed in repository-local config")
	}
	if desiredSigningFormat == "" && state.SigningFormatManagementPresent {
		return fmt.Errorf("repository-local signing-format management metadata remains after restoring the previous format")
	}
	if selected.DisableSigning && !state.SigningDisabled {
		return fmt.Errorf("repository-local signing guard is not active")
	}
	return nil
}

// InheritedSigningKeys returns signing-key values configured outside the
// repository-local scope. Setup uses this to avoid accidentally repurposing a
// work key whose effective value may currently be hidden by a local guard.
func (c *Client) InheritedSigningKeys(path string) ([]string, error) {
	root, err := c.RepoRoot(path)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, scope := range []string{"--system", "--global"} {
		out, runErr := c.run(root, "config", scope, "--includes", "--null", "--get-all", "user.signingKey")
		if isMissingValue(runErr) {
			continue
		}
		if runErr != nil {
			return nil, fmt.Errorf("read inherited Git signing keys from %s scope: %w", strings.TrimPrefix(scope, "--"), runErr)
		}
		for _, value := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
			if value == "" || slicesContainString(result, value) {
				continue
			}
			result = append(result, value)
		}
	}
	return result, nil
}

// HasSSHDefaultKeyCommand reports whether Git can ask an external command for
// an SSH signing key. The command itself is intentionally not returned or run:
// it is arbitrary user configuration and may contain sensitive arguments.
func (c *Client) HasSSHDefaultKeyCommand(path string) (bool, error) {
	root, err := c.RepoRoot(path)
	if err != nil {
		return false, err
	}
	value, found, err := c.get(root, "gpg.ssh.defaultKeyCommand", false)
	if err != nil {
		return false, err
	}
	return found && strings.TrimSpace(value) != "", nil
}

func slicesContainString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// ResolvePath expands a leading home-relative tilde and returns an absolute path.
func ResolvePath(path string) (string, error) {
	if IsHomeRelativePath(path) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	return filepath.Abs(path)
}

// IsHomeRelativePath reports whether path starts with a standalone tilde or a
// tilde followed by a path separator recognized on this platform.
func IsHomeRelativePath(path string) bool {
	return path == "~" || (len(path) >= 2 && path[0] == '~' && os.IsPathSeparator(path[1]))
}

// ExpectedSSHCommand returns the exact repository-local command used for a key.
func ExpectedSSHCommand(key string) (string, error) {
	if key == "" {
		return "", nil
	}
	path, err := ResolvePath(key)
	if err != nil {
		return "", err
	}
	return isolatedSSHCommand(path), nil
}

func isolatedSSHCommand(path string) string {
	// Using the IdentityFile option suppresses OpenSSH's built-in default key
	// list; -i would add this key while still leaving those defaults enabled.
	// OpenSSH expands percent tokens in IdentityFile, so double every literal
	// percent to keep the validated filesystem path exact for every remote. The
	// option itself needs SSH-config quoting inside the surrounding shell quote.
	identityPath := strings.ReplaceAll(path, "%", "%%")
	identityOption := "IdentityFile=" + sshConfigQuote(identityPath)
	return "ssh -F none -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o " + shellQuote(identityOption)
}

func sshConfigQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

// ValidateSSHPrivateKey verifies that path is a readable private key understood
// by OpenSSH and, on Unix-like systems, that its mode does not expose it to
// group or other users. Windows ACL validation is reported separately.
func ValidateSSHPrivateKey(path string) (string, error) {
	resolved, err := ResolvePath(path)
	if err != nil {
		return "", err
	}
	if strings.Contains(resolved, "${") {
		return "", fmt.Errorf("SSH key path %s contains unsupported OpenSSH environment-variable syntax '${'", resolved)
	}
	if strings.HasSuffix(strings.ToLower(resolved), ".pub") {
		return "", fmt.Errorf("%s appears to be a public key; provide the private key path", resolved)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("SSH key %s: %w", resolved, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("SSH key %s is not a regular file", resolved)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("SSH key %s has permissions %04o; private keys must not be accessible by group or others", resolved, info.Mode().Perm())
	}

	file, err := os.Open(resolved)
	if err != nil {
		return "", fmt.Errorf("SSH key %s is not readable: %w", resolved, err)
	}
	defer file.Close()
	header, err := bufio.NewReader(file).ReadString('\n')
	if err != nil && len(header) == 0 {
		return "", fmt.Errorf("SSH key %s is empty or unreadable", resolved)
	}
	header = strings.TrimSpace(header)
	validHeaders := map[string]bool{
		"-----BEGIN OPENSSH PRIVATE KEY-----":   true,
		"-----BEGIN RSA PRIVATE KEY-----":       true,
		"-----BEGIN EC PRIVATE KEY-----":        true,
		"-----BEGIN DSA PRIVATE KEY-----":       true,
		"-----BEGIN PRIVATE KEY-----":           true,
		"-----BEGIN ENCRYPTED PRIVATE KEY-----": true,
	}
	if !validHeaders[header] {
		return "", fmt.Errorf("SSH key %s does not have a recognized private-key header", resolved)
	}
	command := exec.Command("ssh-keygen", "-l", "-f", resolved)
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", fmt.Errorf("validate SSH key %s: ssh-keygen is required but was not found", resolved)
		}
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("SSH key %s is not a valid private key: %s", resolved, detail)
	}
	return resolved, nil
}

// SSHPrivateKeyPermissionsVerified reports whether this build verifies the
// platform's private-key access controls.
func SSHPrivateKeyPermissionsVerified() bool {
	return runtime.GOOS != "windows"
}

// IsSSHRemote reports whether a remote uses the SSH transport.
func IsSSHRemote(remote string) bool {
	_, ok := parseSSHDestination(remote)
	return ok
}

// SSHRemoteHost returns the network host selected by an SSH Git remote. The
// boolean is false when remote is not a supported SSH URL.
func SSHRemoteHost(remote string) (string, bool) {
	destination, ok := parseSSHDestination(remote)
	if !ok {
		return "", false
	}
	return destination.host, true
}

// VerifyRemoteAccess performs a read-only Git handshake with one SSH remote.
// It reuses the repository's already-validated SSH command, while disabling
// interactive password/passphrase prompts so this command fails with a useful
// result instead of hanging. No refs or repository contents are changed.
func (c *Client) VerifyRemoteAccess(_ string, remote, sshCommand string) error {
	if !IsSSHRemote(remote) {
		return errors.New("remote is not a supported SSH URL")
	}
	if strings.TrimSpace(sshCommand) == "" {
		return errors.New("repository has no managed SSH command")
	}

	timeout := c.remoteVerificationTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	probeCommand := sshCommand + " -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o StrictHostKeyChecking=yes -o UpdateHostKeys=no"
	probeDirectory, err := os.MkdirTemp("", "gitctx-verify-")
	if err != nil {
		return fmt.Errorf("create isolated verification directory: %w", err)
	}
	createdProbeDirectory := probeDirectory
	defer os.Remove(createdProbeDirectory) // The probe does not create files here.
	probeDirectory, err = filepath.Abs(probeDirectory)
	if err != nil {
		return fmt.Errorf("resolve isolated verification directory: %w", err)
	}
	probeDirectory, err = filepath.EvalSymlinks(probeDirectory)
	if err != nil {
		return fmt.Errorf("resolve physical verification directory: %w", err)
	}

	// Request only HEAD. Enumerating every advertised ref would provide no
	// additional access guarantee and would allow an untrusted remote to make
	// this small connectivity check consume unbounded output.
	command := exec.CommandContext(ctx, "git",
		"-c", "core.sshCommand="+probeCommand,
		"-c", "ssh.variant=ssh",
		"ls-remote", "--quiet", "--", remote, "HEAD",
	)
	// Inspect has already resolved Git's push URL rewrites. Run from a fresh
	// directory with all other Git configuration disabled so passing that URL
	// back to Git cannot apply a second url.*.insteadOf rewrite and reach a
	// different host than an actual push.
	command.Dir = probeDirectory
	command.WaitDelay = 2 * time.Second
	configureProbeProcessGroup(command)
	environment := c.Env
	if environment == nil {
		environment = os.Environ()
	}
	environment = sanitizedVerificationEnvironment(environment)
	environment = withEnvironmentValue(environment, "GIT_TERMINAL_PROMPT", "0")
	environment = withEnvironmentValue(environment, "GIT_CONFIG_NOSYSTEM", "1")
	environment = withEnvironmentValue(environment, "GIT_CONFIG_GLOBAL", os.DevNull)
	// GIT_DIR prevents repository discovery even if TMPDIR is inside another
	// worktree. ls-remote with an explicit URL does not require a repository.
	environment = withEnvironmentValue(environment, "GIT_DIR", os.DevNull)
	environment = withEnvironmentValue(environment, "GIT_CEILING_DIRECTORIES", filepath.Dir(probeDirectory))
	command.Env = environment
	var stderr boundedOutput
	command.Stdout = io.Discard
	command.Stderr = &stderr
	err = command.Run()
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("connection timed out")
	}
	detail := strings.TrimSpace(stderr.String())
	if detail == "" {
		detail = err.Error()
	}
	if stderr.Truncated() {
		detail += " [output truncated]"
	}
	return fmt.Errorf("remote access failed: %s", detail)
}

const verificationOutputLimit = 64 * 1024

type boundedOutput struct {
	buffer    bytes.Buffer
	truncated bool
}

func (w *boundedOutput) Write(value []byte) (int, error) {
	originalLength := len(value)
	remaining := verificationOutputLimit - w.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
			w.truncated = true
		}
		_, _ = w.buffer.Write(value)
	} else if len(value) > 0 {
		w.truncated = true
	}
	// Report the original length so os/exec can continue draining the pipe
	// while excess remote-controlled output is discarded.
	return originalLength, nil
}

func (w *boundedOutput) String() string { return w.buffer.String() }

func (w *boundedOutput) Truncated() bool { return w.truncated }

func sanitizedVerificationEnvironment(environment []string) []string {
	base := sanitizedGitEnvironment(environment)
	result := make([]string, 0, len(base))
	for _, entry := range base {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			result = append(result, entry)
			continue
		}
		switch {
		case strings.EqualFold(key, "GIT_SSH_COMMAND"):
			continue
		case strings.EqualFold(key, "GIT_SSH"):
			continue
		case strings.EqualFold(key, "GIT_SSH_VARIANT"):
			continue
		case strings.EqualFold(key, "GIT_CONFIG_PARAMETERS"):
			continue
		case strings.EqualFold(key, "GIT_CONFIG_COUNT"):
			continue
		case strings.HasPrefix(strings.ToUpper(key), "GIT_CONFIG_KEY_"):
			continue
		case strings.HasPrefix(strings.ToUpper(key), "GIT_CONFIG_VALUE_"):
			continue
		case strings.EqualFold(key, "GIT_CONFIG_GLOBAL"):
			continue
		case strings.EqualFold(key, "GIT_CONFIG_SYSTEM"):
			continue
		case strings.EqualFold(key, "GIT_CONFIG_NOSYSTEM"):
			continue
		case strings.EqualFold(key, "GIT_CEILING_DIRECTORIES"):
			continue
		default:
			result = append(result, entry)
		}
	}
	return result
}

func withEnvironmentValue(environment []string, key, value string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(name, key) {
			continue
		}
		result = append(result, entry)
	}
	return append(result, key+"="+value)
}

type sshDestination struct {
	host string
	user string
	port string
}

func parseSSHDestination(remote string) (sshDestination, bool) {
	if strings.HasPrefix(remote, "ssh://") || strings.HasPrefix(remote, "git+ssh://") || strings.HasPrefix(remote, "ssh+git://") {
		parsed, err := url.Parse(remote)
		host := parsed.Hostname()
		if err != nil || host == "" || strings.HasPrefix(host, "-") {
			return sshDestination{}, false
		}
		user := ""
		if parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword {
				return sshDestination{}, false
			}
			user = parsed.User.Username()
		}
		return sshDestination{host: host, user: user, port: parsed.Port()}, true
	}
	if strings.Contains(remote, "://") || len(remote) < 2 {
		return sshDestination{}, false
	}
	if ((remote[0] >= 'A' && remote[0] <= 'Z') || (remote[0] >= 'a' && remote[0] <= 'z')) && remote[1] == ':' {
		return sshDestination{}, false
	}
	delimiter := strings.IndexByte(remote, ':')
	if bracket := strings.Index(remote, "]:"); bracket >= 0 {
		delimiter = bracket + 1
	}
	if delimiter <= 0 || (delimiter+1 < len(remote) && remote[delimiter+1] == ':') {
		return sshDestination{}, false
	}
	hostPart := remote[:delimiter]
	user := ""
	if at := strings.LastIndexByte(hostPart, '@'); at >= 0 {
		user = hostPart[:at]
		hostPart = hostPart[at+1:]
	}
	hostPart = strings.TrimPrefix(strings.TrimSuffix(hostPart, "]"), "[")
	if hostPart == "" || strings.HasPrefix(hostPart, "-") || strings.ContainsAny(hostPart, "/\\ \t\r\n") || strings.ContainsAny(user, " \t\r\n") {
		return sshDestination{}, false
	}
	return sshDestination{host: hostPart, user: user}, true
}

func (c *Client) sshRouteIssue(remotes []string) string {
	firstHost := ""
	for _, remote := range remotes {
		destination, ok := parseSSHDestination(remote)
		if !ok {
			continue
		}
		if firstHost == "" {
			firstHost = destination.host
		}
		if net.ParseIP(destination.host) == nil && !strings.Contains(destination.host, ".") && !strings.EqualFold(destination.host, "localhost") {
			return fmt.Sprintf("SSH remote host %q may be a Host alias, but strict key isolation disables SSH config; use an IP address or fully qualified hostname", destination.host)
		}
	}
	if firstHost != "" {
		return fmt.Sprintf("strict key isolation disables SSH config; routing and connectivity to host %q are not tested", firstHost)
	}
	return ""
}

func (c *Client) applyManagedValue(root, configPath, key, marker, previous, desired string) error {
	managedValues, err := c.getConfigFileAll(root, configPath, marker)
	if err != nil {
		return err
	}
	if len(managedValues) > 1 {
		return fmt.Errorf("local Git config %s has multiple gitctx management markers; refusing to change it", key)
	}
	managed, managedFound := singleValue(managedValues)
	previousValues, err := c.getConfigFileAll(root, configPath, previous)
	if err != nil {
		return err
	}
	if len(previousValues) > 1 {
		return fmt.Errorf("local Git config %s has multiple saved values; refusing to change it", key)
	}
	_, previousFound := singleValue(previousValues)
	if previousFound && !managedFound {
		return fmt.Errorf("local Git config %s has inconsistent gitctx management metadata; refusing to change it", key)
	}
	if managedFound && managed == "" {
		return fmt.Errorf("local Git config %s has an empty gitctx management marker; refusing to change it", key)
	}
	if desired == "" && !managedFound {
		return nil
	}

	currentValues, err := c.getConfigFileAll(root, configPath, key)
	if err != nil {
		return err
	}
	if len(currentValues) > 1 {
		return fmt.Errorf("local Git config %s has multiple values; refusing to collapse them", key)
	}
	current, currentFound := singleValue(currentValues)

	if desired != "" {
		if managedFound && (!currentFound || current != managed) {
			return fmt.Errorf("local Git config %s changed after gitctx managed it; refusing to overwrite it", key)
		}
		if !managedFound && currentFound && !previousFound {
			if err := c.setConfigFile(root, configPath, previous, current); err != nil {
				return err
			}
		}
		if err := c.setConfigFile(root, configPath, key, desired); err != nil {
			return err
		}
		return c.setConfigFile(root, configPath, marker, desired)
	}

	if !currentFound || current != managed {
		return fmt.Errorf("local Git config %s changed after gitctx managed it; refusing to overwrite it", key)
	}
	prior, priorFound := singleValue(previousValues)
	if priorFound {
		if err := c.setConfigFile(root, configPath, key, prior); err != nil {
			return err
		}
	} else if err := c.unsetConfigFile(root, configPath, key); err != nil {
		return err
	}
	if err := c.unsetConfigFile(root, configPath, marker); err != nil {
		return err
	}
	return c.unsetConfigFile(root, configPath, previous)
}

func singleValue(values []string) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

type localConfigSnapshot struct {
	path string
	data []byte
	mode os.FileMode
}

func snapshotLocalConfig(commonDir string) (localConfigSnapshot, error) {
	path := filepath.Join(commonDir, "config")
	info, err := os.Lstat(path)
	if err != nil {
		return localConfigSnapshot{}, fmt.Errorf("inspect local Git config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return localConfigSnapshot{}, fmt.Errorf("local Git config %s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return localConfigSnapshot{}, fmt.Errorf("snapshot local Git config: %w", err)
	}
	return localConfigSnapshot{path: path, data: data, mode: info.Mode().Perm()}, nil
}

func createWorkingConfig(snapshot localConfigSnapshot) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(snapshot.path), "gitctx-config-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create prepared local Git config: %w", err)
	}
	path := file.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(snapshot.mode); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("protect prepared local Git config: %w", err)
	}
	_, writeErr := file.Write(snapshot.data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return "", fmt.Errorf("prepare local Git config: %w", err)
	}
	remove = false
	return path, nil
}

func replaceLocalConfig(snapshot localConfigSnapshot, expected, replacement []byte) error {
	lockPath := snapshot.path + ".lock"
	file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, snapshot.mode)
	if err != nil {
		return fmt.Errorf("lock local Git config: %w", err)
	}
	closed := false
	renamed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !renamed {
			_ = os.Remove(lockPath)
		}
	}()

	current, err := os.ReadFile(snapshot.path)
	if err != nil {
		return fmt.Errorf("read local Git config before replacement: %w", err)
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("local Git config changed concurrently; refusing to overwrite it")
	}
	if err := file.Chmod(snapshot.mode); err != nil {
		return fmt.Errorf("protect local Git config lock: %w", err)
	}
	if _, err := file.Write(replacement); err != nil {
		return fmt.Errorf("write local Git config lock: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync local Git config lock: %w", err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close local Git config lock: %w", err)
	}
	closed = true
	if err := os.Rename(lockPath, snapshot.path); err != nil {
		return fmt.Errorf("replace local Git config: %w", err)
	}
	renamed = true
	return nil
}

func (c *Client) get(root, key string, local bool) (string, bool, error) {
	args := []string{"config"}
	if local {
		args = append(args, "--local", "--no-includes")
	}
	args = append(args, "--null", "--get", key)
	out, err := c.run(root, args...)
	if isMissingValue(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read Git config %s: %w", key, err)
	}
	return strings.TrimSuffix(out, "\x00"), true, nil
}

func (c *Client) getWithOrigin(root, key string) (string, string, bool, error) {
	out, err := c.run(root, "config", "--show-origin", "--null", "--get", key)
	if isMissingValue(err) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("read Git config %s origin: %w", key, err)
	}
	parts := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
	if len(parts) != 2 {
		return "", "", false, fmt.Errorf("read Git config %s origin: unexpected Git output", key)
	}
	return parts[1], parts[0], true, nil
}

func (c *Client) getBoolWithOrigin(root, key string) (bool, string, bool, error) {
	out, err := c.run(root, "config", "--show-origin", "--bool", "--null", "--get", key)
	if isMissingValue(err) {
		return false, "", false, nil
	}
	if err != nil {
		return false, "", false, fmt.Errorf("read Git config %s as a boolean: %w", key, err)
	}
	parts := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
	if len(parts) != 2 || (parts[1] != "true" && parts[1] != "false") {
		return false, "", false, fmt.Errorf("read Git config %s as a boolean: unexpected Git output", key)
	}
	return parts[1] == "true", parts[0], true, nil
}

func (c *Client) getLocalAll(root, key string) ([]string, error) {
	out, err := c.run(root, "config", "--local", "--no-includes", "--null", "--get-all", key)
	if isMissingValue(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read local Git config %s: %w", key, err)
	}
	return strings.Split(strings.TrimSuffix(out, "\x00"), "\x00"), nil
}

func (c *Client) isLocallyManaged(root, key, marker string) (bool, error) {
	values, err := c.getLocalAll(root, key)
	if err != nil {
		return false, err
	}
	markers, err := c.getLocalAll(root, marker)
	if err != nil {
		return false, err
	}
	if len(values) != 1 || len(markers) != 1 || values[0] != markers[0] {
		return false, nil
	}
	effective, found, err := c.get(root, key, false)
	if err != nil {
		return false, err
	}
	// A worktree, command-scoped, or environment-supplied value can outrank
	// repository-local config. Treat the setting as managed only when the value
	// Git will actually use still equals gitctx's local marker.
	return found && effective == markers[0], nil
}

func (c *Client) hasAnyLocalValue(root string, keys ...string) (bool, error) {
	for _, key := range keys {
		values, err := c.getLocalAll(root, key)
		if err != nil {
			return false, err
		}
		if len(values) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) getRemoteURLs(root, name string, push bool) ([]string, bool, error) {
	args := []string{"remote", "get-url"}
	if push {
		args = append(args, "--push")
	}
	args = append(args, "--all", name)
	out, err := c.run(root, args...)
	if err != nil {
		var commandErr *commandError
		if errors.As(err, &commandErr) && commandErr.Code == 2 {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read %s remote: %w", name, err)
	}
	urls := splitOutputLines(out)
	return urls, len(urls) > 0, nil
}

func (c *Client) defaultPushRemote(root string) (string, bool, error) {
	branch := ""
	if out, err := c.run(root, "symbolic-ref", "--quiet", "--short", "HEAD"); err == nil {
		branch = trimOutputLine(out)
	} else {
		var commandErr *commandError
		if !errors.As(err, &commandErr) || commandErr.Code != 1 {
			return "", false, fmt.Errorf("find current Git branch: %w", err)
		}
	}
	if branch != "" {
		if remote, found, err := c.get(root, "branch."+branch+".pushRemote", false); err != nil {
			return "", false, err
		} else if found {
			return remote, true, nil
		}
	}
	if remote, found, err := c.get(root, "remote.pushDefault", false); err != nil {
		return "", false, err
	} else if found {
		return remote, true, nil
	}
	if branch != "" {
		if remote, found, err := c.get(root, "branch."+branch+".remote", false); err != nil {
			return "", false, err
		} else if found {
			return remote, true, nil
		}
	}
	out, err := c.run(root, "remote")
	if err != nil {
		return "", false, fmt.Errorf("list Git remotes: %w", err)
	}
	remotes := splitOutputLines(out)
	if len(remotes) == 1 {
		return remotes[0], false, nil
	}
	for _, remote := range remotes {
		if remote == "origin" {
			return "origin", false, nil
		}
	}
	return "", false, nil
}

func splitOutputLines(output string) []string {
	output = strings.TrimSuffix(output, "\n")
	if output == "" {
		return nil
	}
	lines := strings.Split(output, "\n")
	if runtime.GOOS == "windows" {
		for index := range lines {
			lines[index] = strings.TrimSuffix(lines[index], "\r")
		}
	}
	return lines
}

func trimOutputLine(output string) string {
	output = strings.TrimSuffix(output, "\n")
	if runtime.GOOS == "windows" {
		output = strings.TrimSuffix(output, "\r")
	}
	return output
}

func (c *Client) identity(root, variable string) (string, string, bool, string) {
	out, err := c.run(root, "var", variable)
	if err != nil {
		return "", "", false, err.Error()
	}
	matches := identityPattern.FindStringSubmatch(trimOutputLine(out))
	if len(matches) != 3 {
		return "", "", false, "Git returned an unrecognized identity"
	}
	return matches[1], matches[2], true, ""
}

func (c *Client) hasMultipleWorktrees(root string) (bool, error) {
	out, err := c.run(root, "worktree", "list", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("inspect Git worktrees: %w", err)
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "worktree ") {
			count++
		}
	}
	return count > 1, nil
}

func (c *Client) isOrdinaryRepository(root string) (bool, error) {
	out, err := c.run(root, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return false, fmt.Errorf("find repository Git directory: %w", err)
	}
	actual := filepath.Clean(trimOutputLine(out))
	expected := filepath.Join(root, ".git")
	actualInfo, err := os.Stat(actual)
	if err != nil {
		return false, fmt.Errorf("inspect repository Git directory: %w", err)
	}
	expectedInfo, err := os.Stat(expected)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect ordinary repository Git directory: %w", err)
	}
	return actualInfo.IsDir() && expectedInfo.IsDir() && os.SameFile(actualInfo, expectedInfo), nil
}

func (c *Client) commonGitDir(root string) (string, error) {
	out, err := c.run(root, "rev-parse", "--git-common-dir")
	if err != nil {
		return "", fmt.Errorf("find repository Git directory: %w", err)
	}
	dir := trimOutputLine(out)
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	return filepath.Clean(dir), nil
}

func (c *Client) environmentLookup(name string) (string, bool) {
	environment := c.Env
	if environment == nil {
		environment = os.Environ()
	}
	for index := len(environment) - 1; index >= 0; index-- {
		key, value, found := strings.Cut(environment[index], "=")
		if !found {
			continue
		}
		matches := key == name
		if runtime.GOOS == "windows" {
			matches = strings.EqualFold(key, name)
		}
		if matches {
			return value, true
		}
	}
	return "", false
}

func (c *Client) setConfigFile(root, configPath, key, value string) error {
	_, err := c.run(root, "config", "--file", configPath, "--no-includes", "--replace-all", "--", key, value)
	if err != nil {
		return fmt.Errorf("set local Git config %s: %w", key, err)
	}
	return nil
}

func (c *Client) unsetConfigFile(root, configPath, key string) error {
	values, err := c.getConfigFileAll(root, configPath, key)
	if err != nil || len(values) == 0 {
		return err
	}
	_, err = c.run(root, "config", "--file", configPath, "--no-includes", "--unset-all", "--", key)
	if err != nil {
		return fmt.Errorf("unset local Git config %s: %w", key, err)
	}
	return nil
}

func (c *Client) getConfigFileAll(root, configPath, key string) ([]string, error) {
	out, err := c.run(root, "config", "--file", configPath, "--no-includes", "--null", "--get-all", key)
	if isMissingValue(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read local Git config %s: %w", key, err)
	}
	return strings.Split(strings.TrimSuffix(out, "\x00"), "\x00"), nil
}

func (c *Client) run(dir string, args ...string) (string, error) {
	command := exec.Command("git", args...)
	command.Dir = dir
	environment := c.Env
	if environment == nil {
		environment = os.Environ()
	}
	command.Env = sanitizedGitEnvironment(environment)
	output, err := command.CombinedOutput()
	if err == nil {
		return string(output), nil
	}

	code := -1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		message = err.Error()
	}
	return "", &commandError{Code: code, Message: message}
}

func sanitizedGitEnvironment(environment []string) []string {
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, found := strings.Cut(entry, "=")
		if found && isRepositoryRedirectEnvironment(key) {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func isRepositoryRedirectEnvironment(key string) bool {
	switch {
	case strings.EqualFold(key, "GIT_DIR"):
		return true
	case strings.EqualFold(key, "GIT_WORK_TREE"):
		return true
	case strings.EqualFold(key, "GIT_COMMON_DIR"):
		return true
	case strings.EqualFold(key, "GIT_CONFIG"):
		return true
	case strings.EqualFold(key, "GIT_CONFIG_LOCAL"):
		return true
	default:
		return false
	}
}

type commandError struct {
	Code    int
	Message string
}

func (e *commandError) Error() string { return e.Message }

func isMissingValue(err error) bool {
	var commandErr *commandError
	return errors.As(err, &commandErr) && commandErr.Code == 1
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func trustedSSHSigningProgram() (string, string, error) {
	program, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return "", "", errors.New("SSH signing requires ssh-keygen, but it was not found")
	}
	program, err = filepath.Abs(program)
	if err != nil {
		return "", "", fmt.Errorf("resolve ssh-keygen path: %w", err)
	}
	program, err = filepath.EvalSymlinks(program)
	if err != nil {
		return "", "", fmt.Errorf("resolve ssh-keygen executable: %w", err)
	}
	digest, err := executableFileDigest(program)
	if err != nil {
		return "", "", fmt.Errorf("inspect ssh-keygen executable: %w", err)
	}
	// Git executes gpg.ssh.program directly rather than parsing it through a
	// shell, so the resolved path must be stored verbatim (including spaces).
	return program, digest, nil
}

func executableFileDigest(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("executable path is not absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("path is not a regular non-symbolic-link file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("file is not executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(info, after) {
		return "", errors.New("executable changed during integrity inspection")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
