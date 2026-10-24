package gitconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"gitctx/internal/profile"
)

func TestPendingNativeProfileIsRejectedBeforeRepositoryMutation(t *testing.T) {
	directory := t.TempDir()
	p := profile.Profile{GitName: "Ada", GitEmail: "ada@example.invalid", GitHubUser: "ada", GitHubAccountID: 42, SSHKey: "/keys/pending", SSHFingerprint: "SHA256:" + strings.Repeat("a", 43), ManagedKeyID: strings.Repeat("b", 32)}
	err := NewClient().Apply(directory, "pending", p)
	if err == nil || !strings.Contains(err.Error(), "incomplete native registration") {
		t.Fatalf("pending profile error=%v", err)
	}
	files, readErr := os.ReadDir(directory)
	if readErr != nil || len(files) != 0 {
		t.Fatal("pending profile mutated the target directory")
	}
}

func TestApplyIsRepositoryLocal(t *testing.T) {
	repo := initRepository(t)
	key := filepath.Join(t.TempDir(), "personal key")
	writeTestPrivateKey(t, key, 0o600)

	client := &Client{Env: isolatedGitEnvironment()}
	selected := profile.Profile{
		GitName:  "Ada Lovelace",
		GitEmail: "ada@example.com",
		SSHKey:   key,
	}
	if err := client.Apply(repo, "personal", selected); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if state.Profile != "personal" || state.GitName != selected.GitName || state.GitEmail != selected.GitEmail {
		t.Fatalf("Inspect() state = %#v", state)
	}
	wantSSHCommand, err := ExpectedSSHCommand(key)
	if err != nil {
		t.Fatal(err)
	}
	if state.SSHCommand != wantSSHCommand {
		t.Fatalf("Inspect() SSH command = %q, want %q", state.SSHCommand, wantSSHCommand)
	}
	if !strings.Contains(state.SSHCommand, "IdentityFile=") || strings.Contains(state.SSHCommand, " -i ") {
		t.Fatalf("Inspect() SSH command does not suppress OpenSSH default identity files: %q", state.SSHCommand)
	}
	if !strings.Contains(state.SSHCommand, "PreferredAuthentications=publickey") {
		t.Fatalf("Inspect() SSH command does not restrict authentication to the selected key: %q", state.SSHCommand)
	}
	if !strings.Contains(state.SSHCommand, "-F none") {
		t.Fatalf("Inspect() SSH command does not isolate user SSH config: %q", state.SSHCommand)
	}
}

func TestApplyRestoresUnmanagedSSHCommand(t *testing.T) {
	repo := initRepository(t)
	key := filepath.Join(t.TempDir(), "key")
	writeTestPrivateKey(t, key, 0o600)
	client := &Client{Env: isolatedGitEnvironment()}
	if _, err := client.run(repo, "config", "--local", "core.sshCommand", "custom-ssh"); err != nil {
		t.Fatalf("set baseline: %v", err)
	}
	if _, err := client.run(repo, "config", "--local", "ssh.variant", "plink"); err != nil {
		t.Fatalf("set variant baseline: %v", err)
	}
	withSSH := profile.Profile{GitName: "Ada", GitEmail: "ada@example.com", SSHKey: key}
	withoutSSH := profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"}
	if err := client.Apply(repo, "personal", withSSH); err != nil {
		t.Fatalf("Apply(with SSH) error = %v", err)
	}
	if err := client.Apply(repo, "plain", withoutSSH); err != nil {
		t.Fatalf("Apply(without SSH) error = %v", err)
	}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if state.SSHCommand != "custom-ssh" {
		t.Fatalf("SSH command = %q, want restored custom-ssh", state.SSHCommand)
	}
	if state.SSHVariant != "plink" {
		t.Fatalf("SSH variant = %q, want restored plink", state.SSHVariant)
	}
}

func TestApplyDisablesCommitSigningLocallyAndRestoresInheritance(t *testing.T) {
	repo := initRepository(t)
	root := t.TempDir()
	globalPath := filepath.Join(root, "global.gitconfig")
	workKey := filepath.Join(root, "work-key")
	keygen := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", workKey)
	if output, err := keygen.CombinedOutput(); err != nil {
		t.Fatalf("generate work signing key: %v: %s", err, output)
	}
	client := &Client{Env: append(os.Environ(), "GIT_CONFIG_GLOBAL="+globalPath, "GIT_CONFIG_SYSTEM="+os.DevNull)}
	if _, err := client.run(repo, "config", "--global", "commit.gpgSign", "true"); err != nil {
		t.Fatalf("set global signing policy: %v", err)
	}
	if _, err := client.run(repo, "config", "--global", "gpg.format", "ssh"); err != nil {
		t.Fatalf("set global signing format: %v", err)
	}
	if _, err := client.run(repo, "config", "--global", "user.signingKey", workKey+".pub"); err != nil {
		t.Fatalf("set global signing key: %v", err)
	}

	disabled := profile.Profile{GitName: "Ada", GitEmail: "ada@example.com", DisableSigning: true}
	if err := client.Apply(repo, "personal", disabled); err != nil {
		t.Fatalf("Apply(disabled) error = %v", err)
	}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !state.CommitSigningSet || state.CommitSigningEnabled || !state.CommitSigningLocal || !state.CommitSigningManaged || !state.CommitSigningManagementPresent || !state.SigningDisabled || !state.SigningKeyManaged || !state.SigningFormatManaged {
		t.Fatalf("disabled commit-signing state = %#v", state)
	}
	if state.CommitSigningOrigin == "" {
		t.Fatalf("disabled commit-signing origin = %q, want local config origin", state.CommitSigningOrigin)
	}
	global, err := client.run(repo, "config", "--global", "--bool", "--get", "commit.gpgSign")
	if err != nil || trimOutputLine(global) != "true" {
		t.Fatalf("global commit.gpgSign = %q, error = %v; want unchanged true", global, err)
	}
	if _, err := client.run(repo, "commit", "--allow-empty", "-S", "-m", "guarded"); err == nil {
		t.Fatal("bare -S used an inherited signing key despite the local signing guard")
	}

	inherited := profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"}
	if err := client.Apply(repo, "plain", inherited); err != nil {
		t.Fatalf("Apply(inherited) error = %v", err)
	}
	state, err = client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !state.CommitSigningSet || !state.CommitSigningEnabled || state.CommitSigningLocal || state.CommitSigningManaged || state.CommitSigningManagementPresent {
		t.Fatalf("restored inherited commit-signing state = %#v", state)
	}
	if state.SigningKey != workKey+".pub" || state.SigningFormat != "ssh" || state.SigningDisabled {
		t.Fatalf("restored inherited signing state = %#v", state)
	}
	if _, err := client.run(repo, "commit", "--allow-empty", "-S", "-m", "signed after restore"); err != nil {
		t.Fatalf("bare -S did not use the restored inherited key: %v", err)
	}
}

func TestApplySigningPolicyRestoresPreexistingLocalValues(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	if _, err := client.run(repo, "config", "--local", "commit.gpgSign", "false"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.run(repo, "config", "--local", "gpg.format", "openpgp"); err != nil {
		t.Fatal(err)
	}

	signed := profile.Profile{
		GitName:       "Ada",
		GitEmail:      "ada@example.com",
		SigningKey:    "personal-key.pub",
		SigningFormat: "ssh",
	}
	if err := client.Apply(repo, "signed", signed); err != nil {
		t.Fatalf("Apply(signed) error = %v", err)
	}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !state.CommitSigningEnabled || !state.CommitSigningManaged || state.SigningKey != signed.SigningKey || !state.SigningKeyManaged || state.SigningFormat != "ssh" || !state.SigningFormatManaged || !state.SigningFormatManagementPresent {
		t.Fatalf("managed signing state = %#v", state)
	}

	plain := profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"}
	if err := client.Apply(repo, "plain", plain); err != nil {
		t.Fatalf("Apply(plain) error = %v", err)
	}
	state, err = client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if state.CommitSigningEnabled || !state.CommitSigningSet || !state.CommitSigningLocal || state.CommitSigningManaged || state.CommitSigningManagementPresent {
		t.Fatalf("restored commit-signing state = %#v", state)
	}
	if state.SigningFormat != "openpgp" || state.SigningFormatManaged || state.SigningFormatManagementPresent {
		t.Fatalf("restored signing-format state = %#v", state)
	}
	if state.SigningKey != "" || state.SigningKeyManaged || state.SigningManagementPresent {
		t.Fatalf("restored signing-key state = %#v", state)
	}
}

func TestApplyCommitSigningRefusesTamperedManagedValue(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	disabled := profile.Profile{GitName: "Ada", GitEmail: "ada@example.com", DisableSigning: true}
	if err := client.Apply(repo, "personal", disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := client.run(repo, "config", "--local", "commit.gpgSign", "true"); err != nil {
		t.Fatal(err)
	}
	commonDir, err := client.commonGitDir(repo)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(commonDir, "config")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Apply(repo, "plain", profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"})
	if err == nil || !strings.Contains(err.Error(), "changed after gitctx managed it") {
		t.Fatalf("Apply() error = %v, want tamper refusal", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("local config changed despite tamper refusal\nbefore:\n%s\nafter:\n%s", before, after)
	}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !state.CommitSigningManagementPresent || state.CommitSigningManaged {
		t.Fatalf("tampered management state = %#v", state)
	}
}

func TestApplyRejectsSigningKeyWithoutFormat(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	commonDir, err := client.commonGitDir(repo)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(commonDir, "config")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	selected := profile.Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningKey: "ABC123"}
	err = client.Apply(repo, "ambiguous-signed", selected)
	if err == nil || !strings.Contains(err.Error(), "requires a signing format") {
		t.Fatalf("Apply() error = %v, want signing-format requirement", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("local config changed after rejected ambiguous signing profile\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestExpectedSSHCommandEscapesOpenSSHIdentityTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "personal-%h-%r-%%-key")
	command, err := ExpectedSSHCommand(path)
	if err != nil {
		t.Fatal(err)
	}
	escaped := strings.ReplaceAll(path, "%", "%%")
	if !strings.Contains(command, shellQuote("IdentityFile="+sshConfigQuote(escaped))) {
		t.Fatalf("ExpectedSSHCommand() = %q, want escaped identity path %q", command, escaped)
	}
}

func TestApplyRollsBackWhenEnvironmentOverridesIdentity(t *testing.T) {
	repo := initRepository(t)
	env := isolatedGitEnvironment()
	env = append(env, "GIT_AUTHOR_EMAIL=override@example.com", "GIT_COMMITTER_EMAIL=override@example.com")
	client := &Client{Env: env}

	err := client.Apply(repo, "personal", profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"})
	if err == nil {
		t.Fatal("Apply() error = nil, want environment override error")
	}
	for _, key := range []string{"user.name", "user.email", profileKey} {
		values, getErr := client.getLocalAll(repo, key)
		if getErr != nil {
			t.Fatalf("getLocalAll(%s) error = %v", key, getErr)
		}
		if len(values) != 0 {
			t.Fatalf("local %s = %q after rollback, want unset", key, values)
		}
	}
}

func TestApplyRollbackRestoresExactLocalConfigOrdering(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	commonDir, err := client.commonGitDir(repo)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(commonDir, "config")
	base, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	includePath := filepath.Join(t.TempDir(), "included.gitconfig")
	if err := os.WriteFile(includePath, []byte("[user]\n\temail = included@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := append(append([]byte{}, base...), []byte(fmt.Sprintf("\n[user]\n\tname = Before\n\temail = direct@example.com\n[include]\n\tpath = %q\n[user]\n\tsigningKey = original-signing-key\n", includePath))...)
	if err := os.WriteFile(configPath, fixture, 0o600); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if state.ConfigEmail != "included@example.com" {
		t.Fatalf("fixture email = %q, want included value", state.ConfigEmail)
	}

	err = client.Apply(repo, "personal", profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Apply() error = %v, want verification rollback", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("local config changed after rollback\nbefore:\n%s\nafter:\n%s", before, after)
	}
	state, err = client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if state.ConfigEmail != "included@example.com" || state.SigningKey != "original-signing-key" {
		t.Fatalf("state after rollback = %#v", state)
	}
}

func TestApplyIgnoresRepositoryRedirectionEnvironment(t *testing.T) {
	repoA := initRepository(t)
	repoB := initRepository(t)
	env := append(isolatedGitEnvironment(),
		"GIT_DIR="+filepath.Join(repoA, ".git"),
		"GIT_WORK_TREE="+repoA,
		"GIT_COMMON_DIR="+filepath.Join(repoA, ".git"),
	)
	client := &Client{Env: env}
	selected := profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"}
	if err := client.Apply(repoB, "personal", selected); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if values, err := client.getLocalAll(repoA, profileKey); err != nil || len(values) != 0 {
		t.Fatalf("repository A marker = %q, error = %v", values, err)
	}
	state, err := client.Inspect(repoB)
	if err != nil {
		t.Fatal(err)
	}
	if state.Profile != "personal" || state.ConfigEmail != selected.GitEmail {
		t.Fatalf("repository B state = %#v", state)
	}
}

func TestApplyRejectsEmptySSHCommandAndVariantOverrides(t *testing.T) {
	for _, override := range []string{"GIT_SSH_COMMAND=", "GIT_SSH=", "GIT_SSH_VARIANT=plink"} {
		t.Run(override, func(t *testing.T) {
			repo := initRepository(t)
			key := filepath.Join(t.TempDir(), "key")
			writeTestPrivateKey(t, key, 0o600)
			client := &Client{Env: append(isolatedGitEnvironment(), override)}
			err := client.Apply(repo, "personal", profile.Profile{GitName: "Ada", GitEmail: "ada@example.com", SSHKey: key})
			if err == nil || !strings.Contains(err.Error(), "overrides the selected SSH key") {
				t.Fatalf("Apply() error = %v, want SSH override rejection", err)
			}
			if values, readErr := client.getLocalAll(repo, profileKey); readErr != nil || len(values) != 0 {
				t.Fatalf("profile marker after rollback = %q, error = %v", values, readErr)
			}
		})
	}
}

func TestApplyRefusesMultipleExistingManagedValuesWithoutChangingConfig(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	if _, err := client.run(repo, "config", "--local", "--add", "user.signingKey", "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.run(repo, "config", "--local", "--add", "user.signingKey", "second"); err != nil {
		t.Fatal(err)
	}
	commonDir, err := client.commonGitDir(repo)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(commonDir, "config")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Apply(repo, "signed", profile.Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningKey: "third", SigningFormat: "openpgp"})
	if err == nil || !strings.Contains(err.Error(), "multiple values") {
		t.Fatalf("Apply() error = %v, want multiple-value refusal", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("local config changed despite pre-commit refusal\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestApplyManagedValueRejectsOrphanPreviousMetadata(t *testing.T) {
	for _, desired := range []string{"new-signing-key", ""} {
		name := "set"
		if desired == "" {
			name = "relinquish"
		}
		t.Run(name, func(t *testing.T) {
			repo := initRepository(t)
			client := &Client{Env: isolatedGitEnvironment()}
			commonDir, err := client.commonGitDir(repo)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(commonDir, "config")
			if err := client.setConfigFile(repo, configPath, "user.signingKey", "user-value"); err != nil {
				t.Fatal(err)
			}
			if err := client.setConfigFile(repo, configPath, previousSigningKey, "stale-saved-value"); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}

			err = client.applyManagedValue(repo, configPath, "user.signingKey", managedSigningKey, previousSigningKey, desired)
			if err == nil || !strings.Contains(err.Error(), "inconsistent gitctx management metadata") {
				t.Fatalf("applyManagedValue() error = %v, want inconsistent-metadata refusal", err)
			}
			after, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("local config changed despite orphan-metadata refusal\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

func TestApplyManagedValueRejectsEmptyManagedMarker(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	commonDir, err := client.commonGitDir(repo)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(commonDir, "config")
	if err := client.setConfigFile(repo, configPath, "user.signingKey", "user-value"); err != nil {
		t.Fatal(err)
	}
	if err := client.setConfigFile(repo, configPath, managedSigningKey, ""); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	err = client.applyManagedValue(repo, configPath, "user.signingKey", managedSigningKey, previousSigningKey, "new-signing-key")
	if err == nil || !strings.Contains(err.Error(), "empty gitctx management marker") {
		t.Fatalf("applyManagedValue() error = %v, want empty-marker refusal", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("local config changed despite empty-marker refusal\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestApplyManagedValuePreservesDeletedOrChangedValueWhenRelinquishing(t *testing.T) {
	changed := "user-change"
	for _, test := range []struct {
		name    string
		current *string
	}{
		{name: "deleted"},
		{name: "changed", current: &changed},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := initRepository(t)
			client := &Client{Env: isolatedGitEnvironment()}
			commonDir, err := client.commonGitDir(repo)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(commonDir, "config")
			if test.current != nil {
				if err := client.setConfigFile(repo, configPath, "user.signingKey", *test.current); err != nil {
					t.Fatal(err)
				}
			}
			if err := client.setConfigFile(repo, configPath, managedSigningKey, "gitctx-value"); err != nil {
				t.Fatal(err)
			}
			if err := client.setConfigFile(repo, configPath, previousSigningKey, "original-value"); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}

			err = client.applyManagedValue(repo, configPath, "user.signingKey", managedSigningKey, previousSigningKey, "")
			if err == nil || !strings.Contains(err.Error(), "changed after gitctx managed it") {
				t.Fatalf("applyManagedValue() error = %v, want user-change refusal", err)
			}
			after, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("local config changed while relinquishing a user-modified value\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

func TestInspectRequiresRepositoryLocalIdentityAndManagedSSHScope(t *testing.T) {
	repo := initRepository(t)
	globalPath := filepath.Join(t.TempDir(), "global.gitconfig")
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+globalPath, "GIT_CONFIG_SYSTEM="+os.DevNull)
	client := &Client{Env: env}
	key := filepath.Join(t.TempDir(), "key")
	writeTestPrivateKey(t, key, 0o600)
	selected := profile.Profile{GitName: "Ada", GitEmail: "ada@example.com", SSHKey: key}
	if err := client.Apply(repo, "personal", selected); err != nil {
		t.Fatal(err)
	}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if state.LocalNameCount != 1 || state.LocalEmailCount != 1 || !state.SSHCommandManaged || !state.SSHVariantManaged {
		t.Fatalf("initial scope state = %#v", state)
	}
	if _, err := client.run(repo, "config", "--global", "user.name", selected.GitName); err != nil {
		t.Fatal(err)
	}
	if _, err := client.run(repo, "config", "--global", "user.email", selected.GitEmail); err != nil {
		t.Fatal(err)
	}
	if _, err := client.run(repo, "config", "--global", "core.sshCommand", state.SSHCommand); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"user.name", "user.email", "core.sshCommand"} {
		if _, err := client.run(repo, "config", "--local", "--unset-all", key); err != nil {
			t.Fatal(err)
		}
	}
	state, err = client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if state.ConfigName != selected.GitName || state.ConfigEmail != selected.GitEmail || state.SSHCommand == "" {
		t.Fatalf("effective values should still match: %#v", state)
	}
	if state.LocalNameCount != 0 || state.LocalEmailCount != 0 || state.SSHCommandManaged {
		t.Fatalf("lost local scope was not detected: %#v", state)
	}
}

func TestInspectReportsInvalidIdentityEnvironment(t *testing.T) {
	repo := initRepository(t)
	clean := &Client{Env: isolatedGitEnvironment()}
	if err := clean.Apply(repo, "personal", profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"}); err != nil {
		t.Fatal(err)
	}
	client := &Client{Env: append(isolatedGitEnvironment(), "GIT_AUTHOR_DATE=garbage")}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if state.AuthorIdentityErr == "" {
		t.Fatalf("Inspect() state = %#v, want author identity error", state)
	}
}

func TestSSHRouteIssueRejectsHostAliasAndAcceptsCanonicalHost(t *testing.T) {
	client := &Client{Env: os.Environ()}
	issue := client.sshRouteIssue([]string{"git@work-alias:owner/repo.git"})
	if issue == "" || !strings.Contains(issue, "Host alias") {
		t.Fatalf("sshRouteIssue(alias) = %q, want Host-alias warning", issue)
	}
	issue = client.sshRouteIssue([]string{"git@github.com:owner/repo.git"})
	if !strings.Contains(issue, "not tested") {
		t.Fatalf("sshRouteIssue(canonical host) = %q, want unverified-routing warning", issue)
	}
	issue = client.sshRouteIssue([]string{"git@github.com:owner/repo.git", "git@personal-alias:owner/backup.git"})
	if issue == "" || !strings.Contains(issue, "personal-alias") || !strings.Contains(issue, "Host alias") {
		t.Fatalf("sshRouteIssue(later alias) = %q, want specific Host-alias warning", issue)
	}
}

func TestApplyTargetsRepositoryWhosePathEndsInWhitespace(t *testing.T) {
	parent := t.TempDir()
	plainRepo := filepath.Join(parent, "repo")
	trailingWhitespace := " "
	if runtime.GOOS == "windows" {
		// Win32 normalizes a trailing ASCII space away. A non-breaking space is
		// still whitespace to strings.TrimSpace but names a distinct directory.
		trailingWhitespace = "\u00a0"
	}
	spaceRepo := filepath.Join(parent, "repo"+trailingWhitespace)
	for _, repo := range []string{plainRepo, spaceRepo} {
		command := exec.Command("git", "init", "--quiet", repo)
		command.Env = isolatedGitEnvironment()
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git init %q: %v: %s", repo, err, output)
		}
	}
	client := &Client{Env: isolatedGitEnvironment()}
	if err := client.Apply(spaceRepo, "personal", profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"}); err != nil {
		t.Fatal(err)
	}
	spaceState, err := client.Inspect(spaceRepo)
	if err != nil {
		t.Fatal(err)
	}
	plainState, err := client.Inspect(plainRepo)
	if err != nil {
		t.Fatal(err)
	}
	expectedInfo, err := os.Stat(spaceRepo)
	if err != nil {
		t.Fatal(err)
	}
	resolvedInfo, err := os.Stat(spaceState.Repository)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(expectedInfo, resolvedInfo) || spaceState.Profile != "personal" {
		t.Fatalf("space repository state = %#v", spaceState)
	}
	if plainState.Profile != "" {
		t.Fatalf("plain repository was changed: %#v", plainState)
	}
}

func TestReplaceLocalConfigRefusesConcurrentChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotLocalConfig(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("concurrent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceLocalConfig(snapshot, snapshot.data, []byte("replacement\n")); err == nil || !strings.Contains(err.Error(), "changed concurrently") {
		t.Fatalf("replaceLocalConfig() error = %v, want conflict", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "concurrent\n" {
		t.Fatalf("config = %q, want concurrent content preserved", data)
	}
}

func TestApplyRefusesRepositoryWithLinkedWorktree(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	if _, err := client.run(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--quiet", "--allow-empty", "-m", "initial"); err != nil {
		t.Fatalf("create initial commit: %v", err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if _, err := client.run(repo, "worktree", "add", "--quiet", "-b", "linked", linked); err != nil {
		t.Fatalf("add worktree: %v", err)
	}
	state, inspectErr := client.Inspect(repo)
	if inspectErr != nil {
		t.Fatalf("Inspect() error = %v", inspectErr)
	}
	if !state.MultipleWorktrees {
		t.Fatalf("Inspect() did not report multiple linked worktrees: %#v", state)
	}

	err := client.Apply(repo, "personal", profile.Profile{GitName: "Ada", GitEmail: "ada@example.com"})
	if err == nil || !strings.Contains(err.Error(), "multiple linked worktrees") {
		t.Fatalf("Apply() error = %v, want linked-worktree refusal", err)
	}
	values, getErr := client.getLocalAll(repo, profileKey)
	if getErr != nil {
		t.Fatalf("getLocalAll() error = %v", getErr)
	}
	if len(values) != 0 {
		t.Fatalf("profile marker = %q after refusal", values)
	}
}

func TestConcurrentApplyLeavesOneCompleteProfile(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	profiles := map[string]profile.Profile{
		"work":     {GitName: "Work User", GitEmail: "work@example.com"},
		"personal": {GitName: "Personal User", GitEmail: "personal@example.com"},
	}
	const count = 10
	start := make(chan struct{})
	errorsFound := make(chan error, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		name := "work"
		if index%2 == 1 {
			name = "personal"
		}
		group.Add(1)
		go func(name string) {
			defer group.Done()
			<-start
			if err := client.apply(repo, name, profiles[name], time.Minute); err != nil {
				errorsFound <- err
			}
		}(name)
	}
	close(start)
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("Apply() error = %v", err)
	}

	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	selected, exists := profiles[state.Profile]
	if !exists {
		t.Fatalf("final profile = %q", state.Profile)
	}
	if state.ConfigName != selected.GitName || state.ConfigEmail != selected.GitEmail ||
		state.GitName != selected.GitName || state.GitEmail != selected.GitEmail ||
		state.CommitterName != selected.GitName || state.CommitterEmail != selected.GitEmail {
		t.Fatalf("final state mixes profiles: %#v", state)
	}
}

func TestResolvePathExpandsPlatformHomeForms(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "home", path: "~", want: home},
		{name: "slash", path: "~/keys/id", want: filepath.Join(home, "keys", "id")},
		{name: "native separator", path: "~" + string(filepath.Separator) + filepath.Join("keys", "id"), want: filepath.Join(home, "keys", "id")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ResolvePath(test.path)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("ResolvePath(%q) = %q, want %q", test.path, got, test.want)
			}
		})
	}
}

func TestValidateSSHPrivateKeyRejectsNonKeyAndLoosePermissions(t *testing.T) {
	expandingPath := filepath.Join(t.TempDir(), "key-${GITCTX_TEST_KEY}")
	writeTestPrivateKey(t, expandingPath, 0o600)
	if _, err := ValidateSSHPrivateKey(expandingPath); err == nil || !strings.Contains(err.Error(), "environment-variable syntax") {
		t.Fatalf("ValidateSSHPrivateKey(expanding path) error = %v", err)
	}
	nonKey := filepath.Join(t.TempDir(), "ordinary-file")
	if err := os.WriteFile(nonKey, []byte("not a private key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSSHPrivateKey(nonKey); err == nil || !strings.Contains(err.Error(), "private-key header") {
		t.Fatalf("ValidateSSHPrivateKey(non-key) error = %v", err)
	}
	headerOnly := filepath.Join(t.TempDir(), "header-only")
	if err := os.WriteFile(headerOnly, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ngarbage\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSSHPrivateKey(headerOnly); err == nil || !strings.Contains(err.Error(), "not a valid private key") {
		t.Fatalf("ValidateSSHPrivateKey(header-only) error = %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	loose := filepath.Join(t.TempDir(), "loose-key")
	writeTestPrivateKey(t, loose, 0o644)
	if _, err := ValidateSSHPrivateKey(loose); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("ValidateSSHPrivateKey(loose) error = %v", err)
	}
}

func TestIsSSHRemote(t *testing.T) {
	tests := map[string]bool{
		"git@github.com:owner/repo.git":       true,
		"work-alias:owner/repo.git":           true,
		"ssh://git@github.com/owner/repo.git": true,
		"git+ssh://github.com/owner/repo.git": true,
		"ssh+git://github.com/owner/repo.git": true,
		"ssh:///owner/repo.git":               false,
		"ssh://git:password@github.com/repo":  false,
		"SSH://github.com/owner/repo.git":     false,
		"git@[2001:db8::1]:owner/repo.git":    true,
		"git@-alias:owner/repo.git":           false,
		"git@:owner/repo.git":                 false,
		"https://github.com/owner/repo.git":   false,
		"file:///tmp/repo.git":                false,
		"ext::ssh github.com owner/repo.git":  false,
		"../local/repo.git":                   false,
		`C:\\Users\\person\\repo.git`:         false,
		`C:repo.git`:                          false,
		" ssh://github.com/owner/repo.git":    false,
	}
	for remote, want := range tests {
		if got := IsSSHRemote(remote); got != want {
			t.Errorf("IsSSHRemote(%q) = %v, want %v", remote, got, want)
		}
	}
}

func TestInspectUsesSoleNonOriginRemoteForPush(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	if _, err := client.run(repo, "remote", "add", "deploy", "https://github.com/ada/project.git"); err != nil {
		t.Fatal(err)
	}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if state.PushRemote != "deploy" || state.PushURL != "https://github.com/ada/project.git" {
		t.Fatalf("push state = %#v", state)
	}
}

func TestInspectFailsClosedForUnresolvedExplicitPushSelector(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	if _, err := client.run(repo, "config", "branch.master.pushRemote", "ssh://git@example.com/owner/repo.git"); err != nil {
		t.Fatal(err)
	}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !state.PushRemoteExplicit || state.PushRemote == "" || len(state.PushURLs) != 0 {
		t.Fatalf("push state = %#v, want explicit unresolved selector", state)
	}
}

func TestInspectFailsClosedForEmptyExplicitPushSelector(t *testing.T) {
	repo := initRepository(t)
	client := &Client{Env: isolatedGitEnvironment()}
	if _, err := client.run(repo, "remote", "add", "origin", "git@github.com:ada/project.git"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.run(repo, "config", "remote.pushDefault", ""); err != nil {
		t.Fatal(err)
	}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !state.PushRemoteExplicit || state.PushRemote != "" || len(state.EffectivePushURLs()) != 0 || state.SSHRouteIssue != "" {
		t.Fatalf("push state = %#v, want explicit empty unresolved selector", state)
	}
}

func initRepository(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	command := exec.Command("git", "init", "--quiet", repo)
	command.Env = isolatedGitEnvironment()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init error = %v: %s", err, output)
	}
	return repo
}

func isolatedGitEnvironment() []string {
	env := os.Environ()
	env = append(env, "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_SYSTEM="+os.DevNull)
	return env
}

func writeTestPrivateKey(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
