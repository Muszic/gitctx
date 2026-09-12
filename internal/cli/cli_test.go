package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gitctx/internal/autorules"
	"gitctx/internal/configstore"
	"gitctx/internal/profile"
)

func TestProfileWorkflow(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "remote", "add", "origin", "git@github.com:ada/project.git")
	key := filepath.Join(t.TempDir(), "id personal")
	writeTestPrivateKey(t, key, 0o600)

	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")

	stdout, stderr, code := runCLI(t, "add", "personal", "--name", "Ada Lovelace", "--email", "ada@example.com", "--github", "@ada", "--ssh-key", key, "--config", configPath, "--json")
	if code != 0 {
		t.Fatalf("add exit code = %d, stderr = %q", code, stderr)
	}
	assertSuccessfulEnvelope(t, stdout, "add")

	stdout, stderr, code = runCLI(t, "use", "personal", "--repo", repo, "--config", configPath, "--json")
	if code != 0 {
		t.Fatalf("use exit code = %d, stderr = %q, stdout = %q", code, stderr, stdout)
	}
	assertSuccessfulEnvelope(t, stdout, "use")

	stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != 0 {
		t.Fatalf("current exit code = %d, stderr = %q", code, stderr)
	}
	var currentEnvelope struct {
		OK   bool          `json:"ok"`
		Data currentOutput `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &currentEnvelope); err != nil {
		t.Fatalf("current JSON error = %v, output = %q", err, stdout)
	}
	if !currentEnvelope.OK || currentEnvelope.Data.Profile != "personal" || currentEnvelope.Data.GitEmail != "ada@example.com" || currentEnvelope.Data.Status != "warning" {
		t.Fatalf("current envelope = %#v", currentEnvelope)
	}

	stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != 0 {
		t.Fatalf("doctor exit code = %d, stderr = %q, stdout = %q", code, stderr, stdout)
	}
	assertSuccessfulEnvelope(t, stdout, "doctor")

	runGit(t, repo, "config", "--local", "user.email", "work@example.com")
	stdout, _, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != 1 {
		t.Fatalf("mismatched doctor exit code = %d, want 1; output = %q", code, stdout)
	}
}

func TestCurrentAndDoctorFlagProfileSharedByLaterWorktree(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--config", configPath); code != exitOK {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != exitOK {
		t.Fatalf("use exit code = %d: %s", code, stderr)
	}
	runGit(t, repo, "commit", "--quiet", "--allow-empty", "-m", "initial")
	linked := filepath.Join(t.TempDir(), "linked")
	runGit(t, repo, "worktree", "add", "--quiet", "-b", "linked", linked)

	stdout, stderr, code := runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("current exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var currentResponse struct {
		OK       bool          `json:"ok"`
		Data     currentOutput `json:"data"`
		Warnings []notice      `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
		t.Fatalf("current JSON error = %v: %s", err, stdout)
	}
	if !currentResponse.Data.MultipleWorktrees || currentResponse.Data.Status != "mismatch" {
		t.Fatalf("current data = %#v, want unsafe shared worktree state", currentResponse.Data)
	}
	if !hasNotice(currentResponse.Warnings, "multiple_worktrees_unsafe") {
		t.Fatalf("current warnings = %#v, want multiple_worktrees_unsafe", currentResponse.Warnings)
	}
	human, _, code := runCLI(t, "current", "--repo", repo, "--config", configPath)
	if code != exitOK || !strings.Contains(human, "multiple linked worktrees") {
		t.Fatalf("human current output = %q, code = %d; want visible worktree warning", human, code)
	}

	stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" || !strings.Contains(stdout, `"id":"worktree_scope"`) {
		t.Fatalf("doctor output = %q, stderr = %q, code = %d; want worktree_scope failure", stdout, stderr, code)
	}
}

func TestProfileUpdateReportsAndFixesStaleManagedSSH(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	key := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestPrivateKey(t, key, 0o600)
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--ssh-key", key, "--config", configPath); code != exitOK {
		t.Fatalf("add with key exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != exitOK {
		t.Fatalf("use exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "add", "personal", "--force", "--name", "Ada", "--email", "ada@example.com", "--config", configPath); code != exitOK {
		t.Fatalf("replace profile without key exit code = %d: %s", code, stderr)
	}

	stdout, stderr, code := runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("current exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var currentResponse struct {
		Data     currentOutput `json:"data"`
		Warnings []notice      `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
		t.Fatal(err)
	}
	if currentResponse.Data.Status != "mismatch" || currentResponse.Data.Authentication != "SSH configuration mismatch" || !currentResponse.Data.SSHManagementStale {
		t.Fatalf("stale current data = %#v", currentResponse.Data)
	}
	if !hasNotice(currentResponse.Warnings, "stale_managed_ssh") {
		t.Fatalf("stale current warnings = %#v", currentResponse.Warnings)
	}
	stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" || !strings.Contains(stdout, "gitctx SSH management metadata remains") {
		t.Fatalf("doctor output = %q, stderr = %q, code = %d; want stale SSH failure", stdout, stderr, code)
	}
	if _, stderr, code := runCLI(t, "fix", "--repo", repo, "--config", configPath); code != exitOK {
		t.Fatalf("fix exit code = %d: %s", code, stderr)
	}
	if command := gitValueIfSet(t, repo, "core.sshCommand"); command != "" {
		t.Fatalf("core.sshCommand after fix = %q, want unset", command)
	}
}

func TestProfileUpdateDoesNotLabelOldSigningKeyAsCurrent(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--signing-key", "OLDKEY", "--signing-format", "openpgp", "--config", configPath); code != exitOK {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != exitOK {
		t.Fatalf("use exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "add", "personal", "--force", "--name", "Ada", "--email", "ada@example.com", "--signing-key", "NEWKEY", "--signing-format", "openpgp", "--config", configPath); code != exitOK {
		t.Fatalf("replace profile exit code = %d: %s", code, stderr)
	}
	stdout, stderr, code := runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("current code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Data     currentOutput `json:"data"`
		Warnings []notice      `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.SigningManaged || !response.Data.SigningManagementMismatch || response.Data.SigningKey != "OLDKEY" || response.Data.Status != "mismatch" {
		t.Fatalf("current signing data = %#v", response.Data)
	}
	if !hasNotice(response.Warnings, "signing_mismatch") {
		t.Fatalf("current warnings = %#v", response.Warnings)
	}
	human, _, _ := runCLI(t, "current", "--repo", repo, "--config", configPath)
	if !strings.Contains(human, "managed state does not match profile") {
		t.Fatalf("human current mislabels old signing key: %q", human)
	}
	if _, stderr, code := runCLI(t, "fix", "--repo", repo, "--config", configPath); code != exitOK {
		t.Fatalf("fix exit code = %d: %s", code, stderr)
	}
	if got := gitValue(t, repo, "user.signingKey"); got != "NEWKEY" {
		t.Fatalf("signing key after fix = %q, want NEWKEY", got)
	}
}

func TestDoctorFailsWhenGitCannotResolveAuthorIdentity(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--config", configPath); code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != 0 {
		t.Fatalf("use exit code = %d: %s", code, stderr)
	}
	t.Setenv("GIT_AUTHOR_DATE", "garbage")
	stdout, _, code := runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe {
		t.Fatalf("doctor exit code = %d, want %d; output = %s", code, exitUnsafe, stdout)
	}
	if !strings.Contains(stdout, "author_identity") || !strings.Contains(stdout, "invalid date") {
		t.Fatalf("doctor output does not report author failure: %s", stdout)
	}
}

func TestDisplayRemoteRedactsURLCredentialsAndQuery(t *testing.T) {
	remotes := []string{
		"https://secret-user:secret-password@example.com/owner/repo.git?token=secret-token#fragment",
		"https://secret-user:secret-password@example.com/%zz?token=secret-token",
		"helper::https://secret-user:secret-password@example.com/repo?token=secret-token",
		"helper::token=secret-token",
		"ssh://git:secret-password@example.com/owner/repo.git?token=secret-token#fragment",
	}
	for _, remote := range remotes {
		displayed := displayRemote(remote)
		for _, secret := range []string{"secret-user", "secret-password", "secret-token", "fragment"} {
			if strings.Contains(displayed, secret) {
				t.Fatalf("displayRemote(%q) leaked %q in %q", remote, secret, displayed)
			}
		}
	}
	displayed := displayRemote(remotes[0])
	if !strings.Contains(displayed, "example.com/owner/repo.git") {
		t.Fatalf("displayRemote() = %q, want host and path", displayed)
	}
	ssh := "ssh://git@example.com/owner/repo.git"
	if displayed := displayRemote(ssh); displayed != ssh {
		t.Fatalf("displayRemote(SSH) = %q, want %q", displayed, ssh)
	}
	if displayed := displayRemote("git@example.com:owner/\x1b[2Jrepo.git"); strings.ContainsRune(displayed, '\x1b') || !strings.Contains(displayed, `\x1b`) {
		t.Fatalf("displayRemote() left a terminal control active: %q", displayed)
	}
}

func TestHumanOutputEscapesControlsFromGitConfig(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "config", "user.name", "Ada\x1b[2J")
	runGit(t, repo, "config", "user.email", "ada@example.com")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	stdout, stderr, code := runCLI(t, "current", "--repo", repo, "--config", filepath.Join(t.TempDir(), "config.json"))
	if code != exitOK || stderr != "" {
		t.Fatalf("current code = %d, stderr = %q", code, stderr)
	}
	if strings.ContainsRune(stdout, '\x1b') || !strings.Contains(stdout, `Ada\x1b[2J`) {
		t.Fatalf("current left a terminal control active: %q", stdout)
	}
}

func TestDoctorDoesNotExposeSSHCommandOrEnvironmentSecrets(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	key := filepath.Join(t.TempDir(), "key")
	writeTestPrivateKey(t, key, 0o600)
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--ssh-key", key, "--config", configPath); code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != 0 {
		t.Fatalf("use exit code = %d: %s", code, stderr)
	}
	const configSecret = "config-secret-token"
	const environmentSecret = "environment-secret-token"
	runGit(t, repo, "config", "--local", "core.sshCommand", "ssh -o ProxyCommand="+configSecret)
	t.Setenv("GIT_SSH_COMMAND", "ssh -o ProxyCommand="+environmentSecret)

	stdout, stderr, code := runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" {
		t.Fatalf("doctor exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if strings.Contains(stdout, configSecret) || strings.Contains(stdout, environmentSecret) {
		t.Fatalf("doctor exposed an SSH command secret: %s", stdout)
	}
	if !strings.Contains(stdout, "GIT_SSH_COMMAND (set)") {
		t.Fatalf("doctor did not identify the safe override label: %s", stdout)
	}

	stdout, stderr, code = runCLI(t, "fix", "--repo", repo, "--config", configPath, "--json")
	if code != exitGit || stderr != "" {
		t.Fatalf("fix exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if strings.Contains(stdout, configSecret) || strings.Contains(stdout, environmentSecret) {
		t.Fatalf("fix exposed an SSH command secret: %s", stdout)
	}
}

func TestCurrentAndDoctorRedactUnresolvedPushSelector(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "symbolic-ref", "HEAD", "refs/heads/main")
	key := filepath.Join(t.TempDir(), "key")
	writeTestPrivateKey(t, key, 0o600)
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--ssh-key", key, "--config", configPath); code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != 0 {
		t.Fatalf("use exit code = %d: %s", code, stderr)
	}
	secretSelector := "https://secret-user:secret-password@example.com/repo.git?token=secret-token"
	runGit(t, repo, "config", "branch.main.pushRemote", secretSelector)
	for _, command := range []string{"current", "doctor"} {
		stdout, stderr, _ := runCLI(t, command, "--repo", repo, "--config", configPath, "--json")
		combined := stdout + stderr
		for _, secret := range []string{"secret-user", "secret-password", "secret-token"} {
			if strings.Contains(combined, secret) {
				t.Fatalf("%s leaked %q: %s", command, secret, combined)
			}
		}
	}
}

func TestCanonicalDirectoryUsesOnDiskCase(t *testing.T) {
	actual := filepath.Join(t.TempDir(), "Personal")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	requested := filepath.Join(filepath.Dir(actual), "personal")
	requestedInfo, err := os.Stat(requested)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("filesystem is case-sensitive")
	}
	if err != nil {
		t.Fatal(err)
	}
	actualInfo, err := os.Stat(actual)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(requestedInfo, actualInfo) {
		t.Skip("case variant names a different directory")
	}
	canonical, err := canonicalDirectory(requested)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(canonical) != "Personal" {
		t.Fatalf("canonicalDirectory() = %q, want on-disk spelling", canonical)
	}
}

func TestConfigPathUsesOnDiskCase(t *testing.T) {
	root := t.TempDir()
	actualDir := filepath.Join(root, "GitCtx")
	if err := os.Mkdir(actualDir, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasDir := filepath.Join(root, "gitctx")
	aliasInfo, err := os.Stat(aliasDir)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("filesystem is case-sensitive")
	}
	if err != nil {
		t.Fatal(err)
	}
	actualInfo, err := os.Stat(actualDir)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(aliasInfo, actualInfo) {
		t.Skip("case variant names a different directory")
	}

	actualConfig, err := autorules.CanonicalPathAllowMissing(filepath.Join(actualDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	aliasConfig := filepath.Join(aliasDir, "config.json")
	stdout, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--config", aliasConfig, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("add exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Data struct {
			ConfigPath string `json:"config_path"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.ConfigPath != actualConfig {
		t.Fatalf("config path = %q, want on-disk spelling %q", response.Data.ConfigPath, actualConfig)
	}
}

func TestDanglingConfigSymlinkIsPreserved(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	target := filepath.Join(directory, "missing-target.json")
	if err := os.Symlink(target, configPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	_, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--config", configPath)
	if code != exitConfig || !strings.Contains(stderr, "unresolved symbolic link") {
		t.Fatalf("add exit code = %d, stderr = %q", code, stderr)
	}
	info, err := os.Lstat(configPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("config symlink was replaced: info=%v error=%v", info, err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling target unexpectedly exists: %v", err)
	}
}

func TestTwoRepositoriesRemainIndependent(t *testing.T) {
	workRepo := t.TempDir()
	personalRepo := t.TempDir()
	runGit(t, workRepo, "init", "--quiet")
	runGit(t, personalRepo, "init", "--quiet")
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")

	for _, item := range []struct {
		profile string
		name    string
		email   string
		repo    string
	}{
		{profile: "work", name: "Work User", email: "work@example.com", repo: workRepo},
		{profile: "personal", name: "Personal User", email: "personal@example.com", repo: personalRepo},
	} {
		_, stderr, code := runCLI(t, "add", item.profile, "--name", item.name, "--email", item.email, "--config", configPath)
		if code != 0 {
			t.Fatalf("add %s exit code = %d: %s", item.profile, code, stderr)
		}
		_, stderr, code = runCLI(t, "use", item.profile, "--repo", item.repo, "--config", configPath)
		if code != 0 {
			t.Fatalf("use %s exit code = %d: %s", item.profile, code, stderr)
		}
	}

	if got := gitValue(t, workRepo, "user.email"); got != "work@example.com" {
		t.Fatalf("work email = %q", got)
	}
	if got := gitValue(t, personalRepo, "user.email"); got != "personal@example.com" {
		t.Fatalf("personal email = %q", got)
	}
}

func TestAutomaticDirectoryRulePreservesGlobalIdentity(t *testing.T) {
	root := t.TempDir()
	globalConfig := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "gitctx", "config.json")
	personalDir := filepath.Join(root, "personal")
	repo := filepath.Join(personalDir, "project")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", globalConfig)
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	runGit(t, root, "config", "--global", "user.name", "Work User")
	runGit(t, root, "config", "--global", "user.email", "work@example.com")
	runGit(t, repo, "init", "--quiet")

	_, stderr, code := runCLI(t, "add", "personal", "--name", "Personal User", "--email", "personal@example.com", "--config", configPath)
	if code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	_, stderr, code = runCLI(t, "auto", "add", personalDir, "personal", "--config", configPath)
	if code != 0 {
		t.Fatalf("auto add exit code = %d: %s", code, stderr)
	}

	stdout, stderr, code := runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != 0 {
		t.Fatalf("current exit code = %d: %s", code, stderr)
	}
	var currentEnvelope struct {
		Data currentOutput `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &currentEnvelope); err != nil {
		t.Fatalf("current JSON error = %v", err)
	}
	if currentEnvelope.Data.Profile != "personal" || currentEnvelope.Data.ProfileSource != "auto" || currentEnvelope.Data.GitEmail != "personal@example.com" {
		t.Fatalf("current data = %#v", currentEnvelope.Data)
	}
	_, stderr, code = runCLI(t, "auto", "sync", "--config", configPath)
	if code != 0 {
		t.Fatalf("auto sync exit code = %d: %s", code, stderr)
	}
	if got := globalGitValue(t, root, "user.email"); got != "work@example.com" {
		t.Fatalf("global user.email = %q, want work@example.com", got)
	}

	_, stderr, code = runCLI(t, "auto", "remove", personalDir, "--config", configPath)
	if code != 0 {
		t.Fatalf("auto remove exit code = %d: %s", code, stderr)
	}
	if got := effectiveGitValue(t, repo, "user.email"); got != "work@example.com" {
		t.Fatalf("effective email after rule removal = %q, want work@example.com", got)
	}

	missingDir := filepath.Join(root, "temporarily-missing")
	if err := os.Mkdir(missingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code = runCLI(t, "auto", "add", missingDir, "personal", "--config", configPath); code != 0 {
		t.Fatalf("auto add missing-dir rule exit code = %d: %s", code, stderr)
	}
	if err := os.Remove(missingDir); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code = runCLI(t, "auto", "sync", "--config", configPath); code != 0 {
		t.Fatalf("auto sync with absent directory exit code = %d: %s", code, stderr)
	}
	if _, stderr, code = runCLI(t, "auto", "remove", missingDir, "--config", configPath); code != 0 {
		t.Fatalf("auto remove absent directory exit code = %d: %s", code, stderr)
	}
}

func TestAutomaticRuleSurvivesConfigRelocationWithoutLeavingStaleIdentity(t *testing.T) {
	root := t.TempDir()
	globalConfig := filepath.Join(root, "global.gitconfig")
	originalConfig := filepath.Join(root, "old", "config.json")
	relocatedConfig := filepath.Join(root, "new", "config.json")
	personalDir := filepath.Join(root, "personal")
	repo := filepath.Join(personalDir, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", globalConfig)
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	runGit(t, root, "config", "--global", "user.name", "Work User")
	runGit(t, root, "config", "--global", "user.email", "work@example.com")
	runGit(t, repo, "init", "--quiet")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Personal User", "--email", "personal@example.com", "--config", originalConfig); code != exitOK {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "auto", "add", personalDir, "personal", "--config", originalConfig); code != exitOK {
		t.Fatalf("auto add exit code = %d: %s", code, stderr)
	}
	if got := effectiveGitValue(t, repo, "user.email"); got != "personal@example.com" {
		t.Fatalf("effective email before relocation = %q", got)
	}
	if err := os.MkdirAll(filepath.Dir(relocatedConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(originalConfig, relocatedConfig); err != nil {
		t.Fatal(err)
	}

	if _, stderr, code := runCLI(t, "auto", "remove", personalDir, "--config", relocatedConfig); code != exitConfig || !strings.Contains(stderr, "moved profile store") {
		t.Fatalf("direct relocated remove code = %d, stderr = %q; want fail-closed relocation warning", code, stderr)
	}
	config, err := (configstore.Store{Path: relocatedConfig}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Rules) != 1 {
		t.Fatalf("failed relocation cleanup did not roll back stored rule: %#v", config.Rules)
	}
	for _, profileName := range config.Rules {
		if profileName != "personal" {
			t.Fatalf("failed relocation cleanup restored wrong profile: %#v", config.Rules)
		}
	}
	if err := os.Symlink(relocatedConfig, originalConfig); err != nil {
		t.Skipf("cannot create relocation compatibility symlink: %v", err)
	}
	if _, stderr, code := runCLI(t, "auto", "remove", personalDir, "--config", originalConfig); code != exitOK {
		t.Fatalf("remove through prior config path exit code = %d: %s", code, stderr)
	}
	if got := effectiveGitValue(t, repo, "user.email"); got != "work@example.com" {
		t.Fatalf("effective email after relocated cleanup = %q, want work identity", got)
	}
}

func TestAutomaticRuleCanBeRemovedAfterCaseOnlyDirectoryRename(t *testing.T) {
	root := t.TempDir()
	globalConfig := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "gitctx", "config.json")
	originalDir := filepath.Join(root, "Personal")
	renamedDir := filepath.Join(root, "personal")
	repo := filepath.Join(originalDir, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", globalConfig)
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	runGit(t, root, "config", "--global", "user.name", "Work User")
	runGit(t, root, "config", "--global", "user.email", "work@example.com")
	runGit(t, repo, "init", "--quiet")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Personal User", "--email", "personal@example.com", "--config", configPath); code != exitOK {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "auto", "add", originalDir, "personal", "--config", configPath); code != exitOK {
		t.Fatalf("auto add exit code = %d: %s", code, stderr)
	}
	if err := os.Rename(originalDir, renamedDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(originalDir); err != nil {
		t.Skip("filesystem is case-sensitive; case-only alias behavior does not apply")
	}
	if _, stderr, code := runCLI(t, "auto", "remove", renamedDir, "--config", configPath); code != exitOK {
		t.Fatalf("auto remove after case-only rename exit code = %d: %s", code, stderr)
	}
	if got := effectiveGitValue(t, filepath.Join(renamedDir, "repo"), "user.email"); got != "work@example.com" {
		t.Fatalf("effective email after removal = %q, want work identity", got)
	}
}

func TestCurrentAndDoctorDetectInactiveAutomaticRule(t *testing.T) {
	root := t.TempDir()
	globalConfig := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "gitctx", "config.json")
	personalDir := filepath.Join(root, "personal")
	repo := filepath.Join(personalDir, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", globalConfig)
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	runGit(t, root, "config", "--global", "user.name", "Work User")
	runGit(t, root, "config", "--global", "user.email", "work@example.com")
	runGit(t, repo, "init", "--quiet")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Personal User", "--email", "personal@example.com", "--config", configPath); code != exitOK {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "auto", "add", personalDir, "personal", "--config", configPath); code != exitOK {
		t.Fatalf("auto add exit code = %d: %s", code, stderr)
	}
	runGit(t, root, "config", "--global", "--unset-all", "include.path")

	stdout, stderr, code := runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("current exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var currentResponse struct {
		Data     currentOutput `json:"data"`
		Warnings []notice      `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
		t.Fatal(err)
	}
	if currentResponse.Data.Profile != "personal" || currentResponse.Data.ProfileSource != "auto_missing" || currentResponse.Data.Status != "mismatch" {
		t.Fatalf("inactive automatic current data = %#v", currentResponse.Data)
	}
	if !hasNotice(currentResponse.Warnings, "auto_rule_inactive") {
		t.Fatalf("inactive automatic warnings = %#v", currentResponse.Warnings)
	}
	stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" || !strings.Contains(stdout, "gitctx auto sync") {
		t.Fatalf("doctor output = %q, stderr = %q, code = %d; want auto sync guidance", stdout, stderr, code)
	}
	if _, stderr, code := runCLI(t, "auto", "sync", "--config", configPath); code != exitOK {
		t.Fatalf("auto sync exit code = %d: %s", code, stderr)
	}
	stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || !strings.Contains(stdout, `"profile_source":"auto"`) {
		t.Fatalf("current after repair output = %q, stderr = %q, code = %d", stdout, stderr, code)
	}
}

func TestDoctorChecksOriginPushURL(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "remote", "add", "origin", "git@github.com:ada/project.git")
	runGit(t, repo, "remote", "add", "deploy", "https://github.com/ada/project.git")
	runGit(t, repo, "remote", "set-url", "--push", "deploy", "git@github.com:ada/project.git")
	runGit(t, repo, "remote", "set-url", "--add", "--push", "deploy", "https://github.com/ada/project.git")
	runGit(t, repo, "config", "remote.pushDefault", "deploy")
	key := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestPrivateKey(t, key, 0o600)
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")

	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--ssh-key", key, "--config", configPath); code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != exitUnsafe {
		t.Fatalf("use exit code = %d, want unsafe status: %s", code, stderr)
	}
	stdout, stderr, code := runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != 1 || stderr != "" {
		t.Fatalf("doctor exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Data diagnosis `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range response.Data.Checks {
		if item.ID == "push_remote" {
			found = true
			if item.Status != statusFail || !strings.Contains(item.Actual, "deploy:") || !strings.Contains(item.Actual, "https://github.com/ada/project.git") {
				t.Fatalf("push check = %#v", item)
			}
		}
	}
	if !found {
		t.Fatalf("diagnosis has no push_remote check: %#v", response.Data)
	}
	stdout, stderr, code = runCLI(t, "fix", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" {
		t.Fatalf("fix exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var fixResponse struct {
		Data currentOutput `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &fixResponse); err != nil {
		t.Fatal(err)
	}
	if fixResponse.Data.Status != "mismatch" || fixResponse.Data.Authentication != "SSH configuration mismatch" {
		t.Fatalf("fix data = %#v", fixResponse.Data)
	}
}

func TestExplicitEmptyPushSelectorFailsClosed(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "remote", "add", "origin", "git@github.com:ada/project.git")
	runGit(t, repo, "config", "remote.pushDefault", "")
	key := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestPrivateKey(t, key, 0o600)
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")

	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--ssh-key", key, "--config", configPath); code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != exitUnsafe {
		t.Fatalf("use exit code = %d, want unsafe status: %s", code, stderr)
	}
	stdout, stderr, code := runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != 1 || stderr != "" {
		t.Fatalf("doctor exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Data diagnosis `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range response.Data.Checks {
		if item.ID == "push_remote" {
			found = true
			if item.Status != statusFail || item.Actual != "(empty)" {
				t.Fatalf("push check = %#v", item)
			}
		}
	}
	if !found {
		t.Fatalf("diagnosis has no push_remote check: %#v", response.Data)
	}
}

func TestMalformedSSHRemoteFailsClosed(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "remote", "add", "origin", "git@-alias:owner/repo.git")
	key := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestPrivateKey(t, key, 0o600)
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--ssh-key", key, "--config", configPath); code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != exitUnsafe {
		t.Fatalf("use exit code = %d, want unsafe status: %s", code, stderr)
	}
	stdout, stderr, code := runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" {
		t.Fatalf("doctor exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Data diagnosis `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	for _, item := range response.Data.Checks {
		if item.ID == "ssh_route" && item.Status == statusPass {
			t.Fatalf("malformed SSH route was reported as healthy: %#v", item)
		}
		if item.ID == "push_remote" && item.Status == statusFail {
			return
		}
	}
	t.Fatalf("doctor did not fail the malformed push remote: %#v", response.Data)
}

func TestAutomaticRuleRequiresExplicitUseForSSHAndSigning(t *testing.T) {
	root := t.TempDir()
	globalConfig := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "gitctx", "config.json")
	personalDir := filepath.Join(root, "personal")
	repo := filepath.Join(personalDir, "project")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "id_ed25519")
	writeTestPrivateKey(t, key, 0o600)
	t.Setenv("GIT_CONFIG_GLOBAL", globalConfig)
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "remote", "add", "origin", "git@github.com:ada/project.git")

	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--ssh-key", key, "--signing-key", "ABC123", "--signing-format", "openpgp", "--config", configPath); code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	stdout, stderr, code := runCLI(t, "auto", "add", personalDir, "personal", "--config", configPath, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("auto add exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var addResponse envelope
	if err := json.Unmarshal([]byte(stdout), &addResponse); err != nil {
		t.Fatal(err)
	}
	if len(addResponse.Warnings) != 3 {
		t.Fatalf("auto add warnings = %#v, want linked-worktree, SSH, and signing warnings", addResponse.Warnings)
	}

	stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("current exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var currentResponse struct {
		Data     currentOutput `json:"data"`
		Warnings []notice      `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
		t.Fatal(err)
	}
	if currentResponse.Data.ProfileSource != "auto" || currentResponse.Data.Authentication != "automatic identity only (SSH not applied)" || !currentResponse.Data.SigningPending || currentResponse.Data.Status != "warning" {
		t.Fatalf("automatic current data = %#v", currentResponse.Data)
	}
	if got := gitValueIfSet(t, repo, "core.sshCommand"); got != "" {
		t.Fatalf("automatic core.sshCommand = %q, want unset", got)
	}
	if got := gitValueIfSet(t, repo, "user.signingKey"); got != "" {
		t.Fatalf("automatic user.signingKey = %q, want unset", got)
	}
	stdout, stderr, code = runCLI(t, "fix", "--repo", repo, "--config", configPath, "--json")
	if code != exitProfile || stderr != "" {
		t.Fatalf("fix automatic profile exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var fixError envelope
	if err := json.Unmarshal([]byte(stdout), &fixError); err != nil {
		t.Fatal(err)
	}
	if fixError.Error == nil || fixError.Error.Code != "auto_profile_not_pinned" {
		t.Fatalf("fix automatic profile response = %#v", fixError)
	}

	if _, stderr, code = runCLI(t, "use", "personal", "--repo", repo, "--config", configPath); code != 0 {
		t.Fatalf("use exit code = %d: %s", code, stderr)
	}
	stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("current after use exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
		t.Fatal(err)
	}
	if currentResponse.Data.ProfileSource != "local" || currentResponse.Data.Authentication != "repository-scoped SSH (routing unverified)" || !currentResponse.Data.SigningManaged || currentResponse.Data.SigningPending || currentResponse.Data.Status != "warning" {
		t.Fatalf("explicit current data = %#v", currentResponse.Data)
	}
}

func TestAddRejectsReadableNonKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-key")
	if err := os.WriteFile(path, []byte("ordinary readable file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--ssh-key", path, "--config", filepath.Join(t.TempDir(), "config.json"), "--json")
	if code != exitUsage || stderr != "" {
		t.Fatalf("exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response envelope
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != "invalid_ssh_key" {
		t.Fatalf("response = %#v", response)
	}
}

func TestConcurrentAddsPreserveEveryProfile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	const count = 24
	start := make(chan struct{})
	errorsFound := make(chan string, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			name := fmt.Sprintf("profile-%02d", index)
			_, stderr, code := runCLI(t, "add", name, "--name", name, "--email", fmt.Sprintf("p%02d@example.com", index), "--config", configPath)
			if code != 0 {
				errorsFound <- fmt.Sprintf("%s: code %d: %s", name, code, stderr)
			}
		}()
	}
	close(start)
	group.Wait()
	close(errorsFound)
	for message := range errorsFound {
		t.Error(message)
	}

	config, err := (configstore.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Profiles) != count {
		t.Fatalf("saved profiles = %d, want %d", len(config.Profiles), count)
	}
}

func TestGlobalProfileMarkerIsNotClassifiedAsAutomatic(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	globalConfig := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "gitctx", "config.json")
	t.Setenv("GIT_CONFIG_GLOBAL", globalConfig)
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	runGit(t, repo, "init", "--quiet")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--config", configPath); code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	runGit(t, root, "config", "--global", "user.name", "Ada")
	runGit(t, root, "config", "--global", "user.email", "ada@example.com")
	runGit(t, root, "config", "--global", "gitctx.profile", "personal")

	stdout, stderr, code := runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("current exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var currentResponse struct {
		Data     currentOutput `json:"data"`
		Warnings []notice      `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
		t.Fatal(err)
	}
	if currentResponse.Data.ProfileSource != "nonlocal" || currentResponse.Data.Status != "mismatch" || len(currentResponse.Warnings) == 0 {
		t.Fatalf("current response = %#v", currentResponse)
	}
	stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" {
		t.Fatalf("doctor exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var doctorResponse struct {
		Data diagnosis `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &doctorResponse); err != nil {
		t.Fatal(err)
	}
	foundSourceFailure := false
	for _, item := range doctorResponse.Data.Checks {
		if item.ID == "profile_source" && item.Status == statusFail {
			foundSourceFailure = true
		}
	}
	if !foundSourceFailure {
		t.Fatalf("doctor response has no profile-source failure: %#v", doctorResponse.Data)
	}
}

func TestAutoGenerationMismatchIsDetectedAndSyncRepairsIt(t *testing.T) {
	root := t.TempDir()
	globalConfig := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "gitctx", "config.json")
	directory := filepath.Join(root, "personal")
	repo := filepath.Join(directory, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", globalConfig)
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	runGit(t, repo, "init", "--quiet")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--config", configPath); code != 0 {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, "auto", "add", directory, "personal", "--config", configPath); code != 0 {
		t.Fatalf("auto add exit code = %d: %s", code, stderr)
	}
	store := configstore.Store{Path: configPath}
	config, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	config.Profiles["unrelated"] = profile.Profile{GitName: "Other", GitEmail: "other@example.com"}
	if err := store.Save(config); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("current exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Data currentOutput `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.ProfileSource != "nonlocal" || response.Data.Status != "mismatch" {
		t.Fatalf("stale generation current data = %#v", response.Data)
	}
	if _, stderr, code := runCLI(t, "auto", "sync", "--config", configPath); code != 0 {
		t.Fatalf("auto sync exit code = %d: %s", code, stderr)
	}
	stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("current after sync exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.ProfileSource != "auto" || response.Data.GitEmail != "ada@example.com" {
		t.Fatalf("repaired generation current data = %#v", response.Data)
	}
}

func TestEmptyConfigValueAndRootAutoRuleAreRejected(t *testing.T) {
	if _, stderr, code := runCLI(t, "list", "--config", ""); code != exitUsage || !strings.Contains(stderr, "--config requires a value") {
		t.Fatalf("empty --config exit code = %d, stderr = %q", code, stderr)
	}
	if _, stderr, code := runCLI(t, "current", "--repo", "", "--config", filepath.Join(t.TempDir(), "config.json")); code != exitUsage || !strings.Contains(stderr, "--repo requires a non-empty path") {
		t.Fatalf("empty --repo exit code = %d, stderr = %q", code, stderr)
	}
	if _, err := canonicalDirectory(string(filepath.Separator)); err == nil {
		t.Fatal("canonicalDirectory(filesystem root) error = nil")
	}
	for _, args := range [][]string{{"auto", "--force"}, {"auto", "list", "--force"}, {"auto", "sync", "--force"}, {"auto", "remove", "/tmp/example", "--force"}} {
		args = append(args, "--config", filepath.Join(t.TempDir(), "config.json"))
		if _, stderr, code := runCLI(t, args...); code != exitUsage || !strings.Contains(stderr, "--force is only valid with auto add") {
			t.Fatalf("%v exit code = %d, stderr = %q", args, code, stderr)
		}
	}
}

func TestAutoListJSONWorksBeforeConfigDirectoryExists(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "global.gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	configPath := filepath.Join(root, "missing", "nested", "config.json")
	stdout, stderr, code := runCLI(t, "auto", "list", "--json", "--config", configPath)
	if code != exitOK || stderr != "" {
		t.Fatalf("auto list code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		OK   bool `json:"ok"`
		Data struct {
			Rules        []autoRule `json:"rules"`
			ManifestPath string     `json:"manifest_path"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil || !response.OK || len(response.Data.Rules) != 0 || response.Data.ManifestPath != "" {
		t.Fatalf("auto list response = %#v, error = %v, output = %q", response, err, stdout)
	}
}

func TestAutoListWarnsWhenSavedAndActiveRulesDiffer(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "global.gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	configPath := filepath.Join(root, "store", "config.json")
	directory := filepath.Join(root, "personal")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--config", configPath); code != exitOK {
		t.Fatalf("add code = %d, stderr = %q", code, stderr)
	}
	store := configstore.Store{Path: configPath}
	config, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	config.Rules[directory] = "personal"
	if err := store.Save(config); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI(t, "auto", "list", "--json", "--config", configPath)
	if code != exitOK || stderr != "" {
		t.Fatalf("stale auto list code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Warnings []notice `json:"warnings"`
		Data     struct {
			ManifestPath string `json:"manifest_path"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil || !hasNotice(response.Warnings, "auto_state_out_of_sync") {
		t.Fatalf("stale auto list warnings = %#v, error = %v, output = %q", response.Warnings, err, stdout)
	}
	if _, stderr, code := runCLI(t, "auto", "sync", "--config", configPath); code != exitOK {
		t.Fatalf("auto sync code = %d, stderr = %q", code, stderr)
	}
	stdout, stderr, code = runCLI(t, "auto", "list", "--json", "--config", configPath)
	if code != exitOK || stderr != "" {
		t.Fatalf("synced auto list code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	response.Warnings = nil
	if err := json.Unmarshal([]byte(stdout), &response); err != nil || hasNotice(response.Warnings, "auto_state_out_of_sync") {
		t.Fatalf("synced auto list warnings = %#v, error = %v, output = %q", response.Warnings, err, stdout)
	}
	if response.Data.ManifestPath == "" {
		t.Fatal("synced auto list returned no manifest path")
	}
	if err := os.Remove(response.Data.ManifestPath); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLI(t, "auto", "list", "--json", "--config", configPath)
	response.Warnings = nil
	if code != exitOK || stderr != "" {
		t.Fatalf("missing-manifest auto list code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil || !hasNotice(response.Warnings, "auto_state_out_of_sync") {
		t.Fatalf("missing-manifest warnings = %#v, error = %v, output = %q", response.Warnings, err, stdout)
	}
	if _, stderr, code := runCLI(t, "auto", "sync", "--config", configPath); code != exitOK {
		t.Fatalf("repair auto sync code = %d, stderr = %q", code, stderr)
	}

	config, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	config.Rules = map[string]string{}
	if err := store.Save(config); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLI(t, "auto", "list", "--json", "--config", configPath)
	response.Warnings = nil
	if code != exitOK || stderr != "" {
		t.Fatalf("removed-but-active auto list code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil || !hasNotice(response.Warnings, "auto_state_out_of_sync") {
		t.Fatalf("removed-but-active warnings = %#v, error = %v, output = %q", response.Warnings, err, stdout)
	}
}

func TestEarlyOptionScanningRespectsValuesAndDoubleDash(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	stdout, stderr, code := runCLI(t, "add", "personal", "--name", "--help", "--email", "ada@example.com", "--config", configPath)
	if code != exitOK || stderr != "" || !strings.Contains(stdout, "--help <ada@example.com>") {
		t.Fatalf("option-like value code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	stored, err := (configstore.Store{Path: configPath}).Load()
	if err != nil || stored.Profiles["personal"].GitName != "--help" {
		t.Fatalf("stored option-like name = %#v, error = %v", stored.Profiles["personal"], err)
	}

	t.Setenv("GITCTX_CONFIG", filepath.Join(t.TempDir(), "default", "config.json"))
	stdout, stderr, code = runCLI(t, "list", "--", "--json")
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, `unexpected argument "--json"`) {
		t.Fatalf("double-dash JSON code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	stdout, stderr, code = runCLI(t, "list", "--", "--config", "/tmp/not-used")
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, `unexpected argument "--config"`) {
		t.Fatalf("double-dash config code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestMalformedConfigUsesJSONRegardlessOfOptionOrder(t *testing.T) {
	for _, args := range [][]string{
		{"list", "--config=", "--json"},
		{"list", "--json", "--config="},
		{"status", "--config=", "--json"},
	} {
		stdout, stderr, code := runCLI(t, args...)
		if code != exitUsage || stderr != "" {
			t.Fatalf("%v code = %d, stderr = %q, output = %q", args, code, stderr, stdout)
		}
		var response envelope
		if err := json.Unmarshal([]byte(stdout), &response); err != nil || response.OK || response.Error == nil {
			t.Fatalf("%v response = %#v, error = %v, output = %q", args, response, err, stdout)
		}
		wantCommand := "list"
		if args[0] == "status" {
			wantCommand = "current"
		}
		if response.Command != wantCommand {
			t.Fatalf("%v command = %q, want %q", args, response.Command, wantCommand)
		}
	}
}

func TestInvalidJSONFlagUsesStableErrorChannel(t *testing.T) {
	for _, args := range [][]string{
		{"list", "--json=garbage", "--json=false"},
		{"list", "--json=false", "--json=garbage"},
		{"list", "--repo", "--json"},
	} {
		stdout, stderr, code := runCLI(t, args...)
		if code != exitUsage || stderr != "" {
			t.Fatalf("%v code = %d, stderr = %q, output = %q", args, code, stderr, stdout)
		}
		var response envelope
		if err := json.Unmarshal([]byte(stdout), &response); err != nil || response.OK || response.Error == nil {
			t.Fatalf("%v response = %#v, error = %v, output = %q", args, response, err, stdout)
		}
	}
}

func TestHelpAndVersionDoNotRequireConfigDirectory(t *testing.T) {
	t.Setenv("GITCTX_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	stdout, stderr, code := runCLI(t, "help")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "Usage:") {
		t.Fatalf("help code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	stdout, stderr, code = runCLI(t, "version")
	if code != 0 || stderr != "" || stdout != "gitctx test\n" {
		t.Fatalf("version code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestEarlyHelpScanningUsesLastFlagValue(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Ada", "--email", "ada@example.com", "--config", configPath); code != exitOK {
		t.Fatalf("add code = %d, stderr = %q", code, stderr)
	}
	stdout, stderr, code := runCLI(t, "list", "--help", "--help=false", "--config", configPath)
	if code != exitOK || stderr != "" || !strings.Contains(stdout, "personal") || strings.Contains(stdout, "Usage:") {
		t.Fatalf("disabled final help code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}

	t.Setenv("GITCTX_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	stdout, stderr, code = runCLI(t, "list", "--help=false", "--help")
	if code != exitOK || stderr != "" || !strings.Contains(stdout, "Usage: gitctx list") {
		t.Fatalf("enabled final help code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	stdout, stderr, code = runCLI(t, "list", "--help=invalid", "--help=false")
	if code != exitUsage || !strings.Contains(stderr, "expects true or false") {
		t.Fatalf("invalid help code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestJSONErrorEnvelope(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	stdout, stderr, code := runCLI(t, "use", "missing", "--config", configPath, "--json")
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty for JSON mode", stderr)
	}
	var response envelope
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("JSON error = %v, output = %q", err, stdout)
	}
	if response.OK || response.Error == nil || response.Error.Code != "profile_not_found" {
		t.Fatalf("response = %#v", response)
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Setenv("GITCTX_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	_, stderr, code := runCLI(t, "missing")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !bytes.Contains([]byte(stderr), []byte("unknown command")) {
		t.Fatalf("stderr = %q, want unknown command error", stderr)
	}
}

func assertSuccessfulEnvelope(t *testing.T, output, command string) {
	t.Helper()
	var response envelope
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		t.Fatalf("JSON error = %v, output = %q", err, output)
	}
	if !response.OK || response.Command != command || response.Error != nil {
		t.Fatalf("response = %#v", response)
	}
}

func hasNotice(notices []notice, code string) bool {
	for _, item := range notices {
		if item.Code == code {
			return true
		}
	}
	return false
}

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(args, bytes.NewBuffer(nil), &stdout, &stderr, "test")
	return stdout.String(), stderr.String(), code
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v error = %v: %s", args, err, output)
	}
}

func gitValue(t *testing.T, repo, key string) string {
	t.Helper()
	command := exec.Command("git", "config", "--local", "--get", key)
	command.Dir = repo
	command.Env = os.Environ()
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git config %s error = %v", key, err)
	}
	return string(bytes.TrimSpace(output))
}

func gitValueIfSet(t *testing.T, repo, key string) string {
	t.Helper()
	command := exec.Command("git", "config", "--local", "--get", key)
	command.Dir = repo
	command.Env = os.Environ()
	output, err := command.Output()
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
		return ""
	}
	if err != nil {
		t.Fatalf("git config %s error = %v", key, err)
	}
	return string(bytes.TrimSpace(output))
}

func effectiveGitValue(t *testing.T, repo, key string) string {
	t.Helper()
	command := exec.Command("git", "config", "--get", key)
	command.Dir = repo
	command.Env = os.Environ()
	output, err := command.Output()
	if err != nil {
		t.Fatalf("effective git config %s error = %v", key, err)
	}
	return string(bytes.TrimSpace(output))
}

func globalGitValue(t *testing.T, dir, key string) string {
	t.Helper()
	command := exec.Command("git", "config", "--global", "--no-includes", "--get", key)
	command.Dir = dir
	command.Env = os.Environ()
	output, err := command.Output()
	if err != nil {
		t.Fatalf("global git config %s error = %v", key, err)
	}
	return string(bytes.TrimSpace(output))
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
