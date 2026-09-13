package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gitctx/internal/configstore"
	"gitctx/internal/gitconfig"
	"gitctx/internal/sshkey"
)

func TestSetupIdentityOnlyDisablesSigningWithoutChangingGlobalConfig(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	globalPath := setupTestGlobalConfig(t, repo)
	configPath := filepath.Join(t.TempDir(), "config.json")
	beforeGlobal := setupTestReadFile(t, globalPath)

	stdout, stderr, code := runCLI(t,
		"setup", "personal",
		"--name", "Ada Lovelace",
		"--email", "ada@example.com",
		"--github", "ada",
		"--repo", repo,
		"--auth", "identity-only",
		"--signing", "disabled",
		"--config", configPath,
		"--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("setup exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestSuccessfulEnvelope(t, stdout)

	afterGlobal := setupTestReadFile(t, globalPath)
	if !bytes.Equal(afterGlobal, beforeGlobal) {
		t.Fatalf("global Git config changed during identity-only setup\nbefore:\n%s\nafter:\n%s", beforeGlobal, afterGlobal)
	}
	if got := gitValue(t, repo, "user.name"); got != "Ada Lovelace" {
		t.Fatalf("local user.name = %q, want Ada Lovelace", got)
	}
	if got := gitValue(t, repo, "user.email"); got != "ada@example.com" {
		t.Fatalf("local user.email = %q, want ada@example.com", got)
	}
	if got := gitValue(t, repo, "gitctx.profile"); got != "personal" {
		t.Fatalf("local gitctx.profile = %q, want personal", got)
	}
	if got := gitValue(t, repo, "commit.gpgSign"); got != "false" {
		t.Fatalf("local commit.gpgSign = %q, want false", got)
	}
	guardPath := gitValue(t, repo, "user.signingKey")
	guardInfo, guardErr := os.Stat(guardPath)
	gitDirInfo, gitDirErr := os.Stat(filepath.Join(repo, ".git"))
	if guardErr != nil || gitDirErr != nil || !os.SameFile(guardInfo, gitDirInfo) {
		t.Fatalf("repository-local user.signingKey guard = %q, want this repository's Git directory (guard error %v, Git directory error %v)", guardPath, guardErr, gitDirErr)
	}
	if got := gitValue(t, repo, "gpg.format"); got != "ssh" {
		t.Fatalf("repository-local gpg.format = %q, want ssh signing guard", got)
	}
	if got := gitValueIfSet(t, repo, "core.sshCommand"); got != "" {
		t.Fatalf("repository-local core.sshCommand = %q, want unset", got)
	}
	bareSign := exec.Command("git", "commit", "--allow-empty", "-S", "-m", "must not use inherited key")
	bareSign.Dir = repo
	bareSign.Env = os.Environ()
	if output, err := bareSign.CombinedOutput(); err == nil {
		t.Fatalf("bare git commit -S unexpectedly succeeded with signing guard: %s", output)
	}

	stored, err := (configstore.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	selected, found := stored.Profiles["personal"]
	if !found {
		t.Fatal("personal profile was not stored")
	}
	if !selected.DisableSigning || selected.SSHKey != "" || selected.SSHFingerprint != "" || selected.SigningKey != "" || selected.SigningFormat != "" {
		t.Fatalf("stored identity-only profile = %#v", selected)
	}

	stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("current exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var currentResponse struct {
		OK   bool          `json:"ok"`
		Data currentOutput `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
		t.Fatalf("current JSON error = %v: %s", err, stdout)
	}
	if !currentResponse.OK || currentResponse.Data.Status == "mismatch" {
		t.Fatalf("current reports unsafe identity-only setup: %#v", currentResponse.Data)
	}

	stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("doctor exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var doctorResponse struct {
		OK   bool      `json:"ok"`
		Data diagnosis `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &doctorResponse); err != nil {
		t.Fatalf("doctor JSON error = %v: %s", err, stdout)
	}
	if !doctorResponse.OK || doctorResponse.Data.Status == "error" {
		t.Fatalf("doctor reports unsafe identity-only setup: %#v", doctorResponse.Data)
	}
	for _, item := range doctorResponse.Data.Checks {
		if strings.Contains(item.ID, "signing") && item.Status == statusFail {
			t.Fatalf("doctor signing check failed after explicit disable: %#v", item)
		}
	}
}

func TestSetupExistingSSHKeyAppliesAuthenticationAndSameKeySigning(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "remote", "add", "origin", "git@github.com:ada/project.git")
	globalPath := setupTestGlobalConfig(t, repo)
	configPath := filepath.Join(t.TempDir(), "config.json")
	keyPath := filepath.Join(t.TempDir(), "id personal")
	setupTestGenerateSSHKey(t, keyPath)
	publicPath := keyPath + ".pub"
	fingerprint := setupTestFingerprint(t, publicPath)
	privateContents := setupTestReadFile(t, keyPath)
	publicContents := setupTestReadFile(t, publicPath)
	beforeGlobal := setupTestReadFile(t, globalPath)

	stdout, stderr, code := runCLI(t,
		"setup", "personal",
		"--name", "Ada Lovelace",
		"--email", "ada@example.com",
		"--repo", repo,
		"--auth", "existing",
		"--ssh-key", keyPath,
		"--signing", "same-key",
		"--config", configPath,
		"--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("setup exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestSuccessfulEnvelope(t, stdout)
	if !strings.Contains(stdout, fingerprint) {
		t.Fatalf("setup JSON does not contain public-key fingerprint %q: %s", fingerprint, stdout)
	}
	if strings.Contains(stdout, strings.TrimSpace(string(privateContents))) || strings.Contains(stdout, strings.TrimSpace(string(publicContents))) {
		t.Fatalf("setup JSON exposed key contents: %s", stdout)
	}
	if afterGlobal := setupTestReadFile(t, globalPath); !bytes.Equal(afterGlobal, beforeGlobal) {
		t.Fatalf("global Git config changed during SSH setup\nbefore:\n%s\nafter:\n%s", beforeGlobal, afterGlobal)
	}

	stored, err := (configstore.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	selected := stored.Profiles["personal"]
	if selected.SSHKey != keyPath || selected.SSHFingerprint != fingerprint || selected.SigningKey != publicPath || selected.SigningFormat != "ssh" || selected.DisableSigning {
		t.Fatalf("stored SSH/signing profile = %#v", selected)
	}
	storedBytes := setupTestReadFile(t, configPath)
	if bytes.Contains(storedBytes, bytes.TrimSpace(privateContents)) || bytes.Contains(storedBytes, bytes.TrimSpace(publicContents)) {
		t.Fatal("profile store contains SSH key material rather than paths")
	}

	if got := gitValue(t, repo, "user.signingKey"); got != publicPath {
		t.Fatalf("local user.signingKey = %q, want %q", got, publicPath)
	}
	if got := gitValue(t, repo, "gpg.format"); got != "ssh" {
		t.Fatalf("local gpg.format = %q, want ssh", got)
	}
	if got := gitValue(t, repo, "commit.gpgSign"); got != "true" {
		t.Fatalf("local commit.gpgSign = %q, want true", got)
	}
	if got := gitValue(t, repo, "ssh.variant"); got != "ssh" {
		t.Fatalf("local ssh.variant = %q, want ssh", got)
	}
	sshCommand := gitValue(t, repo, "core.sshCommand")
	wantSSHCommand, err := gitconfig.ExpectedSSHCommand(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if sshCommand != wantSSHCommand {
		t.Fatalf("local core.sshCommand = %q, want %q", sshCommand, wantSSHCommand)
	}

	stdout, stderr, code = runCLI(t,
		"setup", "personal", "--force",
		"--name", "Ada Lovelace", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("idempotent setup exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
}

func TestCurrentAndDoctorRejectSSHKeyReplacementAtPinnedPath(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	keyPath := filepath.Join(t.TempDir(), "personal-key")
	replacementPath := filepath.Join(t.TempDir(), "replacement-key")
	setupTestGenerateSSHKey(t, keyPath)
	setupTestGenerateSSHKey(t, replacementPath)
	configPath := filepath.Join(t.TempDir(), "config.json")
	stdout, stderr, code := runCLI(t,
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("setup exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if err := os.WriteFile(keyPath, setupTestReadFile(t, replacementPath), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+".pub", setupTestReadFile(t, replacementPath+".pub"), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
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
	if currentResponse.Data.Status != "mismatch" || !currentResponse.Data.SSHKeyValid || currentResponse.Data.SSHFingerprintMatch || !currentResponse.Data.SSHKeyMismatch {
		t.Fatalf("current replaced-key state = %#v", currentResponse.Data)
	}
	if !hasNotice(currentResponse.Warnings, "ssh_key_mismatch") {
		t.Fatalf("warnings = %#v, want ssh_key_mismatch", currentResponse.Warnings)
	}

	stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" || !strings.Contains(stdout, "no longer matches the profile fingerprint") {
		t.Fatalf("doctor code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
}

func TestSetupJSONRejectsInvalidOptionCombinationsWithoutMutation(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestPrivateKey(t, keyPath, 0o600)
	tests := []struct {
		name string
		args []string
	}{
		{name: "identity only with SSH path", args: []string{"--auth", "identity-only", "--ssh-key", keyPath, "--signing", "disabled"}},
		{name: "identity only with same key signing", args: []string{"--auth", "identity-only", "--signing", "same-key"}},
		{name: "existing key omitted", args: []string{"--auth", "existing", "--signing", "disabled"}},
		{name: "unknown authentication mode", args: []string{"--auth", "magic", "--signing", "disabled"}},
		{name: "unknown signing mode", args: []string{"--auth", "identity-only", "--signing", "magic"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := t.TempDir()
			runGit(t, repo, "init", "--quiet")
			setupTestGlobalConfig(t, repo)
			configPath := filepath.Join(t.TempDir(), "config.json")
			args := []string{"setup", "personal", "--name", "Ada", "--email", "ada@example.com", "--repo", repo, "--config", configPath, "--json"}
			args = append(args, test.args...)

			stdout, stderr, code := runCLI(t, args...)
			if code != exitUsage || stderr != "" {
				t.Fatalf("invalid setup exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
			}
			setupTestErrorEnvelope(t, stdout, "invalid_usage")
			if _, err := os.Stat(configPath); !os.IsNotExist(err) {
				t.Fatalf("profile store exists after rejected setup: %v", err)
			}
			if got := gitValueIfSet(t, repo, "gitctx.profile"); got != "" {
				t.Fatalf("repository profile = %q after rejected setup", got)
			}
		})
	}
}

func TestSetupJSONValidatesArgumentsBeforeRepositoryAccess(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	nonRepository := t.TempDir()
	stdout, stderr, code := runCLI(t, "setup", "personal", "--repo", nonRepository, "--config", configPath, "--json")
	if code != exitUsage || stderr != "" {
		t.Fatalf("missing options code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestErrorEnvelope(t, stdout, "invalid_usage")

	keyPath := filepath.Join(t.TempDir(), "must-not-be-created")
	stdout, stderr, code = runCLI(t,
		"setup", "personal", "--name", "Ada", "--email", "invalid",
		"--repo", nonRepository, "--auth", "generate", "--key-path", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	)
	if code != exitUsage || stderr != "" {
		t.Fatalf("invalid identity code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestErrorEnvelope(t, stdout, "invalid_profile")
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("key exists after preflight validation failure: %v", err)
	}
}

func TestSetupJSONRefusesInteractiveKeyGeneration(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	configPath := filepath.Join(t.TempDir(), "config.json")
	keyPath := filepath.Join(t.TempDir(), "id_ed25519_gitctx_personal")

	stdout, stderr, code := runCLI(t,
		"setup", "personal",
		"--name", "Ada",
		"--email", "ada@example.com",
		"--repo", repo,
		"--auth", "generate",
		"--key-path", keyPath,
		"--signing", "same-key",
		"--config", configPath,
		"--json",
	)
	if code != exitUsage || stderr != "" {
		t.Fatalf("JSON generate exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestErrorEnvelope(t, stdout, "invalid_usage")
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("private key exists after rejected JSON generation: %v", err)
	}
	if _, err := os.Stat(keyPath + ".pub"); !os.IsNotExist(err) {
		t.Fatalf("public key exists after rejected JSON generation: %v", err)
	}
}

func TestSetupRefusesKeyGenerationWithoutTerminalInput(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	configPath := filepath.Join(t.TempDir(), "config.json")
	keyPath := filepath.Join(t.TempDir(), "generated key")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "generate", "--key-path", keyPath,
		"--signing", "same-key", "--config", configPath,
	}, strings.NewReader("passphrase\npassphrase\n"), &stdout, &stderr, "test")
	if code != exitUsage || !strings.Contains(stderr.String(), "interactive terminal") {
		t.Fatalf("piped generation code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("private key exists after rejected piped generation: %v", err)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("profile store exists after rejected piped generation: %v", err)
	}
}

func TestSetupBlocksInheritedSigningKeyReuseUnlessExplicitlyAllowed(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	root := t.TempDir()
	globalPath := filepath.Join(root, "global.gitconfig")
	workKey := filepath.Join(root, "work key")
	setupTestGenerateSSHKey(t, workKey)
	t.Setenv("GIT_CONFIG_GLOBAL", globalPath)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	runGit(t, repo, "config", "--global", "user.name", "Work User")
	runGit(t, repo, "config", "--global", "user.email", "work@example.com")
	runGit(t, repo, "config", "--global", "user.signingKey", workKey+".pub")
	runGit(t, repo, "config", "--global", "gpg.format", "ssh")
	runGit(t, repo, "config", "--global", "commit.gpgSign", "true")
	configPath := filepath.Join(t.TempDir(), "config.json")

	baseArgs := []string{
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", workKey,
		"--signing", "same-key", "--config", configPath, "--json",
	}
	stdout, stderr, code := runCLI(t, baseArgs...)
	if code != exitUsage || stderr != "" {
		t.Fatalf("reuse rejection code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestErrorEnvelope(t, stdout, "inherited_key_reuse")
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("profile store exists after rejected reuse: %v", err)
	}
	if got := gitValueIfSet(t, repo, "gitctx.profile"); got != "" {
		t.Fatalf("repository profile = %q after rejected reuse", got)
	}

	allowedArgs := append([]string(nil), baseArgs...)
	allowedArgs = append(allowedArgs, "--allow-key-reuse")
	stdout, stderr, code = runCLI(t, allowedArgs...)
	if code != exitOK || stderr != "" {
		t.Fatalf("explicit reuse code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Warnings []notice `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if !hasNotice(response.Warnings, "inherited_key_reused") {
		t.Fatalf("warnings = %#v, want inherited_key_reused", response.Warnings)
	}
}

func TestSetupIdempotentRerunStillBlocksNewMatchingGlobalSigningKey(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	keyPath := filepath.Join(t.TempDir(), "personal-key")
	setupTestGenerateSSHKey(t, keyPath)
	configPath := filepath.Join(t.TempDir(), "config.json")
	baseArgs := []string{
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	}
	stdout, stderr, code := runCLI(t, baseArgs...)
	if code != exitOK || stderr != "" {
		t.Fatalf("initial setup code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestSuccessfulEnvelope(t, stdout)

	// The same local key is expected during an idempotent rerun. If that key is
	// later also configured globally, however, it becomes an inherited-key reuse
	// risk and must no longer be covered by the local idempotency exemption.
	runGit(t, repo, "config", "--global", "user.signingKey", keyPath+".pub")
	beforeStore := setupTestReadFile(t, configPath)
	rerunArgs := append([]string(nil), baseArgs...)
	rerunArgs = append(rerunArgs, "--force")
	stdout, stderr, code = runCLI(t, rerunArgs...)
	if code != exitUsage || stderr != "" {
		t.Fatalf("matching global key rejection code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestErrorEnvelope(t, stdout, "inherited_key_reuse")
	if afterStore := setupTestReadFile(t, configPath); !bytes.Equal(afterStore, beforeStore) {
		t.Fatalf("profile store changed after rejected rerun\nbefore:\n%s\nafter:\n%s", beforeStore, afterStore)
	}
	if got := gitValue(t, repo, "gitctx.profile"); got != "personal" {
		t.Fatalf("repository profile = %q after rejected rerun, want personal", got)
	}

	rerunArgs = append(rerunArgs, "--allow-key-reuse")
	stdout, stderr, code = runCLI(t, rerunArgs...)
	if code != exitOK || stderr != "" {
		t.Fatalf("explicit rerun reuse code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Warnings []notice `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if !hasNotice(response.Warnings, "inherited_key_reused") {
		t.Fatalf("warnings = %#v, want inherited_key_reused", response.Warnings)
	}
}

func TestSetupIdempotentRerunStillRequiresDefaultKeyCommandOverride(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	keyPath := filepath.Join(t.TempDir(), "personal-key")
	setupTestGenerateSSHKey(t, keyPath)
	configPath := filepath.Join(t.TempDir(), "config.json")
	baseArgs := []string{
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	}
	stdout, stderr, code := runCLI(t, baseArgs...)
	if code != exitOK || stderr != "" {
		t.Fatalf("initial setup code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	runGit(t, repo, "config", "--global", "gpg.ssh.defaultKeyCommand", "printf must-not-run")
	runArgs := append(append([]string(nil), baseArgs...), "--force")
	stdout, stderr, code = runCLI(t, runArgs...)
	if code != exitUsage || stderr != "" {
		t.Fatalf("default-key rerun rejection code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestErrorEnvelope(t, stdout, "inherited_key_unverifiable")

	runArgs = append(runArgs, "--allow-key-reuse")
	stdout, stderr, code = runCLI(t, runArgs...)
	if code != exitOK || stderr != "" {
		t.Fatalf("allowed default-key rerun code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Warnings []notice `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if !hasNotice(response.Warnings, "inherited_key_reuse_unverified") {
		t.Fatalf("warnings = %#v, want inherited_key_reuse_unverified", response.Warnings)
	}
}

func TestSetupBlocksSigningKeyManagedByAnotherProfileUnlessExplicitlyAllowed(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	keyPath := filepath.Join(t.TempDir(), "shared-key")
	setupTestGenerateSSHKey(t, keyPath)
	configPath := filepath.Join(t.TempDir(), "config.json")

	stdout, stderr, code := runCLI(t,
		"setup", "work", "--name", "Work User", "--email", "work@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("work setup code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestSuccessfulEnvelope(t, stdout)

	personalArgs := []string{
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	}
	stdout, stderr, code = runCLI(t, personalArgs...)
	if code != exitUsage || stderr != "" {
		t.Fatalf("cross-profile reuse rejection code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestErrorEnvelope(t, stdout, "inherited_key_reuse")
	stored, err := (configstore.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := stored.Profiles["personal"]; exists {
		t.Fatal("personal profile was stored after rejected cross-profile key reuse")
	}
	if got := gitValue(t, repo, "gitctx.profile"); got != "work" {
		t.Fatalf("repository profile = %q after rejected reuse, want work", got)
	}

	personalArgs = append(personalArgs, "--allow-key-reuse")
	stdout, stderr, code = runCLI(t, personalArgs...)
	if code != exitOK || stderr != "" {
		t.Fatalf("explicit cross-profile reuse code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Warnings []notice `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if !hasNotice(response.Warnings, "inherited_key_reused") {
		t.Fatalf("warnings = %#v, want inherited_key_reused", response.Warnings)
	}
}

func TestSetupRecognizesCopiedInlineAndRelativeInheritedSigningKeys(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	for _, form := range []string{"copied", "inline", "relative"} {
		t.Run(form, func(t *testing.T) {
			repo := t.TempDir()
			runGit(t, repo, "init", "--quiet")
			root := t.TempDir()
			globalPath := filepath.Join(root, "global.gitconfig")
			workKey := filepath.Join(root, "work-key")
			if form == "relative" {
				workKey = filepath.Join(repo, "work-key")
			}
			setupTestGenerateSSHKey(t, workKey)
			selectedKey := workKey
			globalValue := workKey + ".pub"
			switch form {
			case "copied":
				selectedKey = filepath.Join(root, "copied-key")
				if err := os.WriteFile(selectedKey, setupTestReadFile(t, workKey), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(selectedKey+".pub", setupTestReadFile(t, workKey+".pub"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "inline":
				globalValue = "key::" + strings.TrimSpace(string(setupTestReadFile(t, workKey+".pub")))
			case "relative":
				globalValue = "work-key.pub"
			}

			t.Setenv("GIT_CONFIG_GLOBAL", globalPath)
			t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
			runGit(t, repo, "config", "--global", "user.name", "Work User")
			runGit(t, repo, "config", "--global", "user.email", "work@example.com")
			runGit(t, repo, "config", "--global", "user.signingKey", globalValue)
			runGit(t, repo, "config", "--global", "gpg.format", "ssh")
			runGit(t, repo, "config", "--global", "commit.gpgSign", "true")
			configPath := filepath.Join(t.TempDir(), "config.json")
			stdout, stderr, code := runCLI(t,
				"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
				"--repo", repo, "--auth", "existing", "--ssh-key", selectedKey,
				"--signing", "same-key", "--config", configPath, "--json",
			)
			if code != exitUsage || stderr != "" {
				t.Fatalf("%s reuse code = %d, stderr = %q, output = %q", form, code, stderr, stdout)
			}
			setupTestErrorEnvelope(t, stdout, "inherited_key_reuse")
		})
	}
}

func TestSetupRequiresOverrideWhenSSHDefaultKeyCommandMakesReuseUnverifiable(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	root := t.TempDir()
	globalPath := filepath.Join(root, "global.gitconfig")
	keyPath := filepath.Join(root, "personal-key")
	setupTestGenerateSSHKey(t, keyPath)
	t.Setenv("GIT_CONFIG_GLOBAL", globalPath)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	runGit(t, repo, "config", "--global", "user.name", "Work User")
	runGit(t, repo, "config", "--global", "user.email", "work@example.com")
	const commandSecret = "default-key-command-secret"
	runGit(t, repo, "config", "--global", "gpg.ssh.defaultKeyCommand", "printf "+commandSecret)
	configPath := filepath.Join(t.TempDir(), "config.json")
	args := []string{
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	}
	stdout, stderr, code := runCLI(t, args...)
	if code != exitUsage || stderr != "" {
		t.Fatalf("default command guard code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestErrorEnvelope(t, stdout, "inherited_key_unverifiable")
	if strings.Contains(stdout, commandSecret) {
		t.Fatalf("setup exposed the configured default-key command: %s", stdout)
	}

	args = append(args, "--allow-key-reuse")
	stdout, stderr, code = runCLI(t, args...)
	if code != exitOK || stderr != "" {
		t.Fatalf("allowed unverifiable reuse code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Warnings []notice `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if !hasNotice(response.Warnings, "inherited_key_reuse_unverified") || strings.Contains(stdout, commandSecret) {
		t.Fatalf("allowed warnings/output = %#v / %s", response.Warnings, stdout)
	}
}

func TestSetupRejectsUnverifiableGeneratedKeyBeforeCreatingIt(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	root := t.TempDir()
	globalPath := filepath.Join(root, "global.gitconfig")
	t.Setenv("GIT_CONFIG_GLOBAL", globalPath)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	runGit(t, repo, "config", "--global", "gpg.ssh.defaultKeyCommand", "printf must-not-run")
	configPath := filepath.Join(t.TempDir(), "config.json")
	keyPath := filepath.Join(t.TempDir(), "must-not-be-created")

	stdout, stderr, code := runCLI(t,
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "generate", "--key-path", keyPath,
		"--signing", "same-key", "--config", configPath,
	)
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, "cannot prove that a generated key") {
		t.Fatalf("early generation guard code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if strings.Contains(stderr, "must-not-run") {
		t.Fatalf("setup exposed the configured default-key command: %s", stderr)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("private key exists after early rejection: %v", err)
	}
	if _, err := os.Stat(keyPath + ".pub"); !os.IsNotExist(err) {
		t.Fatalf("public key exists after early rejection: %v", err)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("profile store exists after early rejection: %v", err)
	}
	if got := gitValueIfSet(t, repo, "gitctx.profile"); got != "" {
		t.Fatalf("repository profile = %q after early rejection", got)
	}
}

func TestSetupJSONRequiresForceToReplaceProfile(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	configPath := filepath.Join(t.TempDir(), "config.json")
	if _, stderr, code := runCLI(t, "add", "personal", "--name", "Before", "--email", "before@example.com", "--config", configPath); code != exitOK {
		t.Fatalf("add exit code = %d: %s", code, stderr)
	}
	beforeStore := setupTestReadFile(t, configPath)

	stdout, stderr, code := runCLI(t,
		"setup", "personal",
		"--name", "After",
		"--email", "after@example.com",
		"--repo", repo,
		"--auth", "identity-only",
		"--signing", "disabled",
		"--config", configPath,
		"--json",
	)
	if code != exitProfile || stderr != "" {
		t.Fatalf("profile collision exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestErrorEnvelope(t, stdout, "profile_exists")
	if afterStore := setupTestReadFile(t, configPath); !bytes.Equal(afterStore, beforeStore) {
		t.Fatalf("profile store changed without --force\nbefore:\n%s\nafter:\n%s", beforeStore, afterStore)
	}
	if got := gitValueIfSet(t, repo, "gitctx.profile"); got != "" {
		t.Fatalf("repository profile = %q after collision", got)
	}
}

func TestSetupHelpDoesNotReadConfig(t *testing.T) {
	blockedConfig := filepath.Join(t.TempDir(), "missing", "config.json")
	stdout, stderr, code := runCLI(t, "setup", "--config", blockedConfig, "--help")
	if code != exitOK || stderr != "" {
		t.Fatalf("setup help exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	for _, fragment := range []string{"gitctx setup <profile>", "--auth", "--signing", "--json"} {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("setup help does not contain %q: %s", fragment, stdout)
		}
	}
	if _, err := os.Stat(blockedConfig); !os.IsNotExist(err) {
		t.Fatalf("setup help accessed config path: %v", err)
	}
}

func TestSetupOptionScanningTreatsOptionLikeValuesAsValues(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	configPath := filepath.Join(t.TempDir(), "selected-config.json")

	stdout, stderr, code := runCLI(t,
		"setup", "personal",
		"--name", "--config",
		"--email", "ada@example.com",
		"--repo", repo,
		"--auth", "identity-only",
		"--signing", "disabled",
		"--config", configPath,
		"--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("setup exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	setupTestSuccessfulEnvelope(t, stdout)
	stored, err := (configstore.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := stored.Profiles["personal"].GitName; got != "--config" {
		t.Fatalf("stored Git name = %q, want option-like value --config", got)
	}
}

func TestSetupPinsResolvedRepositoryAcrossConfirmation(t *testing.T) {
	repoA := t.TempDir()
	repoB := t.TempDir()
	runGit(t, repoA, "init", "--quiet")
	runGit(t, repoB, "init", "--quiet")
	setupTestGlobalConfig(t, repoA)
	linkParent := t.TempDir()
	repoLink := filepath.Join(linkParent, "selected")
	if err := os.Symlink(repoA, repoLink); err != nil {
		t.Skipf("create repository symlink: %v", err)
	}
	resolvedRepo, err := gitconfig.NewClient().RepoRoot(repoLink)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	input := &setupTriggerReader{
		reader: strings.NewReader("yes\n"),
		trigger: func() {
			if err := os.Remove(repoLink); err != nil {
				t.Fatalf("remove repository symlink: %v", err)
			}
			if err := os.Symlink(repoB, repoLink); err != nil {
				t.Fatalf("retarget repository symlink: %v", err)
			}
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repoLink, "--auth", "identity-only", "--clear-github", "--config", configPath,
	}, input, &stdout, &stderr, "test")
	if code != exitOK || stderr.String() != "" {
		t.Fatalf("setup code = %d, stderr = %q, output = %q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), resolvedRepo) {
		t.Fatalf("setup output did not retain resolved repository %q: %s", resolvedRepo, stdout.String())
	}
	if got := gitValue(t, repoA, "gitctx.profile"); got != "personal" {
		t.Fatalf("original repository profile = %q, want personal", got)
	}
	if got := gitValueIfSet(t, repoB, "gitctx.profile"); got != "" {
		t.Fatalf("retargeted repository profile = %q, want untouched", got)
	}
}

type setupTriggerReader struct {
	reader    *strings.Reader
	trigger   func()
	triggered bool
}

func (r *setupTriggerReader) Read(buffer []byte) (int, error) {
	if !r.triggered {
		r.triggered = true
		r.trigger()
	}
	return r.reader.Read(buffer)
}

func setupTestGlobalConfig(t *testing.T, dir string) string {
	t.Helper()
	home := t.TempDir()
	globalPath := filepath.Join(home, "global.gitconfig")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_CONFIG_GLOBAL", globalPath)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	runGit(t, dir, "config", "--global", "user.name", "Work User")
	runGit(t, dir, "config", "--global", "user.email", "work@example.com")
	runGit(t, dir, "config", "--global", "gpg.format", "ssh")
	runGit(t, dir, "config", "--global", "user.signingKey", filepath.Join(home, ".ssh", "work.pub"))
	runGit(t, dir, "config", "--global", "commit.gpgSign", "true")
	return globalPath
}

func TestInheritedKeyMatchesPlatformHomeRelativePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	privatePath := filepath.Join(home, ".ssh", "personal-key")
	pair := sshkey.Pair{PrivatePath: privatePath, PublicPath: privatePath + ".pub"}
	inherited := "~" + string(filepath.Separator) + filepath.Join(".ssh", "personal-key.pub")
	if !inheritedKeyMatches(inherited, pair, t.TempDir()) {
		t.Fatalf("inheritedKeyMatches(%q) = false, want true", inherited)
	}
}

func setupTestGenerateSSHKey(t *testing.T, path string) {
	t.Helper()
	command := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "gitctx-setup-test", "-f", path)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate SSH test key: %v: %s", err, output)
	}
}

func setupTestFingerprint(t *testing.T, path string) string {
	t.Helper()
	command := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", path)
	command.Env = os.Environ()
	output, err := command.Output()
	if err != nil {
		t.Fatalf("fingerprint SSH test key: %v", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) < 2 {
		t.Fatalf("unrecognized ssh-keygen fingerprint output: %q", output)
	}
	return fields[1]
}

func setupTestReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func setupTestSuccessfulEnvelope(t *testing.T, output string) {
	t.Helper()
	var response envelope
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		t.Fatalf("setup JSON error = %v, output = %q", err, output)
	}
	if !response.OK || response.Command != "setup" || response.Error != nil {
		t.Fatalf("setup response = %#v", response)
	}
}

func setupTestErrorEnvelope(t *testing.T, output, code string) {
	t.Helper()
	var response envelope
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		t.Fatalf("setup JSON error = %v, output = %q", err, output)
	}
	if response.OK || response.Command != "setup" || response.Error == nil || response.Error.Code != code {
		t.Fatalf("setup error response = %#v, want code %q", response, code)
	}
}
