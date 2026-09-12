package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gitctx/internal/configstore"
	"gitctx/internal/gitconfig"
)

func TestGuidedSetupExplainsScopeAndRepromptsInvalidAnswers(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	configPath := filepath.Join(t.TempDir(), "profiles.json")
	input := strings.NewReader(strings.Join([]string{
		"Ada Lovelace",
		"not-an-email",
		"ada@example.com",
		"ada",
		"9",
		"3",
		"yes",
	}, "\n") + "\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"setup", "personal", "--repo", repo, "--config", configPath}, input, &stdout, &stderr, "test")
	if code != exitOK || stderr.String() != "" {
		t.Fatalf("guided setup code = %d, stderr = %q, output = %q", code, stderr.String(), stdout.String())
	}
	output := stdout.String()
	for _, expected := range []string{
		"only this repository; your global work identity",
		"Git email \"not-an-email\" is not a valid email address",
		"Please choose a number from 1 to 3",
		"Ready to commit with this identity",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("guided setup output missing %q:\n%s", expected, output)
		}
	}
	stored, err := (configstore.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	selected := stored.Profiles["personal"]
	if selected.GitEmail != "ada@example.com" || !selected.DisableSigning || selected.SSHKey != "" {
		t.Fatalf("guided profile = %#v", selected)
	}
}

func TestGuidedSetupDetectsHTTPSAndDefaultsToIdentityOnly(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "remote", "add", "origin", "https://github.com/ada/project.git")
	setupTestGlobalConfig(t, repo)
	configPath := filepath.Join(t.TempDir(), "profiles.json")
	input := strings.NewReader("Ada\nada@example.com\nada\n\nyes\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"setup", "personal", "--repo", repo, "--config", configPath}, input, &stdout, &stderr, "test")
	if code != exitOK || stderr.String() != "" {
		t.Fatalf("HTTPS setup code = %d, stderr = %q, output = %q", code, stderr.String(), stdout.String())
	}
	output := stdout.String()
	for _, expected := range []string{
		"GitHub over HTTPS",
		"requires changing this remote to SSH first",
		"recommended for the current remote",
		"Choice [3]",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("HTTPS setup output missing %q:\n%s", expected, output)
		}
	}
	stored, err := (configstore.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if selected := stored.Profiles["personal"]; selected.SSHKey != "" || !selected.DisableSigning {
		t.Fatalf("HTTPS default profile = %#v, want identity-only", selected)
	}
}

func TestSetupExistingProfileDefaultsToApplyWithoutEditing(t *testing.T) {
	firstRepo := t.TempDir()
	secondRepo := t.TempDir()
	runGit(t, firstRepo, "init", "--quiet")
	runGit(t, secondRepo, "init", "--quiet")
	setupTestGlobalConfig(t, firstRepo)
	configPath := filepath.Join(t.TempDir(), "profiles.json")
	stdout, stderr, code := runCLI(t,
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", firstRepo, "--auth", "identity-only", "--signing", "disabled",
		"--config", configPath, "--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("initial setup code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code = Run([]string{"setup", "personal", "--repo", secondRepo, "--config", configPath}, strings.NewReader("\n"), &out, &errOut, "test")
	if code != exitOK || errOut.String() != "" {
		t.Fatalf("apply existing code = %d, stderr = %q, output = %q", code, errOut.String(), out.String())
	}
	if !strings.Contains(out.String(), "Apply this saved profile without changing it") || !strings.Contains(out.String(), "Applied profile \"personal\"") {
		t.Fatalf("existing-profile output = %q", out.String())
	}
	if got := gitValue(t, secondRepo, "gitctx.profile"); got != "personal" {
		t.Fatalf("second repository profile = %q", got)
	}
}

func TestSetupExistingSSHProfileDoesNotApplyToHTTPSRemote(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	firstRepo := t.TempDir()
	secondRepo := t.TempDir()
	runGit(t, firstRepo, "init", "--quiet")
	runGit(t, secondRepo, "init", "--quiet")
	runGit(t, firstRepo, "remote", "add", "origin", "git@github.com:ada/one.git")
	runGit(t, secondRepo, "remote", "add", "origin", "https://github.com/ada/two.git")
	setupTestGlobalConfig(t, firstRepo)
	keyPath := filepath.Join(t.TempDir(), "personal-key")
	setupTestGenerateSSHKey(t, keyPath)
	configPath := filepath.Join(t.TempDir(), "profiles.json")
	stdout, stderr, code := runCLI(t,
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", firstRepo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("initial SSH setup code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code = Run([]string{"setup", "personal", "--repo", secondRepo, "--config", configPath}, strings.NewReader("\n"), &out, &errOut, "test")
	if code != exitGit || !strings.Contains(errOut.String(), "would not be used") || !strings.Contains(errOut.String(), "git remote set-url --push") {
		t.Fatalf("HTTPS apply code = %d, stderr = %q, output = %q", code, errOut.String(), out.String())
	}
	if got := gitValueIfSet(t, secondRepo, "gitctx.profile"); got != "" {
		t.Fatalf("HTTPS repository was mutated with profile %q", got)
	}
}

func TestSetupExistingSSHProfileRepromptsWithoutChangingBaselineSnapshot(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "remote", "add", "origin", "git@github.com:ada/project.git")
	setupTestGlobalConfig(t, repo)
	keyOne := filepath.Join(t.TempDir(), "key-one")
	keyTwo := filepath.Join(t.TempDir(), "key-two")
	setupTestGenerateSSHKey(t, keyOne)
	setupTestGenerateSSHKey(t, keyTwo)
	configPath := filepath.Join(t.TempDir(), "profiles.json")
	stdout, stderr, code := runCLI(t,
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyOne,
		"--signing", "same-key", "--config", configPath, "--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("initial SSH setup code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}

	input := strings.NewReader(strings.Join([]string{
		"2", // Edit the profile.
		"",  // Keep name.
		"",  // Keep email.
		"",  // Keep optional GitHub metadata empty.
		"",  // Keep existing-key authentication.
		keyTwo + ".pub",
		keyTwo,
		"", // Keep same-key signing.
		"yes",
	}, "\n") + "\n")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code = Run([]string{"setup", "personal", "--repo", repo, "--config", configPath}, input, &out, &errOut, "test")
	if code != exitOK || errOut.String() != "" {
		t.Fatalf("edited SSH setup code = %d, stderr = %q, output = %q", code, errOut.String(), out.String())
	}
	if !strings.Contains(out.String(), "appears to be a public key") {
		t.Fatalf("edited SSH setup did not explain invalid public-key path: %q", out.String())
	}
	stored, err := (configstore.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if stored.Profiles["personal"].SSHKey != keyTwo {
		t.Fatalf("updated SSH key = %q, want %q", stored.Profiles["personal"].SSHKey, keyTwo)
	}
}

func TestHelpTopicAndEmptyListPreferGuidedSetup(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"help", "setup"}, nil, &stdout, &stderr, "test"); code != exitOK || stderr.String() != "" {
		t.Fatalf("help setup code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "gitctx setup <profile>") {
		t.Fatalf("help setup output = %q", stdout.String())
	}

	configPath := filepath.Join(t.TempDir(), "profiles.json")
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"list", "--config", configPath}, nil, &stdout, &stderr, "test"); code != exitOK || stderr.String() != "" {
		t.Fatalf("empty list code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "gitctx setup personal") || strings.Contains(stdout.String(), "gitctx add") {
		t.Fatalf("empty list output = %q", stdout.String())
	}
}

func TestCurrentLabelsSynthesizedGitIdentityAsUnconfigured(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(t.TempDir(), "profiles.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"current", "--repo", repo, "--config", configPath}, nil, &stdout, &stderr, "test")
	if code != exitOK || stderr.String() != "" {
		t.Fatalf("current code = %d, stderr = %q, output = %q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "not explicitly configured") || !strings.Contains(stdout.String(), "machine-based fallback") {
		t.Fatalf("current output = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"current", "--repo", repo, "--config", configPath, "--json"}, nil, &stdout, &stderr, "test")
	if code != exitOK || stderr.String() != "" {
		t.Fatalf("JSON current code = %d, stderr = %q, output = %q", code, stderr.String(), stdout.String())
	}
	var response struct {
		Data     currentOutput `json:"data"`
		Warnings []notice      `json:"warnings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.IdentityConfigured || !hasNotice(response.Warnings, "identity_unconfigured") {
		t.Fatalf("unconfigured current response = %#v", response)
	}
}

func TestFirstRunOutsideRepositoryUsesPlainRecoveryGuidance(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "profiles.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"current", "--repo", directory, "--config", configPath}, nil, &stdout, &stderr, "test")
	if code != exitGit || stdout.String() != "" {
		t.Fatalf("outside-repository code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "not inside a Git repository") || !strings.Contains(stderr.String(), "pass --repo <path>") || strings.Contains(stderr.String(), "fatal:") {
		t.Fatalf("outside-repository stderr = %q", stderr.String())
	}
}

func TestSSHConversionURLIsExactAndConservative(t *testing.T) {
	tests := []struct {
		remote string
		want   string
		ok     bool
	}{
		{"https://github.com/owner/repo.git", "git@github.com:owner/repo.git", true},
		{"https://gitlab.com/group/subgroup/repo.git", "git@gitlab.com:group/subgroup/repo.git", true},
		{"https://github.example/owner/repo.git", "", false},
		{"https://user@github.com/owner/repo.git", "", false},
		{"https://github.com:8443/owner/repo.git", "", false},
		{"https://github.com/owner/repo.git?token=secret", "", false},
		{"https://github.com/owner/repo.git#fragment", "", false},
		{"https://github.com/owner%2Frepo.git", "", false},
		{"https://github.com/repo.git", "", false},
		{"https://github.com/owner/repo/tree/main", "", false},
		{"https://bitbucket.org/owner/repo/src/main", "", false},
		{"https://gitlab.com/group/repo/-/tree/main", "", false},
	}
	for _, test := range tests {
		t.Run(test.remote, func(t *testing.T) {
			got, ok := sshConversionURL(test.remote)
			if got != test.want || ok != test.ok {
				t.Fatalf("sshConversionURL(%q) = %q, %v; want %q, %v", test.remote, got, ok, test.want, test.ok)
			}
		})
	}
}

func TestSetupSSHRemoteErrorKeepsUnresolvedCode(t *testing.T) {
	code, err, _ := setupSSHRemoteError(gitconfig.State{PushRemote: "missing", PushRemoteExplicit: true})
	if code != "push_remote_unresolved" || err == nil {
		t.Fatalf("unresolved remote = %q, %v", code, err)
	}
}

func TestSetupSSHRemoteHintChangesThePushURLOnly(t *testing.T) {
	_, err, hint := setupSSHRemoteError(gitconfig.State{
		PushRemote: "origin",
		PushURLs:   []string{"https://github.com/owner/repo.git"},
	})
	if err == nil || !strings.Contains(hint, "git remote set-url --push 'origin' 'git@github.com:owner/repo.git'") {
		t.Fatalf("SSH remote hint = %q, error = %v", hint, err)
	}
}

func TestSetupSummaryShowsAliasWarningButCollapsesGenericRoutingWarning(t *testing.T) {
	var output bytes.Buffer
	printSetupCheckSummary(&output, diagnosis{Checks: []check{
		{ID: "ssh_route", Name: "SSH routing", Status: statusWarn, Message: `SSH remote host "github-personal" may be a Host alias`},
		{ID: "ssh_route", Name: "SSH routing", Status: statusWarn, Message: `routing and connectivity to host "github.com" are not tested`},
	}})
	if !strings.Contains(output.String(), "github-personal") || strings.Contains(output.String(), "github.com") {
		t.Fatalf("setup check summary = %q", output.String())
	}
}

func TestShellDisplayQuoteEscapesTerminalControls(t *testing.T) {
	quoted := shellDisplayQuote("/tmp/repo\nFORGED\x1b[31m")
	if strings.ContainsAny(quoted, "\n\r\x1b") || !strings.Contains(quoted, `\x0a`) || !strings.Contains(quoted, `\x1b`) {
		t.Fatalf("shell display quote = %q", quoted)
	}
}

func TestRegistrationDestinationsCoverEveryHostAndDeduplicateGitHub(t *testing.T) {
	targets := registrationDestinations([]string{
		"git@github.com:owner/one.git",
		"ssh://git@ssh.github.com:443/owner/two.git",
		"git@gitlab.com:owner/three.git",
		"git@example.test:owner/four.git",
	}, false)
	if len(targets) != 3 {
		t.Fatalf("registration targets = %#v, want GitHub, GitLab, and example.test", targets)
	}
	if targets[0].Service != "GitHub" || !targets[0].SeparateSigningKey || targets[1].Service != "GitLab" || targets[1].SeparateSigningKey || targets[2].Service != "example.test" {
		t.Fatalf("registration targets = %#v", targets)
	}
}

func TestVerifyChecksRemoteReadAccessWithoutClaimingAccountOrWriteAccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX git wrapper")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "remote", "add", "origin", "git@github.com:ada/project.git")
	globalPath := setupTestGlobalConfig(t, repo)
	knownHosts := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(knownHosts), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, []byte("github.com test-host-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "personal-key")
	setupTestGenerateSSHKey(t, keyPath)
	configPath := filepath.Join(t.TempDir(), "profiles.json")
	stdout, stderr, code := runCLI(t,
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com", "--github", "ada",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("setup code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}

	installVerifyGitWrapper(t)
	argsPath := filepath.Join(t.TempDir(), "verify-args")
	t.Setenv("GITCTX_VERIFY_ARGS", argsPath)
	t.Setenv("GITCTX_VERIFY_RESULT", "success")
	localConfigPath := filepath.Join(repo, ".git", "config")
	beforeLocal := setupTestReadFile(t, localConfigPath)
	beforeGlobal := setupTestReadFile(t, globalPath)
	beforeKnownHosts := setupTestReadFile(t, knownHosts)
	beforePrivate := setupTestReadFile(t, keyPath)
	beforePublic := setupTestReadFile(t, keyPath+".pub")
	stdout, stderr, code = runCLI(t, "verify", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("verify code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Data     verifyOutput `json:"data"`
		Warnings []notice     `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Status != "ready" || len(response.Data.Remotes) != 1 || response.Data.Remotes[0].Status != statusPass {
		t.Fatalf("verify response = %#v", response)
	}
	if hasNotice(response.Warnings, "ssh_routing_unverified") {
		t.Fatalf("successful live verification retained routing warning: %#v", response.Warnings)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"StrictHostKeyChecking=yes", "UpdateHostKeys=no", "BatchMode=yes", "git@github.com:ada/project.git"} {
		if !bytes.Contains(args, []byte(required)) {
			t.Fatalf("verification arguments missing %q: %s", required, args)
		}
	}
	for path, before := range map[string][]byte{
		localConfigPath:  beforeLocal,
		globalPath:       beforeGlobal,
		knownHosts:       beforeKnownHosts,
		keyPath:          beforePrivate,
		keyPath + ".pub": beforePublic,
	} {
		if after := setupTestReadFile(t, path); !bytes.Equal(after, before) {
			t.Fatalf("verify changed %s", path)
		}
	}

	if err := os.Remove(argsPath); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "remote", "set-url", "--add", "--push", "origin", "git@github.com:ada/project.git")
	runGit(t, repo, "remote", "set-url", "--add", "--push", "origin", "git@gitlab.com:ada/project.git")
	stdout, stderr, code = runCLI(t, "verify", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("multi-remote verify code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data.Remotes) != 2 || response.Data.Remotes[0].Status != statusPass || response.Data.Remotes[1].Status != statusPass {
		t.Fatalf("multi-remote response = %#v", response.Data.Remotes)
	}
	args, err = os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(args, []byte("github.com")) || !bytes.Contains(args, []byte("gitlab.com")) {
		t.Fatalf("multi-remote verification args = %s", args)
	}

	t.Setenv("GITCTX_VERIFY_RESULT", "denied")
	stdout, stderr, code = runCLI(t, "verify", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" {
		t.Fatalf("denied verify code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	response = struct {
		Data     verifyOutput `json:"data"`
		Warnings []notice     `json:"warnings"`
	}{}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Status != "not_ready" || !strings.Contains(response.Data.Reason, "rejected this key") {
		t.Fatalf("denied verify response = %#v", response.Data)
	}

	var plain bytes.Buffer
	var plainErr bytes.Buffer
	code = Run([]string{"verify", "--repo", repo, "--config", configPath}, nil, &plain, &plainErr, "test")
	if code != exitUnsafe || plainErr.String() != "" || strings.Contains(plain.String(), "\nReady:") {
		t.Fatalf("plain denied verify code = %d, stderr = %q, output = %q", code, plainErr.String(), plain.String())
	}
	t.Setenv("GITCTX_VERIFY_RESULT", "success")
	plain.Reset()
	plainErr.Reset()
	code = Run([]string{"verify", "--repo", repo, "--config", configPath}, nil, &plain, &plainErr, "test")
	if code != exitOK || !strings.Contains(plain.String(), "does not prove write permission or which account owns the key") {
		t.Fatalf("plain success verify code = %d, stderr = %q, output = %q", code, plainErr.String(), plain.String())
	}
}

func installVerifyGitWrapper(t *testing.T) {
	t.Helper()
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	wrapper := filepath.Join(directory, "git")
	script := `#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "ls-remote" ]; then
	    printf '%s\n' "$@" >> "$GITCTX_VERIFY_ARGS"
    if [ "$GITCTX_VERIFY_RESULT" = "success" ]; then
      exit 0
    fi
    echo 'git@github.com: Permission denied (publickey).' >&2
    exit 128
  fi
done
exec "$GITCTX_REAL_GIT" "$@"
`
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITCTX_REAL_GIT", realGit)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
}
