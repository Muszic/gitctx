package gitconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyRemoteAccessPinsNoninteractiveSSHAndRemovesOverrides(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX git wrapper")
	}
	directory := t.TempDir()
	wrapper := filepath.Join(directory, "git")
	script := `#!/bin/sh
{
  printf 'GIT_SSH_COMMAND=%s\n' "$GIT_SSH_COMMAND"
  printf 'GIT_SSH=%s\n' "$GIT_SSH"
  printf 'GIT_SSH_VARIANT=%s\n' "$GIT_SSH_VARIANT"
  printf 'GIT_TERMINAL_PROMPT=%s\n' "$GIT_TERMINAL_PROMPT"
  printf 'GIT_CONFIG_PARAMETERS=%s\n' "$GIT_CONFIG_PARAMETERS"
  printf 'GIT_CONFIG_COUNT=%s\n' "$GIT_CONFIG_COUNT"
  printf 'GIT_CONFIG_KEY_0=%s\n' "$GIT_CONFIG_KEY_0"
  printf 'GIT_CONFIG_VALUE_0=%s\n' "$GIT_CONFIG_VALUE_0"
  printf 'GIT_CONFIG_NOSYSTEM=%s\n' "$GIT_CONFIG_NOSYSTEM"
  printf 'GIT_CONFIG_GLOBAL=%s\n' "$GIT_CONFIG_GLOBAL"
  printf 'GIT_DIR=%s\n' "$GIT_DIR"
  printf 'ARGS='
  printf '%s ' "$@"
  printf '\n'
} > "$GITCTX_VERIFY_ENV_FILE"
exit 0
`
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(t.TempDir(), "record")
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GITCTX_VERIFY_ENV_FILE", record)
	t.Setenv("GIT_SSH_COMMAND", "must-not-survive")
	t.Setenv("GIT_SSH", "must-not-survive")
	t.Setenv("GIT_SSH_VARIANT", "must-not-survive")
	t.Setenv("GIT_TERMINAL_PROMPT", "1")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'url.fake.insteadOf'='git@github.com:'")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "url.fake.insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_0", "git@github.com:")

	client := &Client{Env: os.Environ()}
	err := client.VerifyRemoteAccess(t.TempDir(), "git@github.com:owner/repo.git", "ssh -F none -o IdentitiesOnly=yes -i '/private/key'")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	for _, absent := range []string{
		"GIT_SSH_COMMAND=must-not-survive",
		"GIT_SSH=must-not-survive",
		"GIT_SSH_VARIANT=must-not-survive",
		"GIT_TERMINAL_PROMPT=1",
		"url.fake.insteadOf",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=url.fake.insteadOf",
		"GIT_CONFIG_VALUE_0=git@github.com:",
	} {
		if strings.Contains(output, absent) {
			t.Fatalf("verification environment retained %q:\n%s", absent, output)
		}
	}
	for _, required := range []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_DIR=" + os.DevNull,
		"BatchMode=yes",
		"ConnectTimeout=10",
		"ServerAliveInterval=5",
		"ServerAliveCountMax=2",
		"StrictHostKeyChecking=yes",
		"UpdateHostKeys=no",
		"ls-remote",
		"git@github.com:owner/repo.git",
		"HEAD",
	} {
		if !strings.Contains(output, required) {
			t.Fatalf("verification record missing %q:\n%s", required, output)
		}
	}
}

func TestVerifyRemoteAccessDoesNotRewriteAnEffectiveURLAgain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX SSH wrapper")
	}
	repo := t.TempDir()
	runTestGit(t, repo, nil, "init", "--quiet")
	runTestGit(t, repo, nil, "remote", "add", "origin", "shortcut:owner/repo.git")
	probeTemp := filepath.Join(repo, "probe-tmp")
	if err := os.Mkdir(probeTemp, 0o700); err != nil {
		t.Fatal(err)
	}

	globalPath := filepath.Join(t.TempDir(), "global.gitconfig")
	globalConfig := `[url "ssh://git@first.example/"]
	insteadOf = shortcut:
`
	if err := os.WriteFile(globalPath, []byte(globalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, repo, nil, "config", "--local", "url.ssh://git@second.example/.insteadOf", "ssh://git@first.example/")
	record := filepath.Join(t.TempDir(), "ssh-args")
	bareRepo := filepath.Join(t.TempDir(), "remote.git")
	runTestGit(t, t.TempDir(), nil, "init", "--quiet", "--bare", bareRepo)
	sshWrapper := filepath.Join(t.TempDir(), "fake-ssh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$GITCTX_VERIFY_SSH_ARGS\"\nexec git-upload-pack \"$GITCTX_VERIFY_BARE_REPO\"\n"
	if err := os.WriteFile(sshWrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+globalPath,
		"GIT_CONFIG_SYSTEM="+os.DevNull,
		"GITCTX_VERIFY_SSH_ARGS="+record,
		"GITCTX_VERIFY_BARE_REPO="+bareRepo,
		"TMPDIR="+probeTemp,
	)
	client := &Client{Env: environment}
	state, err := client.Inspect(repo)
	if err != nil {
		t.Fatal(err)
	}
	if state.PushURL != "ssh://git@first.example/owner/repo.git" {
		t.Fatalf("effective push URL = %q", state.PushURL)
	}
	if err := client.VerifyRemoteAccess(repo, state.PushURL, shellQuote(sshWrapper)); err != nil {
		t.Fatal(err)
	}
	arguments, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	output := string(arguments)
	if !strings.Contains(output, "first.example") || strings.Contains(output, "second.example") {
		t.Fatalf("verification SSH arguments = %q; effective URL was rewritten again", output)
	}
}

func TestBoundedVerificationOutput(t *testing.T) {
	var output boundedOutput
	value := strings.Repeat("x", verificationOutputLimit+1024)
	written, err := output.Write([]byte(value))
	if err != nil || written != len(value) {
		t.Fatalf("Write = %d, %v; want %d, nil", written, err, len(value))
	}
	if len(output.String()) != verificationOutputLimit || !output.Truncated() {
		t.Fatalf("bounded output length = %d, truncated = %v", len(output.String()), output.Truncated())
	}
}

func runTestGit(t *testing.T, directory string, environment []string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = directory
	if environment != nil {
		command.Env = environment
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
}
