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
)

func TestSetupPinsSSHSigningProgramAgainstGlobalOverride(t *testing.T) {
	trustedProgram, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	trustedProgram, err = filepath.Abs(trustedProgram)
	if err != nil {
		t.Fatal(err)
	}
	trustedProgram, err = filepath.EvalSymlinks(trustedProgram)
	if err != nil {
		t.Fatal(err)
	}

	for _, signingMode := range []string{"disabled", "same-key"} {
		t.Run(signingMode, func(t *testing.T) {
			repo := t.TempDir()
			runGit(t, repo, "init", "--quiet")
			globalPath := setupTestGlobalConfig(t, repo)
			untrustedProgram := filepath.Join(t.TempDir(), "untrusted-ssh-signer")
			runGit(t, repo, "config", "--global", "gpg.ssh.program", untrustedProgram)
			beforeGlobal := setupTestReadFile(t, globalPath)
			configPath := filepath.Join(t.TempDir(), "config.json")

			args := []string{
				"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
				"--repo", repo, "--config", configPath, "--json",
			}
			if signingMode == "disabled" {
				args = append(args, "--auth", "identity-only", "--signing", "disabled")
			} else {
				keyPath := filepath.Join(t.TempDir(), "personal-key")
				setupTestGenerateSSHKey(t, keyPath)
				args = append(args, "--auth", "existing", "--ssh-key", keyPath, "--signing", "same-key")
			}

			stdout, stderr, code := runCLI(t, args...)
			if code != exitOK || stderr != "" {
				t.Fatalf("setup exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
			}
			setupTestSuccessfulEnvelope(t, stdout)
			if afterGlobal := setupTestReadFile(t, globalPath); !bytes.Equal(afterGlobal, beforeGlobal) {
				t.Fatalf("global Git config changed during setup\nbefore:\n%s\nafter:\n%s", beforeGlobal, afterGlobal)
			}

			managedProgram := gitValue(t, repo, "gpg.ssh.program")
			if managedProgram == untrustedProgram {
				t.Fatalf("repository still uses inherited untrusted signing program %q", managedProgram)
			}
			if marker := gitValue(t, repo, "gitctx.managedSshSigningProgram"); marker != managedProgram {
				t.Fatalf("managed signing-program marker = %q, want %q", marker, managedProgram)
			}
			if signingMode == "disabled" {
				if digest := gitValueIfSet(t, repo, "gitctx.sshSigningProgramDigest"); digest != "" {
					t.Fatalf("disabled signing unexpectedly stored executable digest %q", digest)
				}
				commonDir := strings.TrimSpace(setupTestGitOutput(t, repo, "rev-parse", "--git-common-dir"))
				if !filepath.IsAbs(commonDir) {
					commonDir = filepath.Join(repo, commonDir)
				}
				commonDir, err = filepath.EvalSymlinks(filepath.Clean(commonDir))
				if err != nil {
					t.Fatal(err)
				}
				if want := commonDir; managedProgram != want {
					t.Fatalf("disabled signing-program sentinel = %q, want %q", managedProgram, want)
				}
				command := exec.Command("git", "commit", "--allow-empty", "-S", "-m", "must not invoke inherited signer")
				command.Dir = repo
				command.Env = os.Environ()
				if output, commitErr := command.CombinedOutput(); commitErr == nil {
					t.Fatalf("bare git commit -S unexpectedly succeeded: %s", output)
				}
			} else {
				if want := trustedProgram; managedProgram != want {
					t.Fatalf("trusted SSH signing program = %q, want %q", managedProgram, want)
				}
				digest := gitValue(t, repo, "gitctx.sshSigningProgramDigest")
				if !strings.HasPrefix(digest, "sha256:") || gitValue(t, repo, "gitctx.managedSshSigningProgramDigest") != digest {
					t.Fatalf("managed signing-program digest is missing or inconsistent: %q", digest)
				}
				runGit(t, repo, "commit", "--allow-empty", "-m", "signed with trusted program")
				commit := setupTestGitOutput(t, repo, "cat-file", "commit", "HEAD")
				if !strings.Contains(commit, "gpgsig -----BEGIN SSH SIGNATURE-----") {
					t.Fatalf("commit was not SSH-signed by the managed program:\n%s", commit)
				}
			}

			tamperedProgram := filepath.Join(t.TempDir(), "tampered-ssh-signer")
			runGit(t, repo, "config", "--local", "gpg.ssh.program", tamperedProgram)

			stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
			if code != exitOK || stderr != "" {
				t.Fatalf("current after tamper exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
			}
			var currentResponse struct {
				OK   bool          `json:"ok"`
				Data currentOutput `json:"data"`
			}
			if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
				t.Fatalf("current JSON error = %v: %s", err, stdout)
			}
			if !currentResponse.OK || currentResponse.Data.Status != "mismatch" {
				t.Fatalf("current did not fail closed after signing-program tamper: %#v", currentResponse)
			}

			stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
			if code != exitUnsafe || stderr != "" {
				t.Fatalf("doctor after tamper exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
			}
			var doctorResponse struct {
				OK   bool      `json:"ok"`
				Data diagnosis `json:"data"`
			}
			if err := json.Unmarshal([]byte(stdout), &doctorResponse); err != nil {
				t.Fatalf("doctor JSON error = %v: %s", err, stdout)
			}
			if !doctorResponse.OK || doctorResponse.Data.Status != "error" || !hasSigningFailure(doctorResponse.Data.Checks) {
				t.Fatalf("doctor did not report signing-program tamper: %#v", doctorResponse)
			}
		})
	}
}

func TestUseRestoresPreexistingLocalSSHSigningProgram(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}

	for _, signingMode := range []string{"disabled", "same-key"} {
		t.Run(signingMode, func(t *testing.T) {
			repo := t.TempDir()
			runGit(t, repo, "init", "--quiet")
			setupTestGlobalConfig(t, repo)
			preexistingProgram := filepath.Join(t.TempDir(), "preexisting-local-signer")
			runGit(t, repo, "config", "--local", "gpg.ssh.program", preexistingProgram)
			configPath := filepath.Join(t.TempDir(), "config.json")

			if stdout, stderr, code := runCLI(t,
				"add", "plain", "--name", "Plain", "--email", "plain@example.com",
				"--config", configPath, "--json",
			); code != exitOK || stderr != "" {
				t.Fatalf("add plain exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
			}

			args := []string{
				"setup", "managed", "--name", "Managed", "--email", "managed@example.com",
				"--repo", repo, "--config", configPath, "--json",
			}
			if signingMode == "disabled" {
				args = append(args, "--auth", "identity-only", "--signing", "disabled")
			} else {
				keyPath := filepath.Join(t.TempDir(), "managed-key")
				setupTestGenerateSSHKey(t, keyPath)
				args = append(args, "--auth", "existing", "--ssh-key", keyPath, "--signing", "same-key")
			}
			if stdout, stderr, code := runCLI(t, args...); code != exitOK || stderr != "" {
				t.Fatalf("setup managed exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
			}
			if got := gitValue(t, repo, "gitctx.previousSshSigningProgram"); got != preexistingProgram {
				t.Fatalf("saved previous signing program = %q, want %q", got, preexistingProgram)
			}

			stdout, stderr, code := runCLI(t, "use", "plain", "--repo", repo, "--config", configPath, "--json")
			if code != exitOK || stderr != "" {
				t.Fatalf("use plain exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
			}
			if got := gitValue(t, repo, "gpg.ssh.program"); got != preexistingProgram {
				t.Fatalf("restored signing program = %q, want %q", got, preexistingProgram)
			}
			for _, marker := range []string{
				"gitctx.managedSshSigningProgram",
				"gitctx.previousSshSigningProgram",
				"gitctx.sshSigningProgramDigest",
				"gitctx.managedSshSigningProgramDigest",
				"gitctx.previousSshSigningProgramDigest",
			} {
				if got := gitValueIfSet(t, repo, marker); got != "" {
					t.Fatalf("stale %s = %q after restoration", marker, got)
				}
			}

			stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
			if code != exitOK || stderr != "" {
				t.Fatalf("current after restoration exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
			}
			var currentResponse struct {
				OK   bool          `json:"ok"`
				Data currentOutput `json:"data"`
			}
			if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
				t.Fatalf("current JSON error = %v: %s", err, stdout)
			}
			if !currentResponse.OK || currentResponse.Data.Status == "mismatch" {
				t.Fatalf("restored unmanaged signing program was reported stale: %#v", currentResponse)
			}

			stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
			if code != exitOK || stderr != "" {
				t.Fatalf("doctor after restoration exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
			}
			var doctorResponse struct {
				OK   bool      `json:"ok"`
				Data diagnosis `json:"data"`
			}
			if err := json.Unmarshal([]byte(stdout), &doctorResponse); err != nil {
				t.Fatalf("doctor JSON error = %v: %s", err, stdout)
			}
			if !doctorResponse.OK || doctorResponse.Data.Status == "error" {
				t.Fatalf("doctor reported restored unmanaged signing program as unsafe: %#v", doctorResponse)
			}
		})
	}
}

func TestCurrentAndDoctorRejectMissingManagedSSHSigningProgram(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("temporary POSIX executable wrapper is Unix-only")
	}
	sourceProgram, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	sourceProgram, err = filepath.EvalSymlinks(sourceProgram)
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	binDir, err = filepath.EvalSymlinks(binDir)
	if err != nil {
		t.Fatal(err)
	}
	pinnedProgram := filepath.Join(binDir, filepath.Base(sourceProgram))
	quotedSource := "'" + strings.ReplaceAll(sourceProgram, "'", `'\''`) + "'"
	wrapper := "#!/bin/sh\nexec " + quotedSource + " \"$@\"\n"
	if err := os.WriteFile(pinnedProgram, []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	keyPath := filepath.Join(t.TempDir(), "personal-key")
	setupTestGenerateSSHKey(t, keyPath)
	configPath := filepath.Join(t.TempDir(), "config.json")
	stdout, stderr, code := runCLI(t,
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("setup exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if got := gitValue(t, repo, "gpg.ssh.program"); got != pinnedProgram {
		t.Fatalf("managed signing program = %q, want temporary executable %q", got, pinnedProgram)
	}
	if err := os.Remove(pinnedProgram); err != nil {
		t.Fatalf("remove managed signing program: %v", err)
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
	if currentResponse.Data.Status != "mismatch" || !currentResponse.Data.SSHSigningProgramManaged || currentResponse.Data.SSHSigningProgramExecutable || !currentResponse.Data.SSHSigningProgramMismatch {
		t.Fatalf("current missing-program state = %#v", currentResponse.Data)
	}
	if !hasNotice(currentResponse.Warnings, "ssh_signing_program_mismatch") {
		t.Fatalf("current warnings = %#v, want ssh_signing_program_mismatch", currentResponse.Warnings)
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
	foundFailure := false
	for _, item := range doctorResponse.Data.Checks {
		if item.ID == "ssh_signing_program" && item.Status == statusFail {
			foundFailure = true
			break
		}
	}
	if !foundFailure {
		t.Fatalf("doctor checks = %#v, want ssh_signing_program failure", doctorResponse.Data.Checks)
	}

	if err := os.Symlink(sourceProgram, pinnedProgram); err != nil {
		t.Fatalf("replace managed signer with symlink: %v", err)
	}
	symlinkState := setupTestCurrentOutput(t, repo, configPath)
	if symlinkState.Status != "mismatch" || symlinkState.SSHSigningProgramExecutable || symlinkState.SSHSigningProgramIntegrity {
		t.Fatalf("symlink replacement was not rejected: %#v", symlinkState)
	}
	if err := os.Remove(pinnedProgram); err != nil {
		t.Fatal(err)
	}
	replacement := wrapper + "# same path, different executable contents\n"
	if err := os.WriteFile(pinnedProgram, []byte(replacement), 0o700); err != nil {
		t.Fatal(err)
	}
	replacedState := setupTestCurrentOutput(t, repo, configPath)
	if replacedState.Status != "mismatch" || !replacedState.SSHSigningProgramExecutable || replacedState.SSHSigningProgramIntegrity {
		t.Fatalf("same-path executable replacement was not rejected: %#v", replacedState)
	}
}

func TestCurrentAndDoctorRejectEffectiveSSHSigningProgramOverride(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	setupTestGlobalConfig(t, repo)
	keyPath := filepath.Join(t.TempDir(), "personal-key")
	setupTestGenerateSSHKey(t, keyPath)
	configPath := filepath.Join(t.TempDir(), "config.json")
	stdout, stderr, code := runCLI(t,
		"setup", "personal", "--name", "Ada", "--email", "ada@example.com",
		"--repo", repo, "--auth", "existing", "--ssh-key", keyPath,
		"--signing", "same-key", "--config", configPath, "--json",
	)
	if code != exitOK || stderr != "" {
		t.Fatalf("setup exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}

	override := filepath.Join(t.TempDir(), "sensitive-custom-signer")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "gpg.ssh.program")
	t.Setenv("GIT_CONFIG_VALUE_0", override)
	stdout, stderr, code = runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("current exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	if strings.Contains(stdout, override) {
		t.Fatalf("current exposed effective signing-program command: %s", stdout)
	}
	var currentResponse struct {
		Data     currentOutput `json:"data"`
		Warnings []notice      `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(stdout), &currentResponse); err != nil {
		t.Fatal(err)
	}
	if currentResponse.Data.Status != "mismatch" || currentResponse.Data.SSHSigningProgramManaged || !currentResponse.Data.SSHSigningProgramMismatch {
		t.Fatalf("current effective-program override state = %#v", currentResponse.Data)
	}
	if !hasNotice(currentResponse.Warnings, "ssh_signing_program_mismatch") {
		t.Fatalf("warnings = %#v, want ssh_signing_program_mismatch", currentResponse.Warnings)
	}

	stdout, stderr, code = runCLI(t, "doctor", "--repo", repo, "--config", configPath, "--json")
	if code != exitUnsafe || stderr != "" || strings.Contains(stdout, override) {
		t.Fatalf("doctor code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var doctorResponse struct {
		Data diagnosis `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &doctorResponse); err != nil {
		t.Fatal(err)
	}
	if doctorResponse.Data.Status != "error" || !hasSigningFailure(doctorResponse.Data.Checks) {
		t.Fatalf("doctor effective-program override state = %#v", doctorResponse.Data)
	}
}

func setupTestGitOutput(t *testing.T, repo string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = repo
	command.Env = os.Environ()
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %v error = %v", args, err)
	}
	return string(output)
}

func setupTestCurrentOutput(t *testing.T, repo, configPath string) currentOutput {
	t.Helper()
	stdout, stderr, code := runCLI(t, "current", "--repo", repo, "--config", configPath, "--json")
	if code != exitOK || stderr != "" {
		t.Fatalf("current exit code = %d, stderr = %q, output = %q", code, stderr, stdout)
	}
	var response struct {
		Data currentOutput `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	return response.Data
}

func hasSigningFailure(checks []check) bool {
	for _, item := range checks {
		if item.Status == statusFail && strings.Contains(strings.ToLower(item.ID+" "+item.Name), "signing") {
			return true
		}
	}
	return false
}
