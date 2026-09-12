//go:build !windows

package gitconfig

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedSSHCommandParsesSpecialIdentityPath(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh is not installed")
	}
	path := filepath.Join(t.TempDir(), `key with spaces 'single' "double" \ %h`)
	writeTestPrivateKey(t, path, 0o600)
	command, err := ExpectedSSHCommand(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed := exec.Command("sh", "-c", command+" -G github.com")
	output, err := parsed.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSH rejected generated command: %v: %s", err, output)
	}
	var identities []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "identityfile ") {
			identities = append(identities, strings.TrimPrefix(line, "identityfile "))
		}
	}
	if len(identities) != 1 {
		t.Fatalf("OpenSSH identity files = %q, want selected identity only; output: %s", identities, output)
	}
	wantIdentity := strings.ReplaceAll(path, "%", "%%")
	if identities[0] != wantIdentity {
		t.Fatalf("OpenSSH identity file = %q, want exact escaped path %q", identities[0], wantIdentity)
	}
	if strings.Contains(identities[0], "~/.ssh/") {
		t.Fatalf("OpenSSH retained a default identity: %q", identities[0])
	}
	if !strings.Contains(string(output), "preferredauthentications publickey") {
		t.Fatalf("OpenSSH did not retain public-key-only authentication: %s", output)
	}
}
