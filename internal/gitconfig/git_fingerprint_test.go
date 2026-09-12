package gitconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gitctx/internal/profile"
	"gitctx/internal/sshkey"
)

func TestApplyRejectsPinnedSSHKeyFingerprintMismatchBeforeMutation(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	repo := initRepository(t)
	keyPath := filepath.Join(t.TempDir(), "personal key")
	command := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate test key: %v: %s", err, output)
	}
	pair, err := sshkey.InspectPair(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongFingerprint := "SHA256:" + strings.Repeat("A", 43)
	if wrongFingerprint == pair.Fingerprint {
		wrongFingerprint = "SHA256:" + strings.Repeat("B", 43)
	}
	selected := profile.Profile{
		GitName:        "Ada",
		GitEmail:       "ada@example.com",
		SSHKey:         pair.PrivatePath,
		SSHFingerprint: wrongFingerprint,
		DisableSigning: true,
	}
	client := &Client{Env: isolatedGitEnvironment()}
	if err := client.Apply(repo, "personal", selected); err == nil || !strings.Contains(err.Error(), "fingerprint changed") {
		t.Fatalf("Apply() error = %v, want pinned fingerprint rejection", err)
	}
	value, found, err := client.get(repo, profileKey, true)
	if err != nil {
		t.Fatal(err)
	}
	if found || value != "" {
		t.Fatalf("profile after rejected Apply = %q, found=%v", value, found)
	}
}
