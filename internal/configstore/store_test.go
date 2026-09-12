package configstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gitctx/internal/profile"
)

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	rulePath := filepath.Join(t.TempDir(), "code", "personal")
	store := Store{Path: path}
	want := profile.Profile{GitName: "Ada Lovelace", GitEmail: "ada@example.com", GitHubUser: "ada"}

	if err := store.Save(Config{
		Profiles: map[string]profile.Profile{"personal": want},
		Rules:    map[string]string{rulePath: "personal"},
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Profiles["personal"] != want {
		t.Fatalf("Load() profile = %#v, want %#v", got.Profiles["personal"], want)
	}
	if got.Rules[rulePath] != "personal" {
		t.Fatalf("Load() rule = %q, want personal", got.Rules[rulePath])
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestSaveNormalizesProfileMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store := Store{Path: path}
	if err := store.Save(Config{Profiles: map[string]profile.Profile{
		"personal": {
			GitName:    "  Ada Lovelace  ",
			GitEmail:   "  ada@example.com  ",
			GitHubUser: "  @ada  ",
		},
	}}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := profile.Profile{GitName: "Ada Lovelace", GitEmail: "ada@example.com", GitHubUser: "ada"}
	if got.Profiles["personal"] != want {
		t.Fatalf("Load() profile = %#v, want %#v", got.Profiles["personal"], want)
	}
}

func TestLoadRejectsFilesystemRootRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	filesystemRoot := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	data, err := json.Marshal(Config{
		SchemaVersion: currentSchemaVersion,
		Profiles: map[string]profile.Profile{
			"personal": {GitName: "Ada", GitEmail: "ada@example.com"},
		},
		Rules: map[string]string{filesystemRoot: "personal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{Path: path}).Load(); err == nil || !strings.Contains(err.Error(), "filesystem root") {
		t.Fatalf("Load() error = %v, want filesystem-root rejection", err)
	}
}

func TestSaveRejectsRulePathWithGitPatternMetacharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	config := Config{
		Profiles: map[string]profile.Profile{
			"personal": {GitName: "Ada", GitEmail: "ada@example.com"},
		},
		Rules: map[string]string{filepath.Join(filepath.Dir(path), "code", "personal*"): "personal"},
	}
	if err := (Store{Path: path}).Save(config); err == nil || !strings.Contains(err.Error(), "pattern metacharacters") {
		t.Fatalf("Save() error = %v, want pattern-metacharacter rejection", err)
	}
}

func TestSaveRejectsRulePathWithControlCharacter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	config := Config{
		Profiles: map[string]profile.Profile{"personal": {GitName: "Ada", GitEmail: "ada@example.com"}},
		Rules:    map[string]string{filepath.Join(filepath.Dir(path), "code", "personal\x1b[2J"): "personal"},
	}
	if err := (Store{Path: path}).Save(config); err == nil || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("Save() error = %v, want control-character rejection", err)
	}
}

func TestLoadAndSaveRefuseDanglingConfigSymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	target := filepath.Join(directory, "missing-target.json")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	store := Store{Path: path}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Load() error = %v, want symbolic-link refusal", err)
	}
	if err := store.Save(Config{Profiles: map[string]profile.Profile{}}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Save() error = %v, want symbolic-link refusal", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("config symlink was replaced: info=%v error=%v", info, err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling target unexpectedly exists: %v", err)
	}
}

func TestLoadAndSaveRefuseNonRegularConfigTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	store := Store{Path: path}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Load() error = %v, want non-regular-file refusal", err)
	}
	if err := store.Save(Config{Profiles: map[string]profile.Profile{}}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Save() error = %v, want non-regular-file refusal", err)
	}
}
