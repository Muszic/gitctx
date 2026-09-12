package autorules

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"gitctx/internal/configstore"
	"gitctx/internal/profile"
)

func TestSyncAppliesDirectoryRuleWithoutChangingGlobalIdentity(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "config", "config.json")
	unrelatedInclude := filepath.Join(root, "unrelated.gitconfig")
	personalDir := filepath.Join(root, "personal")
	repo := filepath.Join(personalDir, "nested", "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+global, "GIT_CONFIG_SYSTEM=/dev/null")
	runGit(t, env, root, "config", "--global", "user.name", "Work User")
	runGit(t, env, root, "config", "--global", "user.email", "work@example.com")
	runGit(t, env, root, "config", "--file", unrelatedInclude, "color.ui", "always")
	runGit(t, env, root, "config", "--global", "--add", "include.path", unrelatedInclude)
	runGit(t, env, root, "init", "--quiet", repo)

	manager := &Manager{ConfigPath: configPath, Env: env}
	config := configstore.Config{
		Profiles: map[string]profile.Profile{
			"personal": {
				GitName:       "Personal User",
				GitEmail:      "personal@example.com",
				SSHKey:        filepath.Join(root, "does-not-need-to-exist"),
				SigningKey:    "ABCDEF1234567890",
				SigningFormat: "openpgp",
			},
		},
		Rules: map[string]string{personalDir: "personal"},
	}
	firstManifest, err := manager.Sync(config)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	runGit(t, env, root, "config", "--global", "--add", "include.path", firstManifest)
	secondManifest, err := manager.Sync(config)
	if err != nil {
		t.Fatalf("second Sync() should repair duplicate include: %v", err)
	}
	if firstManifest == secondManifest {
		t.Fatalf("successive syncs reused manifest %q; want immutable replacement", firstManifest)
	}
	if _, err := os.Stat(firstManifest); err != nil {
		t.Fatalf("old immutable manifest was not retained: %v", err)
	}

	if got := effectiveGitValue(t, env, repo, "user.email"); got != "personal@example.com" {
		t.Fatalf("repository email = %q, want personal@example.com", got)
	}
	if got := effectiveGitValue(t, env, repo, "gitctx.profile"); got != "personal" {
		t.Fatalf("repository profile = %q, want personal", got)
	}
	if got := effectiveGitValue(t, env, repo, "color.ui"); got != "always" {
		t.Fatalf("unrelated included setting = %q, want always", got)
	}
	if got := globalGitValue(t, env, root, "user.name"); got != "Work User" {
		t.Fatalf("global name = %q, want Work User", got)
	}
	if got := globalGitValue(t, env, root, "user.email"); got != "work@example.com" {
		t.Fatalf("global email = %q, want work@example.com", got)
	}
	includes := globalGitValues(t, env, root, "include.path")
	assertIncludesExactlyOnce(t, includes, unrelatedInclude, secondManifest)
	if active, err := manager.ActiveManifestPath(); err != nil || active != secondManifest {
		t.Fatalf("ActiveManifestPath() = %q, %v; want %q", active, err, secondManifest)
	}

	profileFragment := manager.ProfilePath(config, "personal")
	if got := fileGitValues(t, env, root, profileFragment, "user.name"); len(got) != 1 || got[0] != "Personal User" {
		t.Fatalf("generated profile user.name = %q, want Personal User", got)
	}
	if got := fileGitValues(t, env, root, profileFragment, "user.email"); len(got) != 1 || got[0] != "personal@example.com" {
		t.Fatalf("generated profile user.email = %q, want personal@example.com", got)
	}
	if got := fileGitValues(t, env, root, profileFragment, "gitctx.profile"); len(got) != 1 || got[0] != "personal" {
		t.Fatalf("generated profile gitctx.profile = %q, want personal", got)
	}
	if got := fileGitValues(t, env, root, profileFragment, "core.sshCommand"); len(got) != 0 {
		t.Fatalf("generated profile core.sshCommand = %q, want omitted", got)
	}
	if got := fileGitValues(t, env, root, profileFragment, "user.signingKey"); len(got) != 0 {
		t.Fatalf("generated profile user.signingKey = %q, want omitted", got)
	}

	config.Rules = map[string]string{}
	if _, err := manager.Sync(config); err != nil {
		t.Fatalf("Sync(empty) error = %v", err)
	}
	if got := effectiveGitValue(t, env, repo, "user.email"); got != "work@example.com" {
		t.Fatalf("repository email after remove = %q, want work@example.com", got)
	}
	if got := globalGitValue(t, env, root, "user.name"); got != "Work User" {
		t.Fatalf("global name after remove = %q, want Work User", got)
	}
	if got := globalGitValue(t, env, root, "user.email"); got != "work@example.com" {
		t.Fatalf("global email after remove = %q, want work@example.com", got)
	}
	if got := globalGitValues(t, env, root, "include.path"); len(got) != 1 || got[0] != unrelatedInclude {
		t.Fatalf("global includes after remove = %q, want only %q", got, unrelatedInclude)
	}
}

func TestNestedRuleOverridesParentRule(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "config", "config.json")
	parent := filepath.Join(root, "code with spaces")
	nested := filepath.Join(parent, "client")
	repo := filepath.Join(nested, "project")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+global, "GIT_CONFIG_SYSTEM=/dev/null")
	runGit(t, env, root, "init", "--quiet", repo)

	manager := &Manager{ConfigPath: configPath, Env: env}
	config := configstore.Config{
		Profiles: map[string]profile.Profile{
			"personal": {GitName: "Personal User", GitEmail: "personal@example.com"},
			"client":   {GitName: "Client User", GitEmail: "client@example.com"},
		},
		Rules: map[string]string{parent: "personal", nested: "client"},
	}
	if _, err := manager.Sync(config); err != nil {
		t.Fatal(err)
	}
	if got := effectiveGitValue(t, env, repo, "user.email"); got != "client@example.com" {
		t.Fatalf("nested repository email = %q, want client@example.com", got)
	}
}

func TestAutomaticRuleDoesNotFollowLinkedWorktreeMetadata(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "config", "config.json")
	personalDir := filepath.Join(root, "personal")
	mainRepo := filepath.Join(personalDir, "main")
	linkedRepo := filepath.Join(root, "outside", "linked")
	if err := os.MkdirAll(mainRepo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(linkedRepo), 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+global, "GIT_CONFIG_SYSTEM=/dev/null")
	runGit(t, env, root, "config", "--global", "user.name", "Work User")
	runGit(t, env, root, "config", "--global", "user.email", "work@example.com")
	runGit(t, env, root, "init", "--quiet", mainRepo)
	runGit(t, env, mainRepo, "-c", "user.name=Bootstrap", "-c", "user.email=bootstrap@example.com", "commit", "--quiet", "--allow-empty", "-m", "initial")
	runGit(t, env, mainRepo, "worktree", "add", "--quiet", linkedRepo)

	manager := &Manager{ConfigPath: configPath, Env: env}
	config := configstore.Config{
		Profiles: map[string]profile.Profile{"personal": {GitName: "Personal User", GitEmail: "personal@example.com"}},
		Rules:    map[string]string{personalDir: "personal"},
	}
	if _, err := manager.Sync(config); err != nil {
		t.Fatal(err)
	}
	if got := effectiveGitValue(t, env, mainRepo, "user.email"); got != "personal@example.com" {
		t.Fatalf("main repository email = %q, want personal profile", got)
	}
	if got := effectiveGitValue(t, env, linkedRepo, "user.email"); got != "work@example.com" {
		t.Fatalf("linked worktree email = %q, want unmanaged work identity", got)
	}
	command := exec.Command("git", "var", "GIT_AUTHOR_IDENT")
	command.Dir = linkedRepo
	command.Env = env
	if output, err := command.CombinedOutput(); err != nil || !strings.Contains(string(output), "Work User <work@example.com>") {
		t.Fatalf("linked worktree did not retain work identity: error=%v output=%s", err, output)
	}
}

func TestAutomaticRulesIgnoreBareAndSeparateGitDirectories(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "config", "config.json")
	personalDir := filepath.Join(root, "personal")
	bareRepo := filepath.Join(personalDir, "archive.git")
	metadata := filepath.Join(personalDir, "metadata")
	outsideRepo := filepath.Join(root, "outside", "repo")
	if err := os.MkdirAll(filepath.Dir(outsideRepo), 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+global, "GIT_CONFIG_SYSTEM=/dev/null")
	runGit(t, env, root, "config", "--global", "user.name", "Work User")
	runGit(t, env, root, "config", "--global", "user.email", "work@example.com")
	runGit(t, env, root, "init", "--quiet", "--bare", bareRepo)
	runGit(t, env, root, "init", "--quiet", "--separate-git-dir", metadata, outsideRepo)

	manager := &Manager{ConfigPath: configPath, Env: env}
	config := configstore.Config{
		Profiles: map[string]profile.Profile{"personal": {GitName: "Personal User", GitEmail: "personal@example.com"}},
		Rules:    map[string]string{personalDir: "personal"},
	}
	if _, err := manager.Sync(config); err != nil {
		t.Fatal(err)
	}
	for label, repo := range map[string]string{"bare repository": bareRepo, "separate Git directory": outsideRepo} {
		if got := effectiveGitValue(t, env, repo, "user.email"); got != "work@example.com" {
			t.Errorf("%s email = %q, want unmanaged work identity", label, got)
		}
	}
}

func TestSyncRemovesManifestFromEarlierXDGGlobalFile(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	xdgHome := filepath.Join(home, ".config")
	xdgConfig := filepath.Join(xdgHome, "git", "config")
	homeConfig := filepath.Join(home, ".gitconfig")
	configPath := filepath.Join(root, "store", "config.json")
	personalDir := filepath.Join(root, "personal")
	repo := filepath.Join(personalDir, "repo")
	if err := os.MkdirAll(filepath.Dir(xdgConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	env := environmentWithout(os.Environ(), "HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")
	env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+xdgHome, "GIT_CONFIG_NOSYSTEM=1")
	runGit(t, env, root, "config", "--file", xdgConfig, "user.name", "Work User")
	runGit(t, env, root, "config", "--file", xdgConfig, "user.email", "work@example.com")
	runGit(t, env, root, "init", "--quiet", repo)

	manager := &Manager{ConfigPath: configPath, Env: env}
	config := configstore.Config{
		Profiles: map[string]profile.Profile{"personal": {GitName: "Personal User", GitEmail: "personal@example.com"}},
		Rules:    map[string]string{personalDir: "personal"},
	}
	if _, err := manager.Sync(config); err != nil {
		t.Fatal(err)
	}
	if got := effectiveGitValue(t, env, repo, "user.email"); got != "personal@example.com" {
		t.Fatalf("email with XDG manifest = %q, want personal", got)
	}
	runGit(t, env, root, "config", "--file", homeConfig, "user.name", "Work User")
	runGit(t, env, root, "config", "--file", homeConfig, "user.email", "work@example.com")
	config.Rules = map[string]string{}
	if _, err := manager.Sync(config); err != nil {
		t.Fatalf("Sync(empty) error = %v", err)
	}
	if got := effectiveGitValue(t, env, repo, "user.email"); got != "work@example.com" {
		t.Fatalf("email after removing earlier XDG manifest = %q, want work", got)
	}
	if values := fileGitValues(t, env, root, xdgConfig, "include.path"); len(values) != 0 {
		t.Fatalf("XDG include paths after removal = %q", values)
	}
}

func TestSiblingProfileStoresCannotClobberAutomaticRules(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	stores := filepath.Join(root, "stores")
	firstPath := filepath.Join(stores, "first.json")
	secondPath := filepath.Join(stores, "second.json")
	firstDir := filepath.Join(root, "first")
	secondDir := filepath.Join(root, "second")
	firstRepo := filepath.Join(firstDir, "repo")
	if err := os.MkdirAll(firstRepo, 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+global, "GIT_CONFIG_SYSTEM=/dev/null")
	runGit(t, env, root, "config", "--global", "user.name", "Work User")
	runGit(t, env, root, "config", "--global", "user.email", "work@example.com")
	runGit(t, env, root, "init", "--quiet", firstRepo)
	first := &Manager{ConfigPath: firstPath, Env: env}
	firstConfig := configstore.Config{
		Profiles: map[string]profile.Profile{"one": {GitName: "One", GitEmail: "one@example.com"}},
		Rules:    map[string]string{firstDir: "one"},
	}
	if _, err := first.Sync(firstConfig); err != nil {
		t.Fatal(err)
	}
	second := &Manager{ConfigPath: secondPath, Env: env}
	secondConfig := configstore.Config{
		Profiles: map[string]profile.Profile{"two": {GitName: "Two", GitEmail: "two@example.com"}},
		Rules:    map[string]string{secondDir: "two"},
	}
	if _, err := second.Sync(secondConfig); err == nil || !strings.Contains(err.Error(), "another or moved profile store") {
		t.Fatalf("second Sync() error = %v, want ownership conflict", err)
	}
	if got := effectiveGitValue(t, env, firstRepo, "user.email"); got != "one@example.com" {
		t.Fatalf("first store identity after second-store refusal = %q", got)
	}
}

func TestSyncRejectsRelativeGlobalConfigEnvironment(t *testing.T) {
	root := t.TempDir()
	manager := &Manager{ConfigPath: filepath.Join(root, "store", "config.json")}
	manager.Env = environmentWithout(os.Environ(), "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")
	manager.Env = append(manager.Env, "GIT_CONFIG_GLOBAL=relative.gitconfig", "GIT_CONFIG_SYSTEM=/dev/null")
	config := configstore.Config{
		Profiles: map[string]profile.Profile{"personal": {GitName: "Ada", GitEmail: "ada@example.com"}},
		Rules:    map[string]string{filepath.Join(root, "personal"): "personal"},
	}
	if _, err := manager.Sync(config); err == nil || !strings.Contains(err.Error(), "must be an absolute path") {
		t.Fatalf("Sync() error = %v, want relative-global rejection", err)
	}
	if _, err := manager.ActiveManifestPath(); err == nil || !strings.Contains(err.Error(), "must be an absolute path") {
		t.Fatalf("ActiveManifestPath() error = %v, want relative-global rejection", err)
	}
}

func TestDifferentStoresCannotRacePastGlobalOwnershipCheck(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+global, "GIT_CONFIG_SYSTEM=/dev/null")
	managers := []*Manager{
		{ConfigPath: filepath.Join(root, "one", "config.json"), Env: env},
		{ConfigPath: filepath.Join(root, "two", "config.json"), Env: env},
	}
	configs := []configstore.Config{
		{Profiles: map[string]profile.Profile{"one": {GitName: "One", GitEmail: "one@example.com"}}, Rules: map[string]string{filepath.Join(root, "code-one"): "one"}},
		{Profiles: map[string]profile.Profile{"two": {GitName: "Two", GitEmail: "two@example.com"}}, Rules: map[string]string{filepath.Join(root, "code-two"): "two"}},
	}
	results := make([]error, len(managers))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range managers {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, results[index] = managers[index].Sync(configs[index])
		}(index)
	}
	close(start)
	wait.Wait()
	successes := 0
	conflicts := 0
	for _, err := range results {
		if err == nil {
			successes++
		} else if strings.Contains(err.Error(), "another or moved profile store") {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent Sync() error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results = %v; want one success and one ownership conflict", results)
	}
	if includes := globalGitValues(t, env, root, "include.path"); len(includes) != 1 {
		t.Fatalf("global includes after concurrent stores = %q, want exactly one", includes)
	}
}

func TestSyncCleansOnlyOwnedAbandonedStages(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "store", "config.json")
	personalDir := filepath.Join(root, "personal")
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+global, "GIT_CONFIG_SYSTEM=/dev/null")
	manager := &Manager{ConfigPath: configPath, Env: env}
	config := configstore.Config{
		Profiles: map[string]profile.Profile{"personal": {GitName: "Ada", GitEmail: "ada@example.com"}},
		Rules:    map[string]string{personalDir: "personal"},
	}
	manifest, err := manager.Sync(config)
	if err != nil {
		t.Fatal(err)
	}
	ownedSection := "gitctxstage0123456789abcdef0123456789abcdef"
	foreignSection := "gitctxstagefedcba9876543210fedcba9876543210"
	runGit(t, env, root, "config", "--global", "--add", ownedSection+".path", manifest)
	runGit(t, env, root, "config", "--global", "--add", foreignSection+".path", filepath.Join(root, "unrelated.gitconfig"))

	if _, err := manager.Sync(config); err != nil {
		t.Fatalf("Sync() with abandoned stage error = %v", err)
	}
	if values := globalGitValues(t, env, root, ownedSection+".path"); len(values) != 0 {
		t.Fatalf("owned abandoned stage remains = %q", values)
	}
	if values := globalGitValues(t, env, root, foreignSection+".path"); len(values) != 1 || values[0] != filepath.Join(root, "unrelated.gitconfig") {
		t.Fatalf("unrelated stage changed = %q", values)
	}
}

func TestGeneratedManifestShapeRequiresStoreNamespace(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	manifest := generatedManifestPrefix + token + ".gitconfig"
	ordinary := filepath.Join(t.TempDir(), "generations", token, manifest)
	if looksLikeGeneratedManifestPath(ordinary) {
		t.Fatalf("ordinary lookalike path %q was classified as a gitctx manifest", ordinary)
	}
	managedShape := filepath.Join(t.TempDir(), "stores", token, "generations", token, manifest)
	if !looksLikeGeneratedManifestPath(managedShape) {
		t.Fatalf("managed-shape path %q was not recognized", managedShape)
	}
}

func TestManifestMatchesConfigChecksEveryGeneratedFile(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	manager := &Manager{
		ConfigPath: filepath.Join(root, "store", "config.json"),
		Env:        append(os.Environ(), "GIT_CONFIG_GLOBAL="+global, "GIT_CONFIG_SYSTEM=/dev/null"),
	}
	config := configstore.Config{
		Profiles: map[string]profile.Profile{"personal": {GitName: "Ada", GitEmail: "ada@example.com"}},
		Rules:    map[string]string{filepath.Join(root, "personal"): "personal"},
	}
	manifest, err := manager.Sync(config)
	if err != nil {
		t.Fatal(err)
	}
	if !manager.ManifestMatchesConfig(config, manifest) {
		t.Fatal("freshly synchronized manifest does not match config")
	}
	profilePath := manager.ProfilePath(config, "personal")
	if err := os.Remove(profilePath); err != nil {
		t.Fatal(err)
	}
	if manager.ManifestMatchesConfig(config, manifest) {
		t.Fatal("snapshot with missing profile fragment still matches config")
	}
	manifest, err = manager.Sync(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("[user]\n\temail = wrong@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if manager.ManifestMatchesConfig(config, manifest) {
		t.Fatal("corrupted manifest still matches config")
	}
}

func TestGlobalLockPathCanonicalizesConfigAliases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation commonly requires elevated privileges on Windows")
	}
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	if err := os.WriteFile(global, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "global-link.gitconfig")
	if err := os.Symlink(global, alias); err != nil {
		t.Fatal(err)
	}
	managerFor := func(path string) *Manager {
		return &Manager{
			ConfigPath: filepath.Join(root, "store", "config.json"),
			Env:        append(environmentWithout(os.Environ(), "GIT_CONFIG_GLOBAL"), "GIT_CONFIG_GLOBAL="+path),
		}
	}
	direct, err := managerFor(global).globalLockPaths()
	if err != nil {
		t.Fatal(err)
	}
	throughAlias, err := managerFor(alias).globalLockPaths()
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != 1 || len(throughAlias) != 1 || direct[0] != throughAlias[0] {
		t.Fatalf("global lock aliases differ: direct %q, alias %q", direct, throughAlias)
	}
}

func TestGlobalLockPathsCoverSharedHomeAndXDGScopes(t *testing.T) {
	root := t.TempDir()
	sharedXDG := filepath.Join(root, "shared-xdg")
	sharedHome := filepath.Join(root, "shared-home")
	managerFor := func(home, xdg string) *Manager {
		env := environmentWithout(os.Environ(), "HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL")
		return &Manager{
			ConfigPath: filepath.Join(root, "store", "config.json"),
			Env:        append(env, "HOME="+home, "XDG_CONFIG_HOME="+xdg),
		}
	}
	first, err := managerFor(filepath.Join(root, "home-a"), sharedXDG).globalLockPaths()
	if err != nil {
		t.Fatal(err)
	}
	second, err := managerFor(filepath.Join(root, "home-b"), sharedXDG).globalLockPaths()
	if err != nil {
		t.Fatal(err)
	}
	if !hasCommonValue(first, second) {
		t.Fatalf("different homes with shared XDG have no common lock: %q vs %q", first, second)
	}
	first, err = managerFor(sharedHome, filepath.Join(root, "xdg-a")).globalLockPaths()
	if err != nil {
		t.Fatal(err)
	}
	second, err = managerFor(sharedHome, filepath.Join(root, "xdg-b")).globalLockPaths()
	if err != nil {
		t.Fatal(err)
	}
	if !hasCommonValue(first, second) {
		t.Fatalf("shared home with different XDG roots has no common lock: %q vs %q", first, second)
	}
}

func hasCommonValue(left, right []string) bool {
	for _, leftValue := range left {
		for _, rightValue := range right {
			if leftValue == rightValue {
				return true
			}
		}
	}
	return false
}

func TestSyncMovesManagedIncludeAfterLaterGlobalIdentity(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "global.gitconfig")
	configPath := filepath.Join(root, "config", "config.json")
	personalDir := filepath.Join(root, "personal")
	repo := filepath.Join(personalDir, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+global, "GIT_CONFIG_SYSTEM=/dev/null")
	runGit(t, env, root, "init", "--quiet", repo)
	manager := &Manager{ConfigPath: configPath, Env: env}
	config := configstore.Config{
		Profiles: map[string]profile.Profile{"personal": {GitName: "Personal User", GitEmail: "personal@example.com"}},
		Rules:    map[string]string{personalDir: "personal"},
	}
	if _, err := manager.Sync(config); err != nil {
		t.Fatal(err)
	}
	runGit(t, env, root, "config", "--global", "user.name", "Work User")
	runGit(t, env, root, "config", "--global", "user.email", "work@example.com")
	if got := effectiveGitValue(t, env, repo, "user.email"); got != "work@example.com" {
		t.Fatalf("pre-sync repository email = %q, want later global override", got)
	}
	if _, err := manager.Sync(config); err != nil {
		t.Fatal(err)
	}
	if got := effectiveGitValue(t, env, repo, "user.email"); got != "personal@example.com" {
		t.Fatalf("post-sync repository email = %q, want automatic profile", got)
	}
}

func TestProfileFilenamesRemainDistinctIgnoringCase(t *testing.T) {
	manager := &Manager{ConfigPath: filepath.Join(t.TempDir(), "config.json")}
	config := configstore.Config{Profiles: map[string]profile.Profile{
		"work": {GitName: "Lower", GitEmail: "lower@example.com"},
		"Work": {GitName: "Upper", GitEmail: "upper@example.com"},
	}}
	lower := filepath.Base(manager.ProfilePath(config, "work"))
	upper := filepath.Base(manager.ProfilePath(config, "Work"))
	if strings.EqualFold(lower, upper) {
		t.Fatalf("case-distinct profiles map to colliding filenames %q and %q", lower, upper)
	}
}

func TestSyncRejectsFilesystemRootRule(t *testing.T) {
	manager := NewManager(filepath.Join(t.TempDir(), "config.json"))
	manager.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+filepath.Join(t.TempDir(), "global.gitconfig"), "GIT_CONFIG_SYSTEM=/dev/null")
	config := configstore.Config{
		Profiles: map[string]profile.Profile{
			"personal": {GitName: "Ada", GitEmail: "ada@example.com"},
		},
		Rules: map[string]string{string(filepath.Separator): "personal"},
	}
	if _, err := manager.Sync(config); err == nil || !strings.Contains(err.Error(), "filesystem root") {
		t.Fatalf("Sync() error = %v, want filesystem-root rejection", err)
	}
}

func runGit(t *testing.T, env []string, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	command.Env = env
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v error = %v: %s", args, err, output)
	}
}

func effectiveGitValue(t *testing.T, env []string, repo, key string) string {
	t.Helper()
	values := gitConfigValues(t, env, repo, key)
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func globalGitValue(t *testing.T, env []string, dir, key string) string {
	t.Helper()
	values := globalGitValues(t, env, dir, key)
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func gitConfigValues(t *testing.T, env []string, dir, key string) []string {
	t.Helper()
	return runGitConfigValues(t, env, dir, "--null", "--get-all", key)
}

func globalGitValues(t *testing.T, env []string, dir, key string) []string {
	t.Helper()
	return runGitConfigValues(t, env, dir, "--global", "--no-includes", "--null", "--get-all", key)
}

func fileGitValues(t *testing.T, env []string, dir, path, key string) []string {
	t.Helper()
	return runGitConfigValues(t, env, dir, "--file", path, "--null", "--get-all", key)
}

func runGitConfigValues(t *testing.T, env []string, dir string, args ...string) []string {
	t.Helper()
	command := exec.Command("git", append([]string{"config"}, args...)...)
	command.Dir = dir
	command.Env = env
	output, err := command.Output()
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
		return nil
	}
	if err != nil {
		t.Fatalf("git config %v error = %v", args, err)
	}
	return strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
}

func assertIncludesExactlyOnce(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("global includes = %q, want %q", got, want)
	}
	counts := make(map[string]int, len(got))
	for _, value := range got {
		counts[value]++
	}
	for _, value := range want {
		if counts[value] != 1 {
			t.Fatalf("global includes = %q, want %q exactly once", got, value)
		}
	}
}

func environmentWithout(environment []string, names ...string) []string {
	blocked := make(map[string]bool, len(names))
	for _, name := range names {
		blocked[name] = true
	}
	filtered := make([]string, 0, len(environment))
	for _, item := range environment {
		name, _, found := strings.Cut(item, "=")
		if !found || !blocked[name] {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
