package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gitctx/internal/configstore"
	"gitctx/internal/gitconfig"
	"gitctx/internal/githubkeys"
	"gitctx/internal/managedkey"
	"gitctx/internal/profile"
	"gitctx/internal/sshkey"
)

type nativeSession struct {
	fakeRegistrationSession
	accountID int64
}

func (s *nativeSession) Account() githubkeys.Account {
	id := s.accountID
	if id == 0 {
		id = 42
	}
	return githubkeys.Account{Login: s.login, ID: id, Name: "Ada Lovelace"}
}

type fakeLoginKeys struct {
	pair                               sshkey.Pair
	created, unlocked, preflight       int
	preflightErr, unlockErr, createErr error
	retainCreatedKey                   bool
}

func (k *fakeLoginKeys) Preflight() error { k.preflight++; return k.preflightErr }
func (k *fakeLoginKeys) Create(string, string) (managedkey.Key, error) {
	k.created++
	if k.createErr != nil && !k.retainCreatedKey {
		return managedkey.Key{}, k.createErr
	}
	return managedkey.Key{ID: strings.Repeat("a", 32), Pair: k.pair}, k.createErr
}
func (k *fakeLoginKeys) Unlock(profile.Profile) error { k.unlocked++; return k.unlockErr }

func nativeTestApp(t *testing.T, input string) (application, *bytes.Buffer, *bytes.Buffer, *nativeSession, *fakeLoginKeys, *int) {
	t.Helper()
	key := filepath.Join(t.TempDir(), "key")
	setupTestGenerateSSHKey(t, key)
	pair, err := sshkey.InspectPair(key)
	if err != nil {
		t.Fatal(err)
	}
	output, stderr := new(bytes.Buffer), new(bytes.Buffer)
	session := &nativeSession{fakeRegistrationSession: fakeRegistrationSession{login: "Ada"}}
	keys, calls := &fakeLoginKeys{pair: pair}, new(int)
	app := application{
		in: bufio.NewReader(strings.NewReader(input)), rawIn: strings.NewReader("not a real terminal"), out: output, err: stderr,
		store: configstore.Store{Path: filepath.Join(t.TempDir(), "config.json")}, git: gitconfig.NewClient(), command: "login",
		loginTerminal: func() bool { return true }, loginKeys: keys,
		authorizeLogin: func(_ context.Context, id string, notify func(string, string)) (loginSession, error) {
			*calls++
			if id != "test-client-id" {
				t.Errorf("client ID=%q", id)
			}
			notify("ABCD-1234", "https://github.com/login/device")
			return session, nil
		}, openLoginBrowser: func(uri string) error {
			if uri != "https://github.com/login/device" {
				t.Fatal("unsafe browser destination")
			}
			return nil
		},
	}
	return app, output, stderr, session, keys, calls
}

func TestNativeLoginWorksWithoutRepositoryAndDefaultsToPrivateEmail(t *testing.T) {
	app, output, stderr, session, keys, calls := nativeTestApp(t, "\n\n")
	if code := app.login([]string{"personal", "--client-id", "test-client-id"}); code != 0 {
		t.Fatalf("code=%d error=%s output=%s", code, stderr, output)
	}
	config, err := app.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p := config.Profiles["personal"]
	if p.GitHubUser != "Ada" || p.GitEmail != "42+Ada@users.noreply.github.com" || p.GitName != "Ada Lovelace" || !p.GitHubConnected || p.ManagedKeyID == "" || keys.created != 1 || keys.unlocked != 1 || *calls != 1 || !session.closed || session.uploads != 1 {
		t.Fatalf("profile=%+v keys=%+v calls=%d session=%+v", p, keys, *calls, session)
	}
	if !strings.Contains(output.String(), "gitctx use personal") || strings.Contains(output.String(), "gh auth") {
		t.Fatalf("unexpected onboarding output: %s", output)
	}
	bytes, err := os.ReadFile(app.store.Path)
	if err != nil || strings.Contains(string(bytes), "access_token") || strings.Contains(string(bytes), "BEGIN OPENSSH") {
		t.Fatal("credential material appeared in metadata")
	}
	// An ordinary repeat unlocks the same key, without another browser login.
	if code := app.login([]string{"personal"}); code != 0 || keys.created != 1 || keys.unlocked != 2 || *calls != 1 {
		t.Fatalf("repeat login code=%d stderr=%s keys=%+v", code, stderr, keys)
	}
}

func TestNativeLoginWrongAccountMakesNoKeyOrUpload(t *testing.T) {
	app, _, stderr, session, keys, _ := nativeTestApp(t, "")
	code := app.login([]string{"personal", "--client-id", "test-client-id", "--github", "work-user", "--email", "ada@example.com"})
	if code != exitUnsafe || session.uploads != 0 || keys.created != 0 || !session.closed || !strings.Contains(stderr.String(), "expected @work-user") {
		t.Fatalf("code=%d keys=%+v session=%+v error=%s", code, keys, session, stderr)
	}
	if _, err := os.Stat(app.store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong browser account persisted a profile")
	}
}

func TestNativeLoginPartialSuccessRetriesTheSameKey(t *testing.T) {
	app, _, stderr, session, keys, calls := nativeTestApp(t, "")
	session.uploadError = errors.New("signing permission denied")
	args := []string{"personal", "--client-id", "test-client-id", "--github", "Ada", "--email", "ada@example.com"}
	if code := app.login(args); code != exitUnsafe {
		t.Fatalf("code=%d error=%s", code, stderr)
	}
	config, _ := app.store.Load()
	before := config.Profiles["personal"]
	if before.GitHubConnected || before.SSHKey != keys.pair.PrivatePath || before.ManagedKeyID == "" {
		t.Fatalf("pending profile lost: %+v", before)
	}
	session.uploadError = nil
	if code := app.login(args); code != 0 {
		t.Fatalf("retry error=%s", stderr)
	}
	config, _ = app.store.Load()
	after := config.Profiles["personal"]
	if !after.GitHubConnected || before.SSHKey != after.SSHKey || keys.created != 1 || *calls != 2 {
		t.Fatalf("retry replaced key or lost state: before=%+v after=%+v keys=%+v", before, after, keys)
	}
}

func TestNativeLoginFailsClosedBeforeAuthorization(t *testing.T) {
	for _, mode := range []string{"json", "piped", "missing client", "vault locked", "existing profile"} {
		t.Run(mode, func(t *testing.T) {
			app, _, stderr, _, keys, calls := nativeTestApp(t, "\n\n")
			args := []string{"personal", "--client-id", "test-client-id"}
			switch mode {
			case "json":
				args = append(args, "--json")
			case "piped":
				app.loginTerminal = nil
			case "missing client":
				t.Setenv("GITCTX_GITHUB_CLIENT_ID", "")
				args = []string{"personal"}
			case "vault locked":
				keys.preflightErr = errors.New("vault unavailable")
			case "existing profile":
				if err := app.store.Save(configstore.Config{SchemaVersion: 1, Profiles: map[string]profile.Profile{"personal": {GitName: "Original", GitEmail: "original@example.com"}}}); err != nil {
					t.Fatal(err)
				}
			}
			if code := app.login(args); code == 0 || *calls != 0 || keys.created != 0 {
				t.Fatalf("code=%d calls=%d created=%d error=%s", code, *calls, keys.created, stderr)
			}
		})
	}
}

func TestNativeLoginDeclineAndBrowserFailureKeepProfiles(t *testing.T) {
	app, output, stderr, _, keys, _ := nativeTestApp(t, "\n\n")
	app.openLoginBrowser = func(string) error { return errors.New("no browser") }
	app.authorizeLogin = func(_ context.Context, _ string, notify func(string, string)) (loginSession, error) {
		notify("ABCD-1234", "https://github.com/login/device")
		return nil, errors.New("authorization declined")
	}
	if code := app.login([]string{"--client-id", "test-client-id"}); code != exitUnsafe || keys.created != 0 || !strings.Contains(output.String(), "open the URL") || !strings.Contains(stderr.String(), "declined") {
		t.Fatalf("output=%s error=%s", output, stderr)
	}
}

func TestNativeLoginVaultFailureKeepsProfilesAndExplainsMacPrompt(t *testing.T) {
	app, output, stderr, session, keys, _ := nativeTestApp(t, "")
	original := configstore.Config{SchemaVersion: 1, Profiles: map[string]profile.Profile{
		"work":   {GitName: "Work User", GitEmail: "work@example.invalid"},
		"manual": {GitName: "Existing User", GitEmail: "existing@example.invalid"},
	}}
	if err := app.store.Save(original); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(app.store.Path)
	if err != nil {
		t.Fatal(err)
	}
	keys.createErr = errors.New("could not verify secure passphrase storage: timed out waiting for OS password vault approval; no SSH key was generated")
	code := app.login([]string{"personal", "--client-id", "test-client-id", "--github", "Ada", "--email", "ada@example.invalid"})
	if code != exitUnsafe || keys.unlocked != 0 || session.uploads != 0 || !session.closed || !strings.Contains(stderr.String(), "timed out waiting") {
		t.Fatal("failed vault approval continued to unlock/upload, or lost its diagnostic")
	}
	after, err := os.ReadFile(app.store.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed vault approval changed an existing profile")
	}
	if _, err := os.Stat(app.store.Path + ".login-personal.lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed vault approval stranded the login lock")
	}
	if runtime.GOOS == "darwin" && (!strings.Contains(output.String(), "login keychain password") || !strings.Contains(output.String(), "not an SSH passphrase") || !strings.Contains(output.String(), "click Allow")) {
		t.Fatal("macOS enrollment did not explain which password the Keychain dialog requires")
	}
}

func TestNativeLoginInitialAgentFailureRetainsTheSamePendingKey(t *testing.T) {
	app, _, stderr, session, keys, _ := nativeTestApp(t, "")
	keys.createErr, keys.retainCreatedKey = errors.New("initial agent unlock failed"), true
	args := []string{"personal", "--client-id", "test-client-id", "--github", "Ada", "--email", "ada@example.invalid"}
	if code := app.login(args); code != exitUnsafe || session.uploads != 0 || keys.unlocked != 0 {
		t.Fatalf("initial agent failure code=%d error=%s", code, stderr)
	}
	config, err := app.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	pending := config.Profiles["personal"]
	if pending.SSHKey != keys.pair.PrivatePath || pending.ManagedKeyID == "" || pending.GitHubConnected {
		t.Fatal("initial agent failure did not retain the generated key as pending")
	}
	keys.createErr = nil
	if code := app.login(args); code != 0 || keys.created != 1 || keys.unlocked != 1 {
		t.Fatalf("retry failed or generated another key: code=%d error=%s", code, stderr)
	}
	config, err = app.store.Load()
	if err != nil || config.Profiles["personal"].SSHKey != pending.SSHKey || !config.Profiles["personal"].GitHubConnected {
		t.Fatal("retry failed to complete the same pending profile")
	}
}

func TestNativeLoginHelpNeedsNoConfigAndUseUnlocksBeforeMutation(t *testing.T) {
	if output, stderr, code := runCLI(t, "login", "--help", "--config", filepath.Join(t.TempDir(), "missing", "config.json")); code != 0 || !strings.Contains(output, "No gh installation") || stderr != "" {
		t.Fatalf("code=%d output=%s error=%s", code, output, stderr)
	}
	app, _, stderr, _, keys, _ := nativeTestApp(t, "\n\n")
	if code := app.login([]string{"--client-id", "test-client-id"}); code != 0 {
		t.Fatal(stderr)
	}
	keys.unlockErr = errors.New("OS vault locked")
	// Even outside a Git repository, this error must come before Git mutation.
	if code := app.use([]string{"personal", "--repo", t.TempDir()}); code != exitUnsafe || !strings.Contains(stderr.String(), "OS vault locked") {
		t.Fatalf("code=%d error=%s", code, stderr)
	}
}

func TestNativeLoginPinsNumericAccountAndPreservesExistingProfiles(t *testing.T) {
	app, _, stderr, session, _, _ := nativeTestApp(t, "\n\n")
	work := profile.Profile{GitName: "Work User", GitEmail: "work@example.invalid"}
	if err := app.store.Save(configstore.Config{SchemaVersion: 1, Profiles: map[string]profile.Profile{"work": work}}); err != nil {
		t.Fatal(err)
	}
	if code := app.login([]string{"--client-id", "test-client-id"}); code != 0 {
		t.Fatal(stderr)
	}
	before, _ := app.store.Load()
	if before.Profiles["work"] != work {
		t.Fatal("existing work profile changed during enrollment")
	}
	posts := session.uploads
	session.accountID = 43
	if code := app.login([]string{"personal", "--reauthorize", "--client-id", "test-client-id"}); code != exitUnsafe || session.uploads != posts {
		t.Fatalf("reused username redirected registration: code=%d error=%s", code, stderr)
	}
	after, _ := app.store.Load()
	if after.Profiles["personal"] != before.Profiles["personal"] {
		t.Fatal("mismatched account changed saved metadata")
	}
}

func TestNativeLoginProfileUseKeepsGlobalWorkDefaults(t *testing.T) {
	app, _, stderr, _, keys, _ := nativeTestApp(t, "\n\n")
	global := filepath.Join(t.TempDir(), "global.gitconfig")
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	app.git = gitconfig.NewClient() // Capture the isolated environment, not the real work defaults.
	repo, workRepo := t.TempDir(), t.TempDir()
	runGit(t, repo, "init", "--quiet", "--template=")
	runGit(t, workRepo, "init", "--quiet", "--template=")
	runGit(t, repo, "config", "--global", "user.name", "Work User")
	runGit(t, repo, "config", "--global", "user.email", "work@example.invalid")
	runGit(t, repo, "config", "--global", "user.signingKey", "work-key.pub")
	runGit(t, repo, "config", "--global", "gpg.format", "ssh")
	runGit(t, repo, "config", "--global", "commit.gpgSign", "true")
	before, err := os.ReadFile(global)
	if err != nil {
		t.Fatal(err)
	}
	if code := app.login([]string{"--client-id", "test-client-id"}); code != 0 {
		t.Fatal(stderr)
	}
	if code := app.use([]string{"personal", "--repo", repo}); code != 0 {
		t.Fatal(stderr)
	}
	if keys.unlocked != 2 || gitValue(t, repo, "user.email") != "42+Ada@users.noreply.github.com" {
		t.Fatal("use did not unlock and apply the native profile")
	}
	runGit(t, repo, "commit", "--allow-empty", "--quiet", "-m", "native profile reuse")
	after, err := os.ReadFile(global)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("native enrollment/use modified global work settings")
	}
	state, err := app.git.Inspect(workRepo)
	if err != nil || state.GitName != "Work User" || state.GitEmail != "work@example.invalid" || state.Profile != "" || state.SigningKey != "work-key.pub" {
		t.Fatalf("work repo changed: state=%+v error=%v", state, err)
	}
}

func TestNativeLoginPromptHandlesAndCancelledInputDoNotStrandLocks(t *testing.T) {
	app, _, stderr, _, _, _ := nativeTestApp(t, "@ada\n\n")
	if code := app.login([]string{"--client-id", "test-client-id"}); code != 0 {
		t.Fatalf("@username rejected: %s", stderr)
	}
	app, _, _, _, keys, calls := nativeTestApp(t, "")
	if code := app.login([]string{"--client-id", "test-client-id"}); code != exitUsage || keys.created != 0 || *calls != 0 {
		t.Fatal("cancelled input continued enrollment")
	}
	if _, err := os.Stat(app.store.Path + ".login-personal.lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled question stranded a login lock")
	}
}
