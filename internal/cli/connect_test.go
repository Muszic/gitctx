package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitctx/internal/gitconfig"
	"gitctx/internal/githubkeys"
	"gitctx/internal/profile"
	"gitctx/internal/sshkey"
)

type fakeRegistrationSession struct {
	login        string
	inspections  int
	uploads      int
	closed       bool
	inspectError error
	uploadError  error
	existing     bool
}

func (s *fakeRegistrationSession) Login() string { return s.login }
func (s *fakeRegistrationSession) Close()        { s.closed = true }
func (s *fakeRegistrationSession) Inspect(context.Context, string, bool) (githubkeys.Result, error) {
	s.inspections++
	status := githubkeys.Pending
	if s.existing {
		status = githubkeys.Existing
	}
	return githubkeys.Result{Authentication: status, Signing: status}, s.inspectError
}
func (s *fakeRegistrationSession) Register(_ context.Context, key, title string, signing bool) (githubkeys.Result, error) {
	s.uploads++
	if !strings.HasPrefix(key, "ssh-ed25519 ") || len(strings.Fields(key)) != 2 || title != "gitctx:personal" || !signing {
		return githubkeys.Result{}, errors.New("unexpected registration request")
	}
	if s.uploadError != nil {
		return githubkeys.Result{Authentication: githubkeys.Registered, Signing: "not confirmed"}, s.uploadError
	}
	return githubkeys.Result{Authentication: githubkeys.Registered, Signing: githubkeys.Registered}, nil
}

func TestConnectConfirmsAccountAndHandlesPartialSuccess(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "personal")
	setupTestGenerateSSHKey(t, keyPath)
	pair, err := sshkey.InspectPair(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	selected := profile.Profile{
		GitName: "Ada", GitEmail: "ada@example.com", GitHubUser: "ada",
		SSHKey: pair.PrivatePath, SSHFingerprint: pair.Fingerprint,
		SigningKey: pair.PublicPath, SigningFormat: "ssh",
	}
	for _, test := range []struct {
		name, input, login, want string
		existing                 bool
		inspectError             error
		uploadError              error
		wantOpen, wantUpload     bool
		wantSuccess, wantError   bool
	}{
		{name: "decline login", input: "n\n", want: "Registration skipped"},
		{name: "wrong account", input: "y\ny\n", login: "work-user", wantOpen: true, wantError: true, want: "expects @ada"},
		{name: "managed work account", input: "y\ny\n", login: "mona-cat_octo", wantOpen: true, wantError: true, want: "expects @ada"},
		{name: "decline upload", input: "y\nn\n", login: "Ada", wantOpen: true, want: "Upload cancelled"},
		{name: "upload", input: "y\ny\n", login: "Ada", wantOpen: true, wantUpload: true, wantSuccess: true, want: "Connected profile"},
		{name: "existing", input: "y\n", login: "Ada", existing: true, wantOpen: true, wantSuccess: true, want: "already registered"},
		{name: "denied preflight", input: "y\ny\n", login: "Ada", inspectError: errors.New("missing scope"), wantOpen: true, wantError: true, want: "gh auth refresh"},
		{name: "partial", input: "y\ny\n", login: "Ada", uploadError: errors.New("signing permission denied"), wantOpen: true, wantUpload: true, wantError: true, want: "Authentication key  registered"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			session := &fakeRegistrationSession{login: test.login, existing: test.existing, inspectError: test.inspectError, uploadError: test.uploadError}
			opened := false
			app := application{
				in: bufio.NewReader(strings.NewReader(test.input)), out: &output, err: io.Discard,
				openRegistration: func(context.Context) (registrationSession, error) { opened = true; return session, nil },
			}
			success, err := app.registerProfileKey("personal", selected)
			if success != test.wantSuccess || (err != nil) != test.wantError || opened != test.wantOpen || (session.uploads != 0) != test.wantUpload {
				t.Fatalf("success=%v error=%v opened=%v uploads=%d output=%s", success, err, opened, session.uploads, output.String())
			}
			combined := output.String()
			if err != nil {
				combined += err.Error()
			}
			if !strings.Contains(combined, test.want) || opened && !session.closed {
				t.Fatalf("missing %q or unclosed session: %s", test.want, combined)
			}
			if !strings.EqualFold(test.login, "ada") && session.inspections != 0 {
				t.Fatal("wrong account was used to inspect keys")
			}
		})
	}
}

func TestConnectRefusesKeyChangesBeforeReadingCredentials(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "personal")
	setupTestGenerateSSHKey(t, keyPath)
	pair, err := sshkey.InspectPair(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	app := application{
		in: bufio.NewReader(strings.NewReader("y\ny\n")), out: &output,
		openRegistration: func(context.Context) (registrationSession, error) {
			t.Fatal("read credentials after key changed")
			return nil, nil
		},
	}
	selected := profile.Profile{GitHubUser: "ada", SSHKey: keyPath, SSHFingerprint: "SHA256:changed"}
	if _, err := app.registerProfileKey("personal", selected); err == nil {
		t.Fatal("accepted changed fingerprint")
	}
	selected.SSHFingerprint = pair.Fingerprint
	selected.SigningKey, selected.SigningFormat = filepath.Join(t.TempDir(), "missing.pub"), "ssh"
	if _, err := app.registerProfileKey("personal", selected); err == nil {
		t.Fatal("accepted separate or unreadable signing key")
	}
}

func TestConnectHelpAndNoninteractiveModeNeverReadProfileOrLogin(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "does-not-exist.json")
	for _, args := range [][]string{
		{"connect", "--help"},
		{"help", "connect"},
		{"connect", "personal", "--json"},
		{"connect", "personal"},
	} {
		args = append(args, "--config", configPath)
		stdout, stderr, code := runCLI(t, args...)
		want := exitUsage
		if strings.Contains(strings.Join(args, " "), "help") {
			want = exitOK
		}
		if code != want {
			t.Fatalf("args=%v code=%d output=%s stderr=%s", args, code, stdout, stderr)
		}
		if _, err := os.Stat(configPath); !os.IsNotExist(err) {
			t.Fatalf("connect created profile store: %v", err)
		}
	}
}

func TestAutomaticRegistrationOfferIsLimitedToGitHubAndTerminal(t *testing.T) {
	selected := profile.Profile{GitHubUser: "ada", SSHKey: "unused-key"}
	for _, test := range []struct {
		remote string
		want   bool
	}{
		{"", true},
		{"git@github.com:ada/project.git", true},
		{"ssh://git@ssh.github.com:443/ada/project.git", true},
		{"git@gitlab.com:ada/project.git", false},
		{"git@github.example.com:ada/project.git", false},
		{"https://github.com/ada/project", false},
	} {
		state := gitconfig.State{PushURL: test.remote}
		if got := githubRegistrationTarget(state, selected); got != test.want {
			t.Fatalf("remote=%q eligibility=%v", test.remote, got)
		}
		var output bytes.Buffer
		app := application{rawIn: strings.NewReader("y\ny\n"), out: &output}
		connected, err := app.offerKeyRegistration("personal", selected, state)
		if connected || err != nil || output.Len() != 0 {
			t.Fatalf("scripted setup attempted registration: %v %v %s", connected, err, output.String())
		}
	}
	selected.GitHubUser = ""
	if !githubRegistrationTarget(gitconfig.State{PushURL: "git@github.com:ada/project.git"}, selected) {
		t.Fatal("a known GitHub remote should offer registration and prompt for the intended account")
	}
	if githubRegistrationTarget(gitconfig.State{}, selected) {
		t.Fatal("offered GitHub registration without a GitHub remote or username")
	}
}
