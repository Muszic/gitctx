package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"gitctx/internal/filelock"
	"gitctx/internal/githubkeys"
	"gitctx/internal/managedkey"
	"gitctx/internal/profile"
)

type loginSession interface {
	registrationSession
	Account() githubkeys.Account
}

type loginKeyManager interface {
	Preflight() error
	Create(name, configPath string) (managedkey.Key, error)
	Unlock(profile.Profile) error
}

func (a application) keyManager() loginKeyManager {
	if a.loginKeys != nil {
		return a.loginKeys
	}
	return managedkey.New()
}

func (a application) login(args []string) (code int) {
	var clientID, expectedUser, email, gitName string
	var help, jsonOutput, noBrowser, reauthorize bool
	positionals, err := parseOptions(args, map[string]*string{"--client-id": &clientID, "--github": &expectedUser, "--email": &email, "--name": &gitName}, map[string]*bool{
		"--help": &help, "-h": &help, "--json": &jsonOutput, "--no-browser": &noBrowser, "--reauthorize": &reauthorize,
	})
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Run 'gitctx login --help'.")
	}
	if help {
		printLoginHelp(a.out)
		return exitOK
	}
	if len(positionals) > 1 {
		return a.fail(exitUsage, "invalid_usage", errors.New("login accepts one profile name"), "Usage: gitctx login [profile]")
	}
	terminal := isTerminalInput(a.rawIn)
	if a.loginTerminal != nil {
		terminal = a.loginTerminal()
	}
	if jsonOutput || !terminal {
		return a.fail(exitUsage, "interactive_terminal_required", errors.New("native login requires a terminal for browser authorization and secure key storage"), "Run 'gitctx login personal' interactively; JSON and piped input never authorize or upload keys.")
	}
	name := "personal"
	if len(positionals) == 1 {
		name = positionals[0]
	}
	if err := profile.ValidateName(name); err != nil {
		return a.fail(exitUsage, "invalid_profile", err, "")
	}
	expectedUser = strings.TrimPrefix(strings.TrimSpace(expectedUser), "@")
	email, gitName = strings.TrimSpace(email), strings.TrimSpace(gitName)
	if err := validateLoginIdentity(expectedUser, email, gitName); err != nil {
		return a.fail(exitUsage, "invalid_profile", err, "")
	}
	config, err := a.store.Load()
	if err != nil {
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	selected, exists := config.Profiles[name]
	if exists && selected.ManagedKeyID == "" {
		return a.fail(exitProfile, "profile_exists", fmt.Errorf("profile %q already exists and uses an independently managed key or identity", name), "It was not changed. Use 'gitctx connect' for its existing key, or choose a new login profile name.")
	}
	if exists && ((expectedUser != "" && !strings.EqualFold(expectedUser, selected.GitHubUser)) || (email != "" && email != selected.GitEmail) || (gitName != "" && gitName != selected.GitName)) {
		return a.fail(exitProfile, "profile_conflict", errors.New("login will not silently replace the saved account or commit identity"), "Choose a different profile name; the existing profile was kept.")
	}
	keys := a.keyManager()
	if exists && selected.GitHubConnected && !reauthorize {
		a.printLoginVaultNotice()
		if err := keys.Unlock(selected); err != nil {
			return a.fail(exitUnsafe, "key_unlock_failed", err, "Your saved profile and key were kept.")
		}
		a.printLoginReady(name, selected)
		return exitOK
	}
	if clientID == "" {
		clientID = os.Getenv("GITCTX_GITHUB_CLIENT_ID")
	}
	if clientID == "" {
		clientID = githubkeys.OAuthClientID
	}
	if err := githubkeys.ValidateClientID(clientID); err != nil {
		return a.fail(exitUsage, "github_app_not_configured", err, "See the Native login app-registration section in README.md. Existing setup/connect commands remain available.")
	}
	if err := keys.Preflight(); err != nil {
		return a.fail(exitUnsafe, "secure_storage_unavailable", err, "Nothing was uploaded; no existing key, profile, or Git setting was changed.")
	}
	if exists {
		expectedUser = selected.GitHubUser
	} else {
		if expectedUser == "" {
			expectedUser, err = a.promptValidatedSetupValue("GitHub username (optional; Enter detects it in the browser)", "", false, validateSetupGitHubUser)
			if err != nil {
				return a.fail(exitUsage, "login_cancelled", err, "Nothing was uploaded.")
			}
		}
		if email == "" {
			email, err = a.promptValidatedSetupValue("Commit email (optional; Enter uses your GitHub private email)", "", false, func(value string) error {
				if value == "" {
					return nil
				}
				return validateSetupGitEmail(value)
			})
			if err != nil {
				return a.fail(exitUsage, "login_cancelled", err, "Nothing was uploaded.")
			}
		}
	}
	expectedUser = strings.TrimPrefix(strings.TrimSpace(expectedUser), "@")
	// Text prompts hold no locks: Ctrl-C/EOF there must not strand a login lock.
	// Once authorization starts, cancellation is handled and the per-profile
	// lock is released. Shared store locks are used only for short merges.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, 16*time.Minute)
	defer deadline()
	lock, err := filelock.Acquire(a.store.Path+".login-"+name+".lock", 10*time.Second)
	if err != nil {
		return a.fail(exitConfig, "login_busy", err, "Another login may still be active.")
	}
	defer func() {
		if err := lock.Release(); err != nil {
			code = a.fail(exitConfig, "login_lock_failed", err, "Local and remote account state was kept; inspect the reported lock before retrying.")
		}
	}()
	latest, err := a.store.Load()
	if err != nil {
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	latestProfile, existsNow := latest.Profiles[name]
	if existsNow != exists || (exists && latestProfile != selected) {
		return a.fail(exitProfile, "profile_changed", errors.New("the profile changed while login questions were being answered"), "Run login again to use its current values; it was not overwritten.")
	}
	if ctx.Err() != nil {
		return a.fail(exitUnsafe, "login_cancelled", errors.New("login was cancelled"), "Nothing was uploaded.")
	}
	fmt.Fprintln(a.out, "\nAuthorize gitctx with the intended GitHub account.")
	if email != "" {
		fmt.Fprintln(a.out, "  Your commit email is recorded in Git history and may become public.")
	}
	fmt.Fprintln(a.out, "  gitctx will protect a separate key in your OS password vault and register its public half for authentication and signing.")
	fmt.Fprintln(a.out, "  No repository, global work identity, or GitHub CLI login will be changed. The GitHub token is not saved.")
	if expectedUser != "" {
		fmt.Fprintf(a.out, "  Expected account: @%s\n", escapeDisplayControls(expectedUser))
	}
	authorize := a.authorizeLogin
	if authorize == nil {
		authorize = func(ctx context.Context, id string, announce func(string, string)) (loginSession, error) {
			return githubkeys.AuthorizeDevice(ctx, id, announce)
		}
	}
	session, err := authorize(ctx, clientID, func(code, uri string) {
		fmt.Fprintf(a.out, "\nGitHub verification code: %s\nOpen: %s\n", code, uri)
		fmt.Fprintln(a.out, "Only approve this code if you started this login here. GitHub may request sign-in or 2FA.")
		if !noBrowser {
			open := a.openLoginBrowser
			if open == nil {
				open = openGitHubLoginBrowser
			}
			if err := open(uri); err != nil {
				fmt.Fprintln(a.out, "Could not open the browser automatically; open the URL above yourself.")
			}
		}
	})
	if err != nil {
		return a.fail(exitUnsafe, "github_authorization_failed", err, "Existing local profiles and keys were kept.")
	}
	defer session.Close()
	account := session.Account()
	if expectedUser != "" && !strings.EqualFold(account.Login, expectedUser) {
		return a.fail(exitUnsafe, "github_account_mismatch", fmt.Errorf("authorized as @%s, but expected @%s; no keys were uploaded", escapeDisplayControls(account.Login), escapeDisplayControls(expectedUser)), "Run login again and choose the intended browser account.")
	}
	if exists && account.ID != selected.GitHubAccountID {
		return a.fail(exitUnsafe, "github_account_mismatch", errors.New("the authenticated GitHub account ID no longer matches this profile; no keys were uploaded"), "The existing profile and key were kept. Check the browser account.")
	}
	fmt.Fprintf(a.out, "\nAuthorized as @%s.\n", escapeDisplayControls(account.Login))
	a.printLoginVaultNotice()
	if !exists {
		if email == "" {
			email = fmt.Sprintf("%d+%s@users.noreply.github.com", account.ID, account.Login)
		}
		if gitName == "" {
			gitName = strings.TrimSpace(account.Name)
			if gitName == "" || validateSetupGitName(gitName) != nil {
				gitName = account.Login
			}
		}
		selected = profile.Profile{GitName: gitName, GitEmail: email, GitHubUser: account.Login}
		if account.ID <= 0 || selected.Validate() != nil {
			return a.fail(exitUnsafe, "invalid_github_identity", errors.New("GitHub returned an unsupported account identity"), "No keys were generated or uploaded.")
		}
		key, creationErr := keys.Create(name, a.store.Path)
		if creationErr != nil && (key.ID == "" || key.Pair.PrivatePath == "" || key.Pair.PublicPath == "" || key.Pair.Fingerprint == "") {
			return a.fail(exitUnsafe, "key_generation_failed", creationErr, "No key was uploaded. Existing profiles and keys were kept.")
		}
		selected.SSHKey, selected.SSHFingerprint, selected.ManagedKeyID = key.Pair.PrivatePath, key.Pair.Fingerprint, key.ID
		selected.GitHubAccountID = account.ID
		selected.SigningKey, selected.SigningFormat = key.Pair.PublicPath, "ssh"
		// Persist the encrypted pair's metadata before any upload. An ambiguous
		// or partial remote success can be retried with the SAME key.
		if err := a.saveLoginProfile(name, nil, selected); err != nil {
			return a.fail(exitConfig, "config_io", err, "The encrypted key and vault record were retained; no key was uploaded.")
		}
		if creationErr != nil {
			return a.fail(exitUnsafe, "key_unlock_failed", creationErr, "The pending profile and encrypted key were kept. Retry this login command; the same key will be reused. No key was uploaded.")
		}
	}
	if err := keys.Unlock(selected); err != nil {
		return a.fail(exitUnsafe, "key_unlock_failed", err, "The pending profile and encrypted key were kept. Retry this login command.")
	}
	publicKey, err := githubkeys.ReadPublicKey(selected.SSHKey+".pub", selected.SSHFingerprint)
	if err != nil {
		return a.fail(exitUnsafe, "invalid_public_key", err, "The saved profile was kept; nothing was uploaded.")
	}
	registrationCtx, registrationCancel := context.WithTimeout(ctx, 90*time.Second)
	defer registrationCancel()
	result, err := session.Register(registrationCtx, publicKey, "gitctx:"+name, true)
	printRegistrationResult(a.out, result)
	if err != nil {
		return a.fail(exitUnsafe, "key_registration_failed", err, "The saved profile, encrypted key and any successful registrations were kept. Retry the same login command; matching registrations are reused.")
	}
	previous := selected
	selected.GitHubConnected = true
	if err := a.saveLoginProfile(name, &previous, selected); err != nil {
		return a.fail(exitConfig, "config_io", err, "The remote keys were kept. Retry login to reconcile the saved state.")
	}
	a.printLoginReady(name, selected)
	return exitOK
}

func validateLoginIdentity(user, email, name string) error {
	if user != "" {
		if err := validateSetupGitHubUser(user); err != nil {
			return err
		}
	}
	if email != "" {
		if err := validateSetupGitEmail(email); err != nil {
			return err
		}
	}
	if name != "" {
		if err := validateSetupGitName(name); err != nil {
			return err
		}
	}
	return nil
}

func (a application) saveLoginProfile(name string, previous *profile.Profile, selected profile.Profile) error {
	if err := selected.Validate(); err != nil {
		return err
	}
	return a.store.WithLock(func() error {
		config, err := a.store.Load()
		if err != nil {
			return err
		}
		current, exists := config.Profiles[name]
		if (previous == nil && exists) || (previous != nil && (!exists || current != *previous)) {
			return errors.New("the account profile changed during login; it was not overwritten")
		}
		config.Profiles[name] = selected
		return a.store.Save(config)
	})
}

func (a application) printLoginVaultNotice() {
	if runtime.GOOS == "darwin" {
		fmt.Fprintln(a.out, "  macOS may show a 'security' prompt for gitctx.ssh-passphrase; gitctx will wait up to 5 minutes per key operation.")
		fmt.Fprintln(a.out, "  Enter your login keychain password (usually your Mac sign-in password), not an SSH passphrase or GitHub password, then click Allow.")
		fmt.Fprintln(a.out, "  Already-unlocked keys need no Keychain read; otherwise gitctx reuses one approved read for this operation. Never share that password here.")
	}
}

func (a application) printLoginReady(name string, selected profile.Profile) {
	fmt.Fprintf(a.out, "\nAccount %q is ready on this computer: @%s\n", name, escapeDisplayControls(selected.GitHubUser))
	fmt.Fprintf(a.out, "  Commits  %s <%s>\n", escapeDisplayControls(selected.GitName), escapeDisplayControls(selected.GitEmail))
	fmt.Fprintln(a.out, "  Key      encrypted on disk; passphrase held by the OS password vault; unlocked in this session's agent")
	fmt.Fprintln(a.out, "  Work defaults and existing repositories were not changed.")
	fmt.Fprintf(a.out, "\nInside a repository: gitctx use %s\nThen check access:    gitctx verify\n", name)
	fmt.Fprintln(a.out, "Repository access and organization SSO remain subject to GitHub permissions.")
}

func openGitHubLoginBrowser(uri string) error {
	if uri != "https://github.com/login/device" {
		return errors.New("untrusted browser destination")
	}
	var program string
	switch runtime.GOOS {
	case "darwin":
		program = "/usr/bin/open"
	case "linux":
		program = "xdg-open"
	default:
		return errors.New("open the verification URL manually")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, uri)
	command.WaitDelay = time.Second
	return command.Run()
}

func printLoginHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  gitctx login [profile] [options]

Add a reusable GitHub account from any directory (default profile: personal).
Browser authorization registers an encrypted, OS-vault-managed SSH key for
authentication and signing. No gh installation or manual public-key copy is
needed. GitHub may require a verification code and 2FA. The temporary GitHub
token is not saved. No global Git, gh login, or repository settings are changed.

Inside each repository afterward, run: gitctx use <profile>
A normal repeat login only unlocks the saved key. Use --reauthorize to repair
registration. Partial success retains the same encrypted key for safe retries.

Options:
  --github <username>  Expected browser account (optional; detected otherwise)
  --email <email>      Commit email (default: GitHub private noreply address)
  --name <name>        Commit author name (default: GitHub display name)
  --no-browser         Display the GitHub code/URL without opening a browser
  --reauthorize        Authorize again and reconcile public-key registration
  --client-id <id>     Public gitctx GitHub app Client ID (NOT a client secret)
  --config <path>      Explicit profile store
  --help              Show this help

The distributor must configure a GitHub OAuth app with Device Flow enabled.
GITCTX_GITHUB_CLIENT_ID or an embedded OAuthClientID supplies its public ID.
Requires macOS Keychain or Linux Secret Service (secret-tool), and an existing
SSH session agent. A locked/missing vault fails closed, without plaintext keys.
After an agent restart, 'gitctx use' unlocks this profile again. Windows native
login is unsupported; the existing advanced setup remains available.
JSON/piped input never opens authorization or uploads keys.`)
}
