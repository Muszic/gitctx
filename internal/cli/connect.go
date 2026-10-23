package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"gitctx/internal/gitconfig"
	"gitctx/internal/githubkeys"
	"gitctx/internal/profile"
	"gitctx/internal/sshkey"
)

type registrationSession interface {
	Login() string
	Inspect(context.Context, string, bool) (githubkeys.Result, error)
	Register(context.Context, string, string, bool) (githubkeys.Result, error)
	Close()
}

func (a application) connect(args []string) int {
	var help, jsonOutput bool
	positionals, err := parseOptions(args, nil, map[string]*bool{
		"--help": &help, "-h": &help, "--json": &jsonOutput,
	})
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Run 'gitctx connect --help' for usage.")
	}
	if help {
		printConnectHelp(a.out)
		return exitOK
	}
	if len(positionals) != 1 {
		return a.fail(exitUsage, "invalid_usage", errors.New("connect requires one saved profile name"), "Usage: gitctx connect <profile>")
	}
	if jsonOutput || !isTerminalInput(a.rawIn) {
		return a.fail(exitUsage, "interactive_terminal_required", errors.New("connect requires an interactive terminal to confirm the account and key upload"), "Run 'gitctx connect <profile>' in a terminal; JSON mode never uploads keys.")
	}
	name := positionals[0]
	if err := profile.ValidateName(name); err != nil {
		return a.fail(exitUsage, "invalid_profile", err, "")
	}
	config, err := a.store.Load()
	if err != nil {
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	selected, found := config.Profiles[name]
	if !found {
		return a.fail(exitProfile, "profile_missing", fmt.Errorf("profile %q does not exist", name), "Create it with 'gitctx setup <profile>'.")
	}
	if selected.SSHKey == "" {
		return a.fail(exitUsage, "ssh_key_required", errors.New("this profile has no SSH key to register"), "Edit it with 'gitctx setup <profile>' and choose SSH authentication.")
	}
	_, err = a.registerProfileKey(name, selected)
	if err != nil {
		return a.fail(exitUnsafe, "key_registration_failed", err, "Local profiles and keys were kept. Retry this connect command or register the public key manually; no remote keys were deleted.")
	}
	return exitOK
}

// offerKeyRegistration runs after successful local setup and outside all local
// mutation locks. Scripted setup and JSON never start a GitHub session.
func (a application) offerKeyRegistration(name string, selected profile.Profile, state gitconfig.State) (bool, error) {
	if !isTerminalInput(a.rawIn) || !githubRegistrationTarget(state, selected) {
		return false, nil
	}
	if _, err := exec.LookPath("gh"); err != nil {
		fmt.Fprintf(a.out, "\nOptional: install GitHub CLI from https://cli.github.com, then run: gitctx connect %s\n", name)
		return false, nil
	}
	return a.registerProfileKey(name, selected)
}

func githubRegistrationTarget(state gitconfig.State, selected profile.Profile) bool {
	if selected.SSHKey == "" {
		return false
	}
	if len(state.EffectivePushURLs()) == 0 {
		return selected.GitHubUser != ""
	}
	for _, remote := range state.EffectivePushURLs() {
		host, ok := gitconfig.SSHRemoteHost(remote)
		if !ok || (!strings.EqualFold(host, "github.com") && !strings.EqualFold(host, "ssh.github.com")) {
			return false
		}
	}
	return true
}

func (a application) registerProfileKey(name string, selected profile.Profile) (bool, error) {
	if selected.GitHubUser == "" {
		username, err := a.promptValidatedSetupValue("GitHub account to register this key with", "", true, validateSetupGitHubUser)
		if err != nil {
			return false, err
		}
		selected.GitHubUser = strings.TrimPrefix(strings.TrimSpace(username), "@")
	}
	pair, err := sshkey.InspectPair(selected.SSHKey)
	if err != nil {
		return false, err
	}
	if selected.SSHFingerprint != "" && selected.SSHFingerprint != pair.Fingerprint {
		return false, errors.New("the SSH key no longer matches the saved profile fingerprint")
	}
	key, err := githubkeys.ReadPublicKey(pair.PublicPath, pair.Fingerprint)
	if err != nil {
		return false, err
	}
	signing := selected.SigningKey != "" && selected.SigningFormat == "ssh"
	if signing {
		fingerprint, err := sshkey.Fingerprint(selected.SigningKey)
		if err != nil || fingerprint != pair.Fingerprint {
			return false, errors.New("automatic registration requires the profile's authentication and SSH signing keys to match; register separate signing keys manually")
		}
	}

	fmt.Fprintf(a.out, "\nConnect profile %q to GitHub @%s\n", name, escapeDisplayControls(selected.GitHubUser))
	fmt.Fprintln(a.out, "  Use the current GitHub CLI login to check the account and register this public key.")
	fmt.Fprintln(a.out, "  The login credential is held in memory for this operation and is never saved by gitctx.")
	fmt.Fprintln(a.out, "  GitHub CLI's active account and global Git settings stay unchanged.")
	confirmed, err := a.promptConfirmation("Continue with GitHub CLI")
	if err != nil || !confirmed {
		fmt.Fprintln(a.out, "Registration skipped. You can connect this saved profile later.")
		return false, nil
	}
	open := a.openRegistration
	if open == nil {
		open = func(ctx context.Context) (registrationSession, error) { return githubkeys.Open(ctx) }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	session, err := open(ctx)
	cancel()
	if err != nil {
		return false, err
	}
	defer session.Close()
	if !strings.EqualFold(session.Login(), selected.GitHubUser) {
		return false, fmt.Errorf("GitHub CLI is authenticated as @%s, but this profile expects @%s; no keys were uploaded; choose the intended gh login yourself or use manual registration", escapeDisplayControls(session.Login()), escapeDisplayControls(selected.GitHubUser))
	}
	fmt.Fprintf(a.out, "  Account     @%s (verified with GitHub)\n", escapeDisplayControls(session.Login()))
	fmt.Fprintf(a.out, "  Public key  %s\n", escapeDisplayControls(pair.PublicPath))
	fmt.Fprintf(a.out, "  Fingerprint %s\n", escapeDisplayControls(pair.Fingerprint))
	ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
	result, err := session.Inspect(ctx, key, signing)
	cancel()
	if err != nil {
		printRegistrationPermissionHint(a.out)
		return false, err
	}
	printRegistrationResult(a.out, result)
	if result.Authentication != githubkeys.Pending && result.Signing != githubkeys.Pending {
		fmt.Fprintln(a.out, "This public key is already registered for every requested purpose.")
		printAfterRegistration(a.out)
		return true, nil
	}
	fmt.Fprintln(a.out, "  Only the public key is uploaded. Existing keys are retained.")
	confirmed, err = a.promptConfirmation(fmt.Sprintf("Register this public key with GitHub @%s", session.Login()))
	if err != nil || !confirmed {
		fmt.Fprintln(a.out, "Upload cancelled. Existing registrations and local setup were kept.")
		return false, nil
	}
	ctx, cancel = context.WithTimeout(context.Background(), 90*time.Second)
	result, err = session.Register(ctx, key, "gitctx:"+name, signing)
	cancel()
	printRegistrationResult(a.out, result)
	if err != nil {
		fmt.Fprintln(a.out, "Registration is incomplete. Retry 'gitctx connect' with this profile; existing matching keys will be reused.")
		printRegistrationPermissionHint(a.out)
		return false, err
	}
	fmt.Fprintf(a.out, "Connected profile %q to GitHub @%s.\n", name, escapeDisplayControls(session.Login()))
	printAfterRegistration(a.out)
	return true, nil
}

func printRegistrationResult(w io.Writer, result githubkeys.Result) {
	fmt.Fprintf(w, "  Authentication key  %s\n", result.Authentication)
	fmt.Fprintf(w, "  Signing key         %s\n", result.Signing)
}

func printRegistrationPermissionHint(w io.Writer) {
	fmt.Fprintln(w, "If GitHub reports missing permissions, review the active account and run this yourself:")
	fmt.Fprintln(w, "  gh auth refresh --hostname github.com --scopes write:public_key,write:ssh_signing_key")
	fmt.Fprintln(w, "This opens GitHub's permission approval flow. Manual registration is also available.")
}

func printAfterRegistration(w io.Writer) {
	fmt.Fprintln(w, "\nKey registration is complete. Remote connectivity has not been checked.")
	fmt.Fprintln(w, "If the key has a passphrase, load it with ssh-add before using Git.")
	fmt.Fprintln(w, "Inside a repository using this profile, run: gitctx verify")
	fmt.Fprintln(w, "An organization may also require SSO authorization for this key.")
}

func printConnectHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  gitctx connect <profile> [--config <path>]

Register a saved profile's public SSH key with github.com using the current
GitHub CLI (gh) login. The exact GitHub username must match the intended account.
The flow confirms before reading gh's credential and again before uploading.
Authentication and same-key SSH signing registrations are checked separately;
existing matching keys are reused and partial success is kept for a safe retry.

Requires an interactive terminal. JSON and piped input never upload keys.
No account switching, browser login, permission refresh, key generation, remote
rewriting, or local Git/profile changes are performed by this command.
The temporary credential is used in memory and is not stored by gitctx.

Options:
  --config <path>  Use an explicit profile store
  --help          Show this help`)
}
