// Package cli contains the command-line interface for gitctx.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"gitctx/internal/autorules"
	"gitctx/internal/configstore"
	"gitctx/internal/gitconfig"
	"gitctx/internal/profile"
	"gitctx/internal/sshkey"
)

const (
	exitOK      = 0
	exitUnsafe  = 1
	exitUsage   = 2
	exitProfile = 3
	exitGit     = 4
	exitConfig  = 5
	statusPass  = "pass"
	statusWarn  = "warn"
	statusFail  = "fail"
	statusSkip  = "skip"
	jsonSchema  = 1
)

// Run executes gitctx and returns a process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	cleanArgs, explicitConfig, configArgErr := extractConfigOption(args)
	app := application{
		in:      bufio.NewReader(stdin),
		rawIn:   stdin,
		out:     stdout,
		err:     stderr,
		version: version,
		git:     gitconfig.NewClient(),
		json:    requestsJSON(args),
		command: commandName(args),
	}
	if configArgErr != nil {
		return app.fail(exitUsage, "invalid_usage", configArgErr, "Run 'gitctx help' for usage.")
	}
	if doesNotNeedConfig(cleanArgs) {
		return app.run(cleanArgs)
	}

	configPath := explicitConfig
	if configPath == "" {
		var err error
		configPath, err = configstore.DefaultPath()
		if err != nil {
			return app.fail(exitConfig, "config_io", err, "")
		}
	} else {
		var err error
		configPath, err = filepath.Abs(configPath)
		if err != nil {
			return app.fail(exitUsage, "invalid_usage", fmt.Errorf("resolve --config path: %w", err), "")
		}
	}
	requestedConfigPath := filepath.Clean(configPath)
	previousConfigLocation, previousLocationErr := canonicalConfigLocation(configPath)
	if previousLocationErr != nil {
		return app.fail(exitConfig, "config_io", fmt.Errorf("canonicalize config parent: %w", previousLocationErr), "")
	}
	configPath, err := canonicalConfigPath(configPath)
	if err != nil {
		return app.fail(exitConfig, "config_io", fmt.Errorf("canonicalize config path: %w", err), "")
	}
	app.store = configstore.Store{Path: configPath}
	for _, candidate := range []string{requestedConfigPath, previousConfigLocation} {
		if candidate != configPath && !slicesContain(app.legacyConfigPaths, candidate) {
			app.legacyConfigPaths = append(app.legacyConfigPaths, candidate)
		}
	}
	return app.run(cleanArgs)
}

func canonicalConfigPath(path string) (string, error) {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil {
			return "", fmt.Errorf("config path %s is an unresolved symbolic link: %w", path, resolveErr)
		}
		path = resolved
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect config path %s: %w", path, err)
	}
	return autorules.CanonicalPathAllowMissing(path)
}

func canonicalConfigLocation(path string) (string, error) {
	parent, err := autorules.CanonicalPathAllowMissing(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func slicesContain(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func doesNotNeedConfig(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "help", "-h", "--help", "version", "-v", "--version":
		return true
	case "login", "setup", "connect", "add", "list", "profiles", "use", "current", "status", "doctor", "verify", "fix", "auto":
		// These commands may need the profile store unless effective help is true.
	default:
		// Unknown commands can report usage without resolving user configuration.
		return true
	}
	command := commandName(args)
	helpRequested := false
	invalidHelp := false
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			break
		}
		name, inline, hasInline := strings.Cut(arg, "=")
		if !hasInline && optionConsumesValue(command, name) {
			index++
			continue
		}
		if name == "--help" || name == "-h" {
			if !hasInline || inline == "true" {
				helpRequested = true
			} else if inline == "false" {
				helpRequested = false
			} else {
				// Parsing will reject this value before accessing configuration.
				invalidHelp = true
			}
		}
	}
	return invalidHelp || helpRequested
}

type application struct {
	in                *bufio.Reader
	rawIn             io.Reader
	out               io.Writer
	err               io.Writer
	version           string
	store             configstore.Store
	git               *gitconfig.Client
	legacyConfigPaths []string
	json              bool
	command           string
	openRegistration  func(context.Context) (registrationSession, error)
	authorizeLogin    func(context.Context, string, func(string, string)) (loginSession, error)
	openLoginBrowser  func(string) error
	loginKeys         loginKeyManager
	loginTerminal     func() bool
}

type envelope struct {
	SchemaVersion int       `json:"schema_version"`
	Command       string    `json:"command"`
	OK            bool      `json:"ok"`
	Data          any       `json:"data,omitempty"`
	Warnings      []notice  `json:"warnings,omitempty"`
	Error         *apiError `json:"error,omitempty"`
}

type notice struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

func (a application) run(args []string) int {
	if len(args) == 0 {
		a.command = "current"
		return a.current(nil)
	}

	a.command = args[0]
	switch args[0] {
	case "help", "-h", "--help":
		if len(args) == 2 && args[1] != "help" && args[1] != "-h" && args[1] != "--help" {
			return a.run([]string{args[1], "--help"})
		}
		if len(args) > 2 {
			return a.fail(exitUsage, "invalid_usage", errors.New("help accepts at most one command name"), "Usage: gitctx help [command]")
		}
		printHelp(a.out)
		return exitOK
	case "version", "-v", "--version":
		fmt.Fprintf(a.out, "gitctx %s\n", a.version)
		return exitOK
	case "add":
		return a.add(args[1:])
	case "setup":
		return a.setup(args[1:])
	case "connect":
		return a.connect(args[1:])
	case "login":
		return a.login(args[1:])
	case "list", "profiles":
		a.command = "list"
		return a.list(args[1:])
	case "use":
		return a.use(args[1:])
	case "current", "status":
		a.command = "current"
		return a.current(args[1:])
	case "doctor":
		return a.doctor(args[1:])
	case "verify":
		return a.verify(args[1:])
	case "fix":
		return a.fix(args[1:])
	case "auto":
		return a.auto(args[1:])
	default:
		return a.fail(exitUsage, "invalid_usage", fmt.Errorf("unknown command %q", args[0]), "Run 'gitctx help' for usage.")
	}
}

type addOptions struct {
	profile        string
	gitName        string
	email          string
	github         string
	sshKey         string
	signingKey     string
	signingFormat  string
	disableSigning bool
	force          bool
	json           bool
	help           bool
}

func (a application) add(args []string) int {
	options, err := parseAdd(args)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Run 'gitctx add --help' for usage.")
	}
	if options.help {
		printAddHelp(a.out)
		return exitOK
	}
	if options.profile == "" {
		return a.fail(exitUsage, "invalid_usage", fmt.Errorf("add requires a profile name"), "Usage: gitctx add <profile> [options]")
	}
	if err := profile.ValidateName(options.profile); err != nil {
		return a.fail(exitUsage, "invalid_profile", err, "")
	}

	if options.json && (options.gitName == "" || options.email == "") {
		return a.fail(exitUsage, "invalid_usage", fmt.Errorf("--json requires --name and --email so output remains machine-readable"), "")
	}
	if options.gitName == "" {
		options.gitName, err = a.prompt("Git name")
		if err != nil {
			return a.fail(exitUsage, "invalid_profile", err, "")
		}
	}
	if options.email == "" {
		options.email, err = a.prompt("Git email")
		if err != nil {
			return a.fail(exitUsage, "invalid_profile", err, "")
		}
	}

	selected := profile.Profile{
		GitName:        options.gitName,
		GitEmail:       options.email,
		GitHubUser:     options.github,
		SSHKey:         options.sshKey,
		SigningKey:     options.signingKey,
		SigningFormat:  options.signingFormat,
		DisableSigning: options.disableSigning,
	}.Normalize()
	if selected.SSHKey != "" {
		selected.SSHKey, err = gitconfig.ValidateSSHPrivateKey(selected.SSHKey)
		if err != nil {
			return a.fail(exitUsage, "invalid_ssh_key", err, "")
		}
	}
	if err := selected.Validate(); err != nil {
		return a.fail(exitUsage, "invalid_profile", err, "")
	}

	var config configstore.Config
	var existed bool
	var conflict bool
	err = a.store.WithLock(func() error {
		var loadErr error
		config, loadErr = a.store.Load()
		if loadErr != nil {
			return loadErr
		}
		_, existed = config.Profiles[options.profile]
		if existed && !options.force {
			conflict = true
			return nil
		}
		previous := cloneConfig(config)
		config.Profiles[options.profile] = selected
		if saveErr := a.store.Save(config); saveErr != nil {
			return saveErr
		}
		if len(config.Rules) > 0 {
			return a.syncRulesWithRollback(previous, config)
		}
		return nil
	})
	if err != nil {
		return a.fail(exitConfig, "config_io", err, "")
	}
	if conflict {
		return a.fail(exitProfile, "profile_exists", fmt.Errorf("profile %q already exists", options.profile), "Use --force to replace it.")
	}

	if options.json {
		return a.succeed(struct {
			Name       string          `json:"name"`
			Profile    profile.Profile `json:"profile"`
			Replaced   bool            `json:"replaced"`
			ConfigPath string          `json:"config_path"`
		}{options.profile, selected, existed, a.store.Path}, sshKeyPlatformWarnings(selected))
	}

	verb := "Created"
	if existed {
		verb = "Updated"
	}
	fmt.Fprintf(a.out, "%s profile %q.\n", verb, options.profile)
	fmt.Fprintf(a.out, "  Git author  %s <%s>\n", escapeDisplayControls(selected.GitName), escapeDisplayControls(selected.GitEmail))
	if selected.GitHubUser != "" {
		fmt.Fprintf(a.out, "  GitHub      @%s\n", escapeDisplayControls(selected.GitHubUser))
	}
	if selected.SSHKey != "" {
		fmt.Fprintf(a.out, "  Auth        SSH key %s\n", escapeDisplayControls(selected.SSHKey))
	} else {
		fmt.Fprintln(a.out, "  Auth        external (not managed by gitctx)")
	}
	if selected.DisableSigning {
		fmt.Fprintln(a.out, "  Signing     guarded against automatic signing and bare -S when applied")
	} else if selected.SigningKey != "" {
		fmt.Fprintf(a.out, "  Signing     %s", escapeDisplayControls(selected.SigningKey))
		if selected.SigningFormat != "" {
			fmt.Fprintf(a.out, " (%s)", escapeDisplayControls(selected.SigningFormat))
		}
		fmt.Fprintln(a.out)
	}
	for _, warning := range sshKeyPlatformWarnings(selected) {
		fmt.Fprintf(a.out, "  Warning     %s\n", escapeDisplayControls(warning.Message))
	}
	fmt.Fprintln(a.out, "\nApply it inside a repository with: gitctx use "+options.profile)
	return exitOK
}

type namedProfile struct {
	Name string `json:"name"`
	profile.Profile
}

func (a application) list(args []string) int {
	options, err := parseSimple(args)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Usage: gitctx list [--json]")
	}
	if options.help {
		fmt.Fprintln(a.out, "Usage: gitctx list [--json] [--config <path>]")
		return exitOK
	}

	config, err := a.store.Load()
	if err != nil {
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	names := make([]string, 0, len(config.Profiles))
	for name := range config.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	profiles := make([]namedProfile, 0, len(names))
	for _, name := range names {
		profiles = append(profiles, namedProfile{Name: name, Profile: config.Profiles[name]})
	}
	if options.json {
		return a.succeed(struct {
			Profiles   []namedProfile `json:"profiles"`
			ConfigPath string         `json:"config_path"`
		}{profiles, a.store.Path}, nil)
	}
	if len(profiles) == 0 {
		fmt.Fprintln(a.out, "No profiles yet. Add an account once with browser login:")
		fmt.Fprintln(a.out, "  gitctx login personal")
		fmt.Fprintln(a.out, "Or use advanced setup inside a repository:")
		fmt.Fprintln(a.out, "  gitctx setup personal")
		return exitOK
	}

	table := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "PROFILE\tGIT AUTHOR\tGITHUB\tAUTH")
	for _, item := range profiles {
		github := "-"
		if item.GitHubUser != "" {
			github = "@" + item.GitHubUser
		}
		auth := "external"
		if item.SSHKey != "" {
			auth = "SSH"
		}
		fmt.Fprintf(table, "%s\t%s <%s>\t%s\t%s\n", escapeDisplayControls(item.Name), escapeDisplayControls(item.GitName), escapeDisplayControls(item.GitEmail), escapeDisplayControls(github), escapeDisplayControls(auth))
	}
	table.Flush()
	return exitOK
}

func (a application) use(args []string) int {
	options, err := parseRepoCommand(args, true, false)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Usage: gitctx use <profile> [--repo <path>] [--json]")
	}
	if options.help {
		fmt.Fprintln(a.out, "Usage: gitctx use <profile> [--repo <path>] [--json] [--config <path>]")
		return exitOK
	}
	if options.profile == "" {
		return a.fail(exitUsage, "invalid_usage", fmt.Errorf("use requires a profile name"), "Usage: gitctx use <profile> [--repo <path>]")
	}
	// Unlock a native key before taking the shared store lock. Vault permission
	// prompts must not hold a mutation lock or switch another agent/account.
	before, loadErr := a.store.Load()
	if loadErr != nil {
		return a.fail(exitConfig, "config_invalid", loadErr, "")
	}
	beforeProfile := before.Profiles[options.profile]
	if beforeProfile.ManagedKeyID != "" {
		if !beforeProfile.GitHubConnected {
			return a.fail(exitUnsafe, "login_incomplete", errors.New("this account's key registration is incomplete"), "Run 'gitctx login "+options.profile+"' again; the same key will be reused.")
		}
		if err := a.keyManager().Unlock(beforeProfile); err != nil {
			return a.fail(exitUnsafe, "key_unlock_failed", err, "No repository settings were changed.")
		}
	}

	var config configstore.Config
	var selected profile.Profile
	var state gitconfig.State
	var profileMissing bool
	var gitOperationErr error
	err = a.store.WithLock(func() error {
		var loadErr error
		config, loadErr = a.store.Load()
		if loadErr != nil {
			return loadErr
		}
		var exists bool
		selected, exists = config.Profiles[options.profile]
		if !exists {
			profileMissing = true
			return nil
		}
		if selected.ManagedKeyID != "" && selected != beforeProfile {
			return errors.New("the managed profile changed while its key was unlocking; retry use")
		}
		gitOperationErr = a.git.Apply(options.repo, options.profile, selected)
		if gitOperationErr != nil {
			return gitOperationErr
		}
		state, gitOperationErr = a.git.Inspect(options.repo)
		return gitOperationErr
	})
	if err != nil {
		if gitOperationErr != nil {
			return a.fail(exitGit, "git_failed", err, "")
		}
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	if profileMissing {
		return a.fail(exitProfile, "profile_not_found", fmt.Errorf("profile %q does not exist", options.profile), "Run 'gitctx list' to see profiles.")
	}
	state = classifyProfileSource(state, config, a.store.Path)
	current := buildCurrent(state, config)
	warnings := currentWarnings(current)
	if options.json {
		if code := a.succeed(current, warnings); code != exitOK {
			return code
		}
		if current.Status == "mismatch" {
			return exitUnsafe
		}
		return exitOK
	}

	if current.Status == "mismatch" {
		fmt.Fprintf(a.out, "Applied profile %q to %s, but verification found a mismatch.\n", options.profile, escapeDisplayControls(state.Repository))
	} else {
		fmt.Fprintf(a.out, "Applied profile %q to %s.\n", options.profile, escapeDisplayControls(state.Repository))
	}
	fmt.Fprintf(a.out, "  Git author  %s <%s>\n", escapeDisplayControls(state.GitName), escapeDisplayControls(state.GitEmail))
	fmt.Fprintf(a.out, "  Auth        %s\n", current.Authentication)
	if strings.HasPrefix(current.Authentication, "repository-scoped SSH") {
		fmt.Fprintf(a.out, "  SSH key     %s\n", escapeDisplayControls(selected.SSHKey))
	}
	printAppliedSigning(a.out, selected)
	fmt.Fprintln(a.out, "  Scope       this repository only")
	for _, warning := range warnings {
		fmt.Fprintf(a.out, "  Warning     %s\n", escapeDisplayControls(warning.Message))
	}
	if current.Status == "mismatch" {
		return exitUnsafe
	}
	return exitOK
}

func (a application) current(args []string) int {
	options, err := parseRepoCommand(args, false, false)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Usage: gitctx current [--repo <path>] [--json]")
	}
	if options.help {
		fmt.Fprintln(a.out, "Usage: gitctx current [--repo <path>] [--json] [--config <path>]")
		return exitOK
	}

	config, err := a.store.Load()
	if err != nil {
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	state, err := a.git.Inspect(options.repo)
	if err != nil {
		return a.fail(exitGit, "not_git_repository", friendlyRepositoryError(err), "Change into a Git repository, or pass --repo <path>.")
	}
	state = classifyProfileSource(state, config, a.store.Path)
	current := buildCurrent(state, config)
	warnings := currentWarnings(current)
	if options.json {
		return a.succeed(current, warnings)
	}

	fmt.Fprintf(a.out, "Repository   %s\n", escapeDisplayControls(current.Repository))
	if current.Profile == "" {
		fmt.Fprintln(a.out, "Profile      unmanaged")
	} else if current.ProfileSource == "auto" {
		fmt.Fprintf(a.out, "Profile      %s (automatic identity)\n", escapeDisplayControls(current.Profile))
	} else if current.ProfileSource == "auto_missing" {
		fmt.Fprintf(a.out, "Profile      %s (automatic rule inactive)\n", escapeDisplayControls(current.Profile))
	} else if current.ProfileSource != "local" {
		fmt.Fprintf(a.out, "Profile      %s (unverified source)\n", escapeDisplayControls(current.Profile))
	} else {
		fmt.Fprintf(a.out, "Profile      %s\n", escapeDisplayControls(current.Profile))
	}
	if current.IdentityConfigured {
		fmt.Fprintf(a.out, "Git author   %s <%s>\n", escapeDisplayControls(valueOrDash(current.GitName)), escapeDisplayControls(valueOrDash(current.GitEmail)))
	} else {
		fmt.Fprintln(a.out, "Git author   not explicitly configured (Git may synthesize a machine-based fallback)")
	}
	if current.CommitterEmail != "" && (current.CommitterName != current.GitName || current.CommitterEmail != current.GitEmail) {
		fmt.Fprintf(a.out, "Committer    %s <%s>\n", escapeDisplayControls(current.CommitterName), escapeDisplayControls(current.CommitterEmail))
	}
	if current.GitHubUser != "" {
		fmt.Fprintf(a.out, "GitHub       @%s\n", escapeDisplayControls(current.GitHubUser))
	}
	fmt.Fprintf(a.out, "Auth         %s\n", current.Authentication)
	if current.SigningDisabled && current.SigningManaged {
		fmt.Fprintln(a.out, "Signing      blocked by profile (automatic signing and bare -S)")
	} else if current.SigningKey != "" {
		managed := "inherited"
		if current.SigningManaged {
			managed = "managed by profile"
		} else if current.SigningManagementMismatch {
			managed = "managed state does not match profile"
		}
		format := ""
		if current.SigningFormat != "" {
			format = ", " + escapeDisplayControls(current.SigningFormat)
		}
		fmt.Fprintf(a.out, "Signing      %s (%s%s)\n", escapeDisplayControls(current.SigningKey), managed, format)
	} else if current.SigningManagementMismatch {
		fmt.Fprintln(a.out, "Signing      configuration mismatch (run 'gitctx doctor')")
	}
	if current.Origin != "" {
		fmt.Fprintf(a.out, "Origin       %s\n", current.Origin)
	}
	if current.PushRemote != "" && current.PushRemote != "origin" {
		fmt.Fprintf(a.out, "Push remote  %s\n", current.PushRemote)
	}
	if len(current.PushURLs) > 1 {
		fmt.Fprintf(a.out, "Push URLs    %s\n", strings.Join(current.PushURLs, ", "))
	} else if current.PushURL != "" && current.PushURL != current.Origin {
		fmt.Fprintf(a.out, "Push URL     %s\n", current.PushURL)
	}
	fmt.Fprintf(a.out, "Status       %s\n", current.Status)
	for _, warning := range warnings {
		fmt.Fprintf(a.out, "Warning      %s\n", escapeDisplayControls(warning.Message))
	}
	return exitOK
}

func (a application) doctor(args []string) int {
	options, err := parseRepoCommand(args, false, true)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Usage: gitctx doctor [--repo <path>] [--strict] [--json]")
	}
	if options.help {
		fmt.Fprintln(a.out, "Usage: gitctx doctor [--repo <path>] [--strict] [--json] [--config <path>]")
		return exitOK
	}

	config, err := a.store.Load()
	if err != nil {
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	state, err := a.git.Inspect(options.repo)
	if err != nil {
		return a.fail(exitGit, "not_git_repository", friendlyRepositoryError(err), "Change into a Git repository, or pass --repo <path>.")
	}
	state = classifyProfileSource(state, config, a.store.Path)
	diagnosis := diagnose(state, config)
	if options.json {
		if code := a.succeed(diagnosis, nil); code != exitOK {
			return code
		}
	} else {
		fmt.Fprintf(a.out, "Repository  %s\n", escapeDisplayControls(diagnosis.Repository))
		profileLabel := valueOr(diagnosis.Profile, "unmanaged")
		if diagnosis.ProfileSource == "auto" {
			profileLabel += " (automatic identity)"
		} else if diagnosis.ProfileSource == "auto_missing" {
			profileLabel += " (automatic rule inactive)"
		}
		fmt.Fprintf(a.out, "Profile     %s\n\n", escapeDisplayControls(profileLabel))
		for _, item := range diagnosis.Checks {
			fmt.Fprintf(a.out, "%-4s  %-17s %s\n", checkLabel(item.Status), escapeDisplayControls(item.Name), escapeDisplayControls(item.Message))
		}
		fmt.Fprintf(a.out, "\nResult: %s\n", diagnosis.Status)
	}
	if diagnosis.Status == "error" || (options.strict && diagnosis.Status == "warning") {
		return exitUnsafe
	}
	return exitOK
}

func (a application) fix(args []string) int {
	options, err := parseRepoCommand(args, false, false)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Usage: gitctx fix [--repo <path>] [--json]")
	}
	if options.help {
		fmt.Fprintln(a.out, "Usage: gitctx fix [--repo <path>] [--json] [--config <path>]")
		return exitOK
	}
	var config configstore.Config
	var state gitconfig.State
	var selected profile.Profile
	var issue string
	var gitOperationErr error
	err = a.store.WithLock(func() error {
		var loadErr error
		config, loadErr = a.store.Load()
		if loadErr != nil {
			return loadErr
		}
		state, gitOperationErr = a.git.Inspect(options.repo)
		if gitOperationErr != nil {
			return gitOperationErr
		}
		state = classifyProfileSource(state, config, a.store.Path)
		if state.Profile == "" {
			issue = "unmanaged"
			return nil
		}
		if state.ProfileSource == "auto" || state.ProfileSource == "auto_missing" {
			issue = "auto"
			return nil
		}
		if state.ProfileSource != "local" {
			issue = "untrusted"
			return nil
		}
		var exists bool
		selected, exists = config.Profiles[state.Profile]
		if !exists {
			issue = "missing"
			return nil
		}
		gitOperationErr = a.git.Apply(options.repo, state.Profile, selected)
		if gitOperationErr != nil {
			return gitOperationErr
		}
		state, gitOperationErr = a.git.Inspect(options.repo)
		if gitOperationErr == nil {
			state = classifyProfileSource(state, config, a.store.Path)
		}
		return gitOperationErr
	})
	if err != nil {
		if gitOperationErr != nil {
			return a.fail(exitGit, "git_failed", err, "")
		}
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	switch issue {
	case "unmanaged":
		return a.fail(exitProfile, "profile_not_found", fmt.Errorf("this repository has no selected profile"), "Run 'gitctx use <profile>' first.")
	case "auto":
		return a.fail(exitProfile, "auto_profile_not_pinned", fmt.Errorf("profile %q is selected by an automatic directory rule", state.Profile), "Run 'gitctx auto sync' to repair automatic rules, or 'gitctx use "+state.Profile+"' to pin and fully apply it to this repository.")
	case "untrusted":
		return a.fail(exitProfile, "profile_source_untrusted", fmt.Errorf("profile %q does not come from repository-local config or a matching managed rule", state.Profile), "Run 'gitctx use "+state.Profile+"' to apply it explicitly.")
	case "missing":
		return a.fail(exitProfile, "profile_not_found", fmt.Errorf("profile %q is missing from the profile store", state.Profile), "Run 'gitctx list' to see profiles.")
	}
	current := buildCurrent(state, config)
	warnings := currentWarnings(current)
	if options.json {
		if code := a.succeed(current, warnings); code != exitOK {
			return code
		}
		if current.Status == "mismatch" {
			return exitUnsafe
		}
		return exitOK
	}
	fmt.Fprintf(a.out, "Re-applied profile %q to %s.\n", state.Profile, escapeDisplayControls(state.Repository))
	fmt.Fprintf(a.out, "  Git author  %s <%s>\n", escapeDisplayControls(state.GitName), escapeDisplayControls(state.GitEmail))
	fmt.Fprintf(a.out, "  Auth        %s\n", current.Authentication)
	printAppliedSigning(a.out, selected)
	fmt.Fprintf(a.out, "  Status      %s\n", current.Status)
	for _, warning := range warnings {
		fmt.Fprintf(a.out, "  Warning     %s\n", escapeDisplayControls(warning.Message))
	}
	if current.Status == "mismatch" {
		return exitUnsafe
	}
	return exitOK
}

func printAppliedSigning(w io.Writer, selected profile.Profile) {
	if selected.DisableSigning {
		fmt.Fprintln(w, "  Signing     guarded against automatic signing and bare -S")
	} else if selected.SigningKey != "" {
		fmt.Fprintf(w, "  Signing     %s", escapeDisplayControls(selected.SigningKey))
		if selected.SigningFormat != "" {
			fmt.Fprintf(w, " (%s)", escapeDisplayControls(selected.SigningFormat))
		}
		fmt.Fprintln(w)
	}
}

type autoOptions struct {
	action  string
	path    string
	profile string
	force   bool
	json    bool
	help    bool
}

type autoRule struct {
	Directory string `json:"directory"`
	Profile   string `json:"profile"`
}

func (a application) auto(args []string) int {
	options, err := parseAuto(args)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Run 'gitctx auto --help' for usage.")
	}
	if options.help || options.action == "" {
		printAutoHelp(a.out)
		return exitOK
	}

	switch options.action {
	case "list":
		config, err := a.store.Load()
		if err != nil {
			return a.fail(exitConfig, "config_invalid", err, "")
		}
		return a.autoList(options, config)
	case "add":
		return a.autoAdd(options)
	case "remove":
		return a.autoRemove(options)
	case "sync":
		return a.autoSync(options)
	default:
		return a.fail(exitUsage, "invalid_usage", fmt.Errorf("unknown auto action %q", options.action), "Run 'gitctx auto --help' for usage.")
	}
}

func (a application) autoList(options autoOptions, config configstore.Config) int {
	paths := make([]string, 0, len(config.Rules))
	for path := range config.Rules {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	rules := make([]autoRule, 0, len(paths))
	for _, path := range paths {
		rules = append(rules, autoRule{Directory: path, Profile: config.Rules[path]})
	}
	manager := a.autoManager()
	manifestPath, stateErr := manager.ActiveManifestPath()
	var warnings []notice
	if stateErr != nil {
		warnings = append(warnings, notice{Code: "auto_state_unavailable", Message: stateErr.Error()})
	} else {
		hasRules := len(config.Rules) > 0
		active := manifestPath != ""
		if hasRules != active || (hasRules && !manager.ManifestMatchesConfig(config, manifestPath)) {
			warnings = append(warnings, notice{
				Code:    "auto_state_out_of_sync",
				Message: "Saved automatic rules do not match Git's active automatic configuration; run 'gitctx auto sync'.",
			})
		}
	}
	if options.json {
		return a.succeed(struct {
			Rules        []autoRule `json:"rules"`
			ManifestPath string     `json:"manifest_path"`
		}{rules, manifestPath}, warnings)
	}
	if len(rules) == 0 {
		fmt.Fprintln(a.out, "No automatic directory rules.")
		for _, warning := range warnings {
			fmt.Fprintf(a.out, "Warning: %s\n", escapeDisplayControls(warning.Message))
		}
		return exitOK
	}
	table := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "DIRECTORY\tPROFILE")
	for _, rule := range rules {
		fmt.Fprintf(table, "%s\t%s\n", escapeDisplayControls(rule.Directory), escapeDisplayControls(rule.Profile))
	}
	table.Flush()
	for _, warning := range warnings {
		fmt.Fprintf(a.out, "Warning: %s\n", escapeDisplayControls(warning.Message))
	}
	return exitOK
}

func (a application) autoAdd(options autoOptions) int {
	if options.path == "" || options.profile == "" {
		return a.fail(exitUsage, "invalid_usage", fmt.Errorf("auto add requires a directory and profile"), "Usage: gitctx auto add <directory> <profile>")
	}
	directory, err := canonicalDirectory(options.path)
	if err != nil {
		return a.fail(exitUsage, "invalid_directory", err, "")
	}

	var config configstore.Config
	var selected profile.Profile
	var profileMissing bool
	var existingProfile string
	var conflict bool
	err = a.store.WithLock(func() error {
		var loadErr error
		config, loadErr = a.store.Load()
		if loadErr != nil {
			return loadErr
		}
		var exists bool
		selected, exists = config.Profiles[options.profile]
		if !exists {
			profileMissing = true
			return nil
		}
		matchingPaths := matchingRulePaths(config, directory)
		for _, matchingPath := range matchingPaths {
			current := config.Rules[matchingPath]
			if current != options.profile && !options.force {
				conflict = true
				existingProfile = current
				return nil
			}
		}
		previous := cloneConfig(config)
		for _, matchingPath := range matchingPaths {
			delete(config.Rules, matchingPath)
		}
		config.Rules[directory] = options.profile
		if saveErr := a.store.Save(config); saveErr != nil {
			return saveErr
		}
		return a.syncRulesWithRollback(previous, config)
	})
	if err != nil {
		return a.fail(exitConfig, "auto_sync_failed", err, "")
	}
	if profileMissing {
		return a.fail(exitProfile, "profile_not_found", fmt.Errorf("profile %q does not exist", options.profile), "Run 'gitctx list' to see profiles.")
	}
	if conflict {
		return a.fail(exitProfile, "rule_exists", fmt.Errorf("%s is already assigned to profile %q", directory, existingProfile), "Use --force to replace the rule.")
	}

	data := autoRule{Directory: directory, Profile: options.profile}
	warnings := autoRuleWarnings(options.profile, selected)
	if options.json {
		return a.succeed(data, warnings)
	}
	fmt.Fprintf(a.out, "Assigned %s to profile %q.\n", escapeDisplayControls(directory), options.profile)
	fmt.Fprintln(a.out, "Git will apply this commit identity automatically to repositories under that directory.")
	fmt.Fprintln(a.out, "Global user.name and user.email were not changed.")
	for _, warning := range warnings {
		fmt.Fprintf(a.out, "Warning: %s\n", escapeDisplayControls(warning.Message))
	}
	return exitOK
}

func (a application) autoRemove(options autoOptions) int {
	if options.path == "" {
		return a.fail(exitUsage, "invalid_usage", fmt.Errorf("auto remove requires a directory"), "Usage: gitctx auto remove <directory>")
	}
	directory, err := canonicalRuleDirectory(options.path)
	if err != nil {
		return a.fail(exitUsage, "invalid_directory", err, "")
	}
	var profileName string
	var found bool
	err = a.store.WithLock(func() error {
		config, loadErr := a.store.Load()
		if loadErr != nil {
			return loadErr
		}
		matchingPaths := matchingRulePaths(config, directory)
		if len(matchingPaths) == 0 {
			return nil
		}
		found = true
		profileName = config.Rules[matchingPaths[0]]
		previous := cloneConfig(config)
		for _, matchingPath := range matchingPaths {
			delete(config.Rules, matchingPath)
		}
		if saveErr := a.store.Save(config); saveErr != nil {
			return saveErr
		}
		return a.syncRulesWithRollback(previous, config)
	})
	if err != nil {
		return a.fail(exitConfig, "auto_sync_failed", err, "")
	}
	if !found {
		return a.fail(exitProfile, "rule_not_found", fmt.Errorf("no automatic rule exists for %s", directory), "Run 'gitctx auto list' to see rules.")
	}

	data := autoRule{Directory: directory, Profile: profileName}
	if options.json {
		return a.succeed(data, nil)
	}
	fmt.Fprintf(a.out, "Removed automatic rule for %s (profile %q).\n", escapeDisplayControls(directory), profileName)
	return exitOK
}

func (a application) autoSync(options autoOptions) int {
	var config configstore.Config
	var manifestPath string
	err := a.store.WithLock(func() error {
		var loadErr error
		config, loadErr = a.store.Load()
		if loadErr != nil {
			return loadErr
		}
		manager := a.autoManager()
		var syncErr error
		manifestPath, syncErr = manager.Sync(config)
		return syncErr
	})
	if err != nil {
		return a.fail(exitConfig, "auto_sync_failed", err, "")
	}
	data := struct {
		RuleCount    int    `json:"rule_count"`
		ManifestPath string `json:"manifest_path"`
	}{len(config.Rules), manifestPath}
	if options.json {
		return a.succeed(data, nil)
	}
	fmt.Fprintf(a.out, "Synchronized %d automatic rule(s).\n", data.RuleCount)
	return exitOK
}

func (a application) syncRulesWithRollback(previous, current configstore.Config) error {
	manager := a.autoManager()
	if _, err := manager.Sync(current); err == nil {
		return nil
	} else {
		originalErr := err
		var rollbackErrors []error
		if restoreErr := a.store.Save(previous); restoreErr != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore profile store: %w", restoreErr))
		}
		if _, restoreErr := manager.Sync(previous); restoreErr != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore automatic rules: %w", restoreErr))
		}
		if len(rollbackErrors) > 0 {
			return errors.Join(append([]error{originalErr}, rollbackErrors...)...)
		}
		return originalErr
	}
}

func (a application) autoManager() *autorules.Manager {
	manager := autorules.NewManager(a.store.Path)
	manager.LegacyConfigPaths = append([]string(nil), a.legacyConfigPaths...)
	manager.Env = a.git.Env
	return manager
}

func matchingRulePaths(config configstore.Config, directory string) []string {
	var matches []string
	for savedPath := range config.Rules {
		if filepath.Clean(savedPath) == directory {
			matches = append(matches, savedPath)
			continue
		}
		canonical, err := autorules.CanonicalPathAllowMissing(savedPath)
		if err == nil && filepath.Clean(canonical) == directory {
			matches = append(matches, savedPath)
		}
	}
	sort.Strings(matches)
	return matches
}

func cloneConfig(config configstore.Config) configstore.Config {
	clone := configstore.Config{
		SchemaVersion: config.SchemaVersion,
		Profiles:      make(map[string]profile.Profile, len(config.Profiles)),
		Rules:         make(map[string]string, len(config.Rules)),
	}
	for name, saved := range config.Profiles {
		clone.Profiles[name] = saved
	}
	for path, profileName := range config.Rules {
		clone.Rules[path] = profileName
	}
	return clone
}

func canonicalDirectory(path string) (string, error) {
	resolved, err := gitconfig.ResolvePath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("directory %s: %w", resolved, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", resolved)
	}
	canonical, err := autorules.CanonicalPathAllowMissing(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve directory %s: %w", resolved, err)
	}
	canonical = filepath.Clean(canonical)
	if err := configstore.ValidateRulePath(canonical); err != nil {
		return "", fmt.Errorf("automatic rule directory: %w", err)
	}
	return canonical, nil
}

// canonicalRuleDirectory also accepts a directory that has since been deleted,
// so users can still remove its saved automatic rule.
func canonicalRuleDirectory(path string) (string, error) {
	resolved, err := gitconfig.ResolvePath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if errors.Is(err, os.ErrNotExist) {
		return canonicalMissingPath(resolved)
	}
	if err != nil {
		return "", fmt.Errorf("directory %s: %w", resolved, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", resolved)
	}
	canonical, err := autorules.CanonicalPathAllowMissing(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve directory %s: %w", resolved, err)
	}
	return filepath.Clean(canonical), nil
}

func canonicalMissingPath(path string) (string, error) {
	canonical, err := autorules.CanonicalPathAllowMissing(path)
	if err != nil {
		return "", fmt.Errorf("resolve directory %s: %w", path, err)
	}
	return canonical, nil
}

func autoRuleWarnings(name string, selected profile.Profile) []notice {
	warnings := []notice{{
		Code:    "auto_repository_topology_limited",
		Message: "Automatic rules are intended for conventional repositories with their own .git directory. Git matches metadata paths, so a separately stored directory named .git can match even when its working tree is elsewhere; verify unusual repository layouts with 'gitctx doctor'.",
	}}
	if selected.SSHKey != "" {
		warnings = append(warnings, notice{
			Code:    "auto_identity_only_ssh",
			Message: fmt.Sprintf("Automatic rules select identity only; run 'gitctx use %s' in a repository to apply its SSH key.", name),
		})
	}
	if selected.SigningKey != "" || selected.DisableSigning {
		policy := "signing policy"
		if selected.DisableSigning {
			policy = "repository-local signing guard"
		}
		warnings = append(warnings, notice{
			Code:    "auto_identity_only_signing",
			Message: fmt.Sprintf("Automatic rules select identity only; run 'gitctx use %s' in a repository to apply its %s.", name, policy),
		})
	}
	return warnings
}

type currentOutput struct {
	Repository                  string   `json:"repository"`
	MultipleWorktrees           bool     `json:"multiple_worktrees,omitempty"`
	Profile                     string   `json:"profile,omitempty"`
	ProfileSource               string   `json:"profile_source,omitempty"`
	ProfileOrigin               string   `json:"profile_origin,omitempty"`
	GitName                     string   `json:"git_name,omitempty"`
	GitEmail                    string   `json:"git_email,omitempty"`
	IdentityConfigured          bool     `json:"identity_configured"`
	CommitterName               string   `json:"committer_name,omitempty"`
	CommitterEmail              string   `json:"committer_email,omitempty"`
	GitHubUser                  string   `json:"github_user,omitempty"`
	Authentication              string   `json:"authentication"`
	SSHKeyValid                 bool     `json:"ssh_key_valid,omitempty"`
	SSHFingerprintMatch         bool     `json:"ssh_fingerprint_match,omitempty"`
	SSHKeyMismatch              bool     `json:"ssh_key_mismatch,omitempty"`
	SigningKey                  string   `json:"signing_key,omitempty"`
	SigningFormat               string   `json:"signing_format,omitempty"`
	SigningDisabled             bool     `json:"signing_disabled,omitempty"`
	CommitSigningEnabled        bool     `json:"commit_signing_enabled"`
	CommitSigningManaged        bool     `json:"commit_signing_managed,omitempty"`
	SigningManaged              bool     `json:"signing_managed"`
	SigningManagementPresent    bool     `json:"signing_management_present,omitempty"`
	SigningManagementMismatch   bool     `json:"signing_management_mismatch,omitempty"`
	SigningManagementStale      bool     `json:"signing_management_stale,omitempty"`
	SSHSigningProgramManaged    bool     `json:"ssh_signing_program_managed,omitempty"`
	SSHSigningProgramExecutable bool     `json:"ssh_signing_program_executable,omitempty"`
	SSHSigningProgramIntegrity  bool     `json:"ssh_signing_program_integrity,omitempty"`
	SSHSigningProgramMismatch   bool     `json:"ssh_signing_program_mismatch,omitempty"`
	SigningPending              bool     `json:"signing_requires_explicit_use"`
	SSHManagementPresent        bool     `json:"ssh_management_present,omitempty"`
	SSHManagementStale          bool     `json:"ssh_management_stale,omitempty"`
	Origin                      string   `json:"origin,omitempty"`
	PushRemote                  string   `json:"push_remote,omitempty"`
	PushRemoteExplicit          bool     `json:"push_remote_explicit,omitempty"`
	PushURL                     string   `json:"push_url,omitempty"`
	PushURLs                    []string `json:"push_urls,omitempty"`
	Status                      string   `json:"status"`
}

func buildCurrent(state gitconfig.State, config configstore.Config) currentOutput {
	result := currentOutput{
		Repository:                  state.Repository,
		MultipleWorktrees:           state.MultipleWorktrees,
		Profile:                     state.Profile,
		ProfileSource:               state.ProfileSource,
		ProfileOrigin:               state.ProfileOrigin,
		GitName:                     state.GitName,
		GitEmail:                    state.GitEmail,
		IdentityConfigured:          state.ConfigName != "" && state.ConfigEmail != "",
		CommitterName:               state.CommitterName,
		CommitterEmail:              state.CommitterEmail,
		SigningKey:                  state.SigningKey,
		SigningFormat:               state.SigningFormat,
		CommitSigningEnabled:        state.CommitSigningEnabled,
		CommitSigningManaged:        state.CommitSigningManaged,
		SigningManagementPresent:    state.SigningManagementPresent || state.SigningFormatManagementPresent || state.CommitSigningManagementPresent || state.SSHSigningProgramManagementPresent || state.SSHSigningProgramDigestManagementPresent,
		SSHSigningProgramManaged:    state.SSHSigningProgramManaged,
		SSHSigningProgramExecutable: state.SSHSigningProgramExecutable,
		SSHSigningProgramIntegrity:  state.SSHSigningProgramIntegrity,
		SSHManagementPresent:        state.SSHManagementPresent,
		Origin:                      displayRemote(state.Origin),
		PushRemote:                  displayRemote(state.PushRemote),
		PushRemoteExplicit:          state.PushRemoteExplicit,
		PushURL:                     displayRemote(state.PushURL),
		PushURLs:                    displayRemotes(state.PushURLs),
		Authentication:              "external (not verified by gitctx)",
		Status:                      "unmanaged",
	}
	selected, found := config.Profiles[state.Profile]
	if state.Profile == "" {
		return result
	}
	if !found {
		result.Status = "mismatch"
		return result
	}
	if state.ProfileSource != "local" && state.ProfileSource != "auto" {
		result.Status = "mismatch"
		return result
	}
	result.GitHubUser = selected.GitHubUser
	result.SigningDisabled = selected.DisableSigning
	if selected.DisableSigning {
		// Hide the internal fail-closed SSH signing sentinel from user-facing
		// output; it is an implementation detail, not an actual signing key.
		result.SigningKey = ""
		result.SigningFormat = ""
	}
	explicitSigning := selected.SigningKey != "" || selected.DisableSigning
	keySigningManaged := selected.SigningKey != "" &&
		state.SigningKey == selected.SigningKey && state.SigningKeyManaged &&
		state.CommitSigningSet && state.CommitSigningEnabled && state.CommitSigningManaged
	if selected.SigningFormat != "" {
		keySigningManaged = keySigningManaged && state.SigningFormat == selected.SigningFormat && state.SigningFormatManaged
	}
	if selected.SigningFormat == "ssh" {
		keySigningManaged = keySigningManaged && state.SSHSigningProgramManaged && state.SSHSigningProgramExecutable && state.SSHSigningProgramDigestManaged && state.SSHSigningProgramIntegrity
	}
	disabledSigningManaged := selected.DisableSigning && state.SigningDisabled
	result.SigningManaged = state.ProfileSource == "local" && (keySigningManaged || disabledSigningManaged)
	result.SigningManagementMismatch = state.ProfileSource == "local" && explicitSigning && !result.SigningManaged
	result.SSHSigningProgramMismatch = state.ProfileSource == "local" &&
		((selected.DisableSigning && !state.SigningDisabled) ||
			(selected.SigningFormat == "ssh" && (!state.SSHSigningProgramManaged || !state.SSHSigningProgramExecutable || !state.SSHSigningProgramDigestManaged || !state.SSHSigningProgramIntegrity)))
	result.SigningManagementStale = state.ProfileSource == "local" && !explicitSigning &&
		(state.SigningManagementPresent || state.SigningFormatManagementPresent || state.CommitSigningManagementPresent || state.SSHSigningProgramManagementPresent || state.SSHSigningProgramDigestManagementPresent)
	result.SSHManagementStale = state.ProfileSource == "local" && selected.SSHKey == "" && state.SSHManagementPresent
	result.SigningPending = state.ProfileSource == "auto" && explicitSigning
	identityScopeMatches := state.ProfileSource != "local" ||
		(state.LocalNameCount == 1 && state.LocalName == selected.GitName && state.LocalEmailCount == 1 && state.LocalEmail == selected.GitEmail)
	worktreeScopeMatches := state.ProfileSource != "local" || !state.MultipleWorktrees
	identityMatches := state.ConfigName == selected.GitName && state.ConfigEmail == selected.GitEmail &&
		state.GitName == selected.GitName && state.GitEmail == selected.GitEmail &&
		state.CommitterName == selected.GitName && state.CommitterEmail == selected.GitEmail &&
		state.AuthorIdentityErr == "" && state.CommitterIdentErr == "" && identityScopeMatches && worktreeScopeMatches
	if identityMatches {
		result.Status = "ok"
	} else {
		result.Status = "mismatch"
	}

	if state.ProfileSource == "auto" {
		if selected.SSHKey != "" {
			result.Authentication = "automatic identity only (SSH not applied)"
		} else {
			result.Authentication = "external (not verified by gitctx)"
		}
		if result.Status == "ok" {
			result.Status = "warning"
		}
		return result
	}

	pushURLs := state.EffectivePushURLs()
	if selected.SSHKey != "" {
		sshKeyValid := false
		fingerprintMatch := selected.SSHFingerprint == ""
		if selected.SSHFingerprint != "" {
			if pair, inspectErr := sshkey.InspectPair(selected.SSHKey); inspectErr == nil {
				sshKeyValid = true
				fingerprintMatch = pair.Fingerprint == selected.SSHFingerprint
			}
		} else if _, inspectErr := gitconfig.ValidateSSHPrivateKey(selected.SSHKey); inspectErr == nil {
			sshKeyValid = true
		}
		result.SSHKeyValid = sshKeyValid
		result.SSHFingerprintMatch = fingerprintMatch
		result.SSHKeyMismatch = !sshKeyValid || !fingerprintMatch
		expected, expectedErr := gitconfig.ExpectedSSHCommand(selected.SSHKey)
		pushDestinationResolved := len(pushURLs) > 0 || (!state.PushRemoteExplicit && state.PushRemote == "")
		if sshKeyValid && fingerprintMatch && expectedErr == nil && !state.SSHOverrideSet && state.SSHCommand == expected && state.SSHVariant == "ssh" && state.SSHCommandManaged && state.SSHVariantManaged && pushDestinationResolved && allSSHRemotes(pushURLs) {
			result.Authentication = "repository-scoped SSH"
			if state.SSHRouteIssue != "" {
				result.Authentication = "repository-scoped SSH (routing unverified)"
			}
			if (len(pushURLs) == 0 || state.SSHRouteIssue != "") && result.Status == "ok" {
				result.Status = "warning"
			}
		} else if result.SSHKeyMismatch {
			result.Authentication = "SSH key mismatch"
			result.Status = "mismatch"
		} else {
			result.Authentication = "SSH configuration mismatch"
			result.Status = "mismatch"
		}
	} else if state.SSHManagementPresent {
		result.Authentication = "SSH configuration mismatch"
		result.Status = "mismatch"
	} else if result.Status == "ok" {
		result.Status = "warning"
	}
	if explicitSigning && !result.SigningManaged {
		result.Status = "mismatch"
	} else if !explicitSigning && (state.SigningManagementPresent || state.SigningFormatManagementPresent || state.CommitSigningManagementPresent || state.SSHSigningProgramManagementPresent || state.SSHSigningProgramDigestManagementPresent) {
		result.Status = "mismatch"
	} else if !explicitSigning && (state.SigningKey != "" || (state.CommitSigningSet && state.CommitSigningEnabled)) && result.Status == "ok" {
		result.Status = "warning"
	}
	return result
}

type check struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Message  string `json:"message"`
}

type diagnosis struct {
	Repository    string  `json:"repository"`
	Profile       string  `json:"profile,omitempty"`
	ProfileSource string  `json:"profile_source,omitempty"`
	ProfileOrigin string  `json:"profile_origin,omitempty"`
	Status        string  `json:"status"`
	Checks        []check `json:"checks"`
}

func diagnose(state gitconfig.State, config configstore.Config) diagnosis {
	result := diagnosis{Repository: state.Repository, Profile: state.Profile, ProfileSource: state.ProfileSource, ProfileOrigin: state.ProfileOrigin, Status: "healthy"}
	selected, found := config.Profiles[state.Profile]
	if state.Profile == "" {
		result.Checks = append(result.Checks, check{ID: "profile", Name: "profile", Status: statusFail, Message: "no gitctx profile is applied; run 'gitctx use <profile>'"})
		result.Status = "error"
		return result
	}
	if !found {
		result.Checks = append(result.Checks, check{ID: "profile", Name: "profile", Status: statusFail, Actual: state.Profile, Message: "the applied profile is missing from the profile store"})
		result.Status = "error"
		return result
	}
	result.Checks = append(result.Checks, check{ID: "profile", Name: "profile", Status: statusPass, Expected: state.Profile, Actual: state.Profile, Message: "profile exists"})
	switch state.ProfileSource {
	case "local":
		result.Checks = append(result.Checks, check{ID: "profile_source", Name: "profile source", Status: statusPass, Actual: "local", Message: "profile is pinned in repository-local Git config"})
		if state.LocalNameCount == 1 && state.LocalName == selected.GitName && state.LocalEmailCount == 1 && state.LocalEmail == selected.GitEmail {
			result.Checks = append(result.Checks, check{ID: "identity_scope", Name: "identity scope", Status: statusPass, Actual: "local", Message: "name and email are isolated in repository-local Git config"})
		} else {
			result.Checks = append(result.Checks, check{ID: "identity_scope", Name: "identity scope", Status: statusFail, Expected: "one local name and email", Message: "name or email is inherited, duplicated, or not repository-local"})
		}
		if state.MultipleWorktrees {
			result.Checks = append(result.Checks, check{ID: "worktree_scope", Name: "worktree scope", Status: statusFail, Expected: "one worktree", Actual: "multiple linked worktrees", Message: "repository-local identity is shared by multiple worktrees; v0.1 cannot guarantee a separate identity for each worktree"})
		} else {
			result.Checks = append(result.Checks, check{ID: "worktree_scope", Name: "worktree scope", Status: statusPass, Actual: "one worktree", Message: "repository-local identity is not shared with another linked worktree"})
		}
	case "auto":
		result.Checks = append(result.Checks, check{ID: "profile_source", Name: "profile source", Status: statusPass, Actual: "auto", Message: "profile comes from the matching managed directory rule"})
	case "auto_missing":
		result.Checks = append(result.Checks, check{ID: "profile_source", Name: "profile source", Status: statusFail, Expected: "active automatic rule", Actual: "inactive", Message: "a directory rule should select this profile, but its generated Git include is not active; run 'gitctx auto sync'"})
	default:
		result.Checks = append(result.Checks, check{ID: "profile_source", Name: "profile source", Status: statusFail, Actual: state.ProfileOrigin, Message: "profile marker does not come from repository-local config or a matching managed directory rule"})
	}
	result.Checks = append(result.Checks, comparison("git_name", "Git name", selected.GitName, state.ConfigName))
	result.Checks = append(result.Checks, comparison("git_email", "Git email", selected.GitEmail, state.ConfigEmail))
	if state.AuthorIdentityErr != "" {
		result.Checks = append(result.Checks, check{ID: "author_identity", Name: "author identity", Status: statusFail, Message: state.AuthorIdentityErr})
	} else if state.GitName != state.ConfigName || state.GitEmail != state.ConfigEmail {
		result.Checks = append(result.Checks, comparison("author_identity", "author identity", identity(selected.GitName, selected.GitEmail), identity(state.GitName, state.GitEmail)))
	}
	if state.CommitterIdentErr != "" {
		result.Checks = append(result.Checks, check{ID: "committer_identity", Name: "committer identity", Status: statusFail, Message: state.CommitterIdentErr})
	} else if state.CommitterName != state.ConfigName || state.CommitterEmail != state.ConfigEmail {
		result.Checks = append(result.Checks, comparison("committer_identity", "committer identity", identity(selected.GitName, selected.GitEmail), identity(state.CommitterName, state.CommitterEmail)))
	}

	explicitSigning := selected.SigningKey != "" || selected.DisableSigning
	if (state.ProfileSource == "auto" || state.ProfileSource == "auto_missing") && explicitSigning {
		expected := "disabled for this repository"
		if selected.SigningKey != "" {
			expected = "signed with " + selected.SigningKey
		}
		result.Checks = append(result.Checks, check{
			ID:       "signing_policy",
			Name:     "signing policy",
			Status:   statusWarn,
			Expected: expected,
			Actual:   commitSigningValue(state),
			Message:  fmt.Sprintf("automatic rules manage identity only; run 'gitctx use %s' to apply this repository's signing policy", state.Profile),
		})
	} else if selected.SigningKey != "" {
		result.Checks = append(result.Checks, comparison("signing_key", "signing key", selected.SigningKey, state.SigningKey))
		if selected.SigningFormat != "" {
			result.Checks = append(result.Checks, comparison("signing_format", "signing format", selected.SigningFormat, state.SigningFormat))
		}
		if selected.SigningFormat == "ssh" {
			if state.SSHSigningProgramManaged && state.SSHSigningProgramExecutable && state.SSHSigningProgramDigestManaged && state.SSHSigningProgramIntegrity {
				result.Checks = append(result.Checks, check{ID: "ssh_signing_program", Name: "SSH signer", Status: statusPass, Actual: "managed local executable", Message: "the resolved ssh-keygen executable is pinned in repository-local config"})
			} else {
				result.Checks = append(result.Checks, check{ID: "ssh_signing_program", Name: "SSH signer", Status: statusFail, Expected: "managed executable with matching integrity marker", Message: "the SSH signing program is inherited, changed, missing, non-executable, or failed its integrity check"})
			}
		}
		if state.CommitSigningSet && state.CommitSigningEnabled {
			result.Checks = append(result.Checks, check{ID: "commit_signing", Name: "commit signing", Status: statusPass, Expected: "enabled", Actual: "enabled", Message: "enabled for this repository"})
		} else {
			result.Checks = append(result.Checks, check{ID: "commit_signing", Name: "commit signing", Status: statusFail, Expected: "enabled", Actual: commitSigningValue(state), Message: "profile signing is not enabled"})
		}
		scopeMatches := state.ProfileSource == "local" && state.SigningKeyManaged && state.CommitSigningManaged
		if selected.SigningFormat != "" {
			scopeMatches = scopeMatches && state.SigningFormatManaged
		}
		if selected.SigningFormat == "ssh" {
			scopeMatches = scopeMatches && state.SSHSigningProgramManaged && state.SSHSigningProgramDigestManaged && state.SSHSigningProgramIntegrity
		}
		if scopeMatches {
			result.Checks = append(result.Checks, check{ID: "signing_scope", Name: "signing scope", Status: statusPass, Expected: "managed local settings", Actual: "managed local settings", Message: "key, format, and signing policy are repository-local"})
		} else {
			result.Checks = append(result.Checks, check{ID: "signing_scope", Name: "signing scope", Status: statusFail, Expected: "managed local settings", Message: "the signing key, format, or enablement is inherited, changed, or not repository-local"})
		}
	} else if selected.DisableSigning {
		if state.SigningDisabled {
			result.Checks = append(result.Checks, check{ID: "ssh_signing_program", Name: "SSH signer", Status: statusPass, Actual: "managed local guard", Message: "an inherited custom SSH signer cannot bypass the repository-local guard"})
		} else {
			result.Checks = append(result.Checks, check{ID: "ssh_signing_program", Name: "SSH signer", Status: statusFail, Expected: "managed local guard", Message: "the SSH signing program is inherited, changed, or not protected by this profile"})
		}
		if state.CommitSigningSet && !state.CommitSigningEnabled {
			result.Checks = append(result.Checks, check{ID: "commit_signing", Name: "commit signing", Status: statusPass, Expected: "disabled", Actual: "disabled", Message: "disabled for this repository"})
		} else {
			result.Checks = append(result.Checks, check{ID: "commit_signing", Name: "commit signing", Status: statusFail, Expected: "disabled", Actual: commitSigningValue(state), Message: "commit signing is not disabled for this repository"})
		}
		if state.ProfileSource == "local" && state.SigningDisabled {
			result.Checks = append(result.Checks, check{ID: "signing_scope", Name: "signing scope", Status: statusPass, Expected: "managed local signing guard", Actual: "managed local signing guard", Message: "automatic signing and bare -S are blocked; only a deliberate command-scoped Git config override can replace the guard"})
		} else {
			result.Checks = append(result.Checks, check{ID: "signing_scope", Name: "signing scope", Status: statusFail, Expected: "managed local signing guard", Message: "the signing guard is inherited, changed, or incomplete"})
		}
	} else if state.SigningManagementPresent || state.SigningFormatManagementPresent || state.CommitSigningManagementPresent || state.SSHSigningProgramManagementPresent || state.SSHSigningProgramDigestManagementPresent {
		result.Checks = append(result.Checks, check{ID: "signing_policy", Name: "signing policy", Status: statusFail, Actual: commitSigningValue(state), Message: "the profile has no signing policy, but repository-local gitctx signing management metadata remains; run 'gitctx fix' only if the managed values are intact, otherwise review the stale local settings manually"})
	} else if state.SigningKey != "" || (state.CommitSigningSet && state.CommitSigningEnabled) {
		result.Checks = append(result.Checks, check{ID: "signing_policy", Name: "signing policy", Status: statusWarn, Actual: commitSigningValue(state), Message: "commit signing is inherited but this profile does not define a signing policy"})
	} else {
		result.Checks = append(result.Checks, check{ID: "signing_policy", Name: "signing policy", Status: statusSkip, Message: "profile does not manage commit signing"})
	}

	if selected.SSHKey == "" {
		if state.SSHManagementPresent {
			result.Checks = append(result.Checks, check{ID: "authentication", Name: "authentication", Status: statusFail, Message: "the profile has no SSH key, but repository-local gitctx SSH management metadata remains; run 'gitctx fix' only if the managed values are intact, otherwise review and remove the stale local settings manually"})
		} else {
			result.Checks = append(result.Checks, check{ID: "authentication", Name: "authentication", Status: statusWarn, Message: "authentication is external and cannot be verified by gitctx"})
		}
	} else {
		resolved := ""
		fingerprint := ""
		var err error
		if selected.SSHFingerprint != "" {
			var pair sshkey.Pair
			pair, err = sshkey.InspectPair(selected.SSHKey)
			resolved = pair.PrivatePath
			fingerprint = pair.Fingerprint
		} else {
			resolved, err = gitconfig.ValidateSSHPrivateKey(selected.SSHKey)
		}
		if err != nil {
			result.Checks = append(result.Checks, check{ID: "ssh_key", Name: "SSH key", Status: statusFail, Actual: selected.SSHKey, Message: err.Error()})
		} else if selected.SSHFingerprint != "" && fingerprint != selected.SSHFingerprint {
			result.Checks = append(result.Checks, check{ID: "ssh_fingerprint", Name: "SSH fingerprint", Status: statusFail, Expected: selected.SSHFingerprint, Actual: fingerprint, Message: "the key at the saved path no longer matches the profile fingerprint"})
		} else if !gitconfig.SSHPrivateKeyPermissionsVerified() {
			result.Checks = append(result.Checks, check{ID: "ssh_key", Name: "SSH key", Status: statusWarn, Actual: resolved, Message: "private key is recognized and readable, but Windows ACL protection was not verified"})
		} else {
			result.Checks = append(result.Checks, check{ID: "ssh_key", Name: "SSH key", Status: statusPass, Actual: resolved, Message: "private key is recognized, readable, and protected"})
		}
		if err == nil && selected.SSHFingerprint != "" && fingerprint == selected.SSHFingerprint {
			result.Checks = append(result.Checks, check{ID: "ssh_fingerprint", Name: "SSH fingerprint", Status: statusPass, Expected: selected.SSHFingerprint, Actual: fingerprint, Message: "matches the fingerprint pinned by the profile"})
		}

		if state.ProfileSource == "auto" || state.ProfileSource == "auto_missing" {
			result.Checks = append(result.Checks, check{
				ID:      "authentication",
				Name:    "authentication",
				Status:  statusWarn,
				Message: fmt.Sprintf("automatic rules manage identity only; run 'gitctx use %s' to apply and verify this SSH key", state.Profile),
			})
		} else {
			expected, err := gitconfig.ExpectedSSHCommand(selected.SSHKey)
			if err != nil {
				result.Checks = append(result.Checks, check{ID: "ssh_command", Name: "SSH command", Status: statusFail, Message: err.Error()})
			} else if state.SSHCommand == expected {
				result.Checks = append(result.Checks, check{ID: "ssh_command", Name: "SSH command", Status: statusPass, Message: "matches the repository command generated for this profile"})
			} else {
				result.Checks = append(result.Checks, check{ID: "ssh_command", Name: "SSH command", Status: statusFail, Message: "the effective SSH command does not match the repository command generated for this profile"})
			}
			if state.SSHCommandManaged && state.SSHVariantManaged && state.SSHVariant == "ssh" {
				result.Checks = append(result.Checks, check{ID: "ssh_scope", Name: "SSH scope", Status: statusPass, Actual: "local", Message: "OpenSSH command and variant are managed in repository-local Git config"})
			} else {
				result.Checks = append(result.Checks, check{ID: "ssh_scope", Name: "SSH scope", Status: statusFail, Expected: "managed local OpenSSH settings", Message: "SSH command or OpenSSH variant is inherited, changed, or not repository-local"})
			}
			if state.SSHOverrideSet {
				result.Checks = append(result.Checks, check{ID: "ssh_environment", Name: "SSH environment", Status: statusFail, Actual: valueOr(state.SSHOverride, "(empty)"), Message: "GIT_SSH_COMMAND, GIT_SSH, or GIT_SSH_VARIANT overrides repository SSH behavior"})
			} else {
				result.Checks = append(result.Checks, check{ID: "ssh_environment", Name: "SSH environment", Status: statusPass, Message: "no SSH environment override detected"})
			}
			pushURLs := state.EffectivePushURLs()
			if state.SSHRouteIssue != "" {
				result.Checks = append(result.Checks, check{ID: "ssh_route", Name: "SSH routing", Status: statusWarn, Message: state.SSHRouteIssue})
			} else if len(pushURLs) == 0 {
				result.Checks = append(result.Checks, check{ID: "ssh_route", Name: "SSH routing", Status: statusSkip, Message: "no resolvable push URL is available for an SSH routing check"})
			} else if !allSSHRemotes(pushURLs) {
				result.Checks = append(result.Checks, check{ID: "ssh_route", Name: "SSH routing", Status: statusSkip, Message: "the default push destination is not a valid SSH URL"})
			} else {
				result.Checks = append(result.Checks, check{ID: "ssh_route", Name: "SSH routing", Status: statusPass, Message: "remote routing does not depend on disabled SSH config"})
			}
			if len(pushURLs) == 0 {
				if state.PushRemoteExplicit || state.PushRemote != "" {
					result.Checks = append(result.Checks, check{ID: "push_remote", Name: "push remote", Status: statusFail, Actual: valueOr(displayRemote(state.PushRemote), "(empty)"), Message: "the configured default push destination is not a resolvable named remote"})
				} else {
					result.Checks = append(result.Checks, check{ID: "push_remote", Name: "push remote", Status: statusWarn, Actual: displayRemote(state.PushRemote), Message: "no default push remote exists, so push authentication cannot be checked"})
				}
			} else if allSSHRemotes(pushURLs) {
				result.Checks = append(result.Checks, check{ID: "push_remote", Name: "push remote", Status: statusPass, Actual: displayRemote(state.PushRemote) + ": " + strings.Join(displayRemotes(pushURLs), ", "), Message: "all default push URLs use SSH and the repository-specific key will apply"})
			} else {
				result.Checks = append(result.Checks, check{ID: "push_remote", Name: "push remote", Status: statusFail, Expected: "all valid SSH URLs", Actual: displayRemote(state.PushRemote) + ": " + strings.Join(displayRemotes(pushURLs), ", "), Message: "at least one default push URL is not a valid SSH destination, so the profile's SSH key cannot be verified for every push target"})
			}
		}
	}

	result.Status = diagnosisStatus(result.Checks)
	return result
}

func comparison(id, name, expected, actual string) check {
	if expected == actual {
		return check{ID: id, Name: name, Status: statusPass, Expected: expected, Actual: actual, Message: "matches profile"}
	}
	return check{ID: id, Name: name, Status: statusFail, Expected: expected, Actual: actual, Message: fmt.Sprintf("expected %q, found %q", expected, actual)}
}

func commitSigningValue(state gitconfig.State) string {
	if !state.CommitSigningSet {
		return "unset"
	}
	if state.CommitSigningEnabled {
		return "enabled"
	}
	return "disabled"
}

func diagnosisStatus(checks []check) string {
	status := "healthy"
	for _, item := range checks {
		if item.Status == statusFail {
			return "error"
		}
		if item.Status == statusWarn {
			status = "warning"
		}
	}
	return status
}

func classifyProfileSource(state gitconfig.State, config configstore.Config, configPath string) gitconfig.State {
	if state.ProfileSource == "local" {
		return state
	}
	if !state.OrdinaryRepository {
		if state.Profile != "" {
			state.ProfileSource = "nonlocal"
		}
		return state
	}
	matchedProfile := ""
	longest := -1
	for directory, profileName := range config.Rules {
		canonicalDirectory, err := autorules.CanonicalPathAllowMissing(directory)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(filepath.Clean(canonicalDirectory), filepath.Clean(state.Repository))
		if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		if length := len(filepath.Clean(canonicalDirectory)); length > longest {
			longest = length
			matchedProfile = profileName
		}
	}
	if matchedProfile == "" {
		if state.Profile != "" {
			state.ProfileSource = "nonlocal"
		}
		return state
	}
	if state.Profile == "" {
		state.Profile = matchedProfile
		state.ProfileSource = "auto_missing"
		return state
	}
	if matchedProfile != state.Profile {
		state.ProfileSource = "nonlocal"
		return state
	}
	expected := autorules.NewManager(configPath).ProfilePath(config, state.Profile)
	if sameOriginFile(state.ProfileOrigin, expected, state.Repository) {
		state.ProfileSource = "auto"
	} else {
		state.ProfileSource = "nonlocal"
	}
	return state
}

func sameOriginFile(origin, expected, repository string) bool {
	if !strings.HasPrefix(origin, "file:") {
		return false
	}
	actual := strings.TrimPrefix(origin, "file:")
	if !filepath.IsAbs(actual) {
		actual = filepath.Join(repository, actual)
	}
	actualInfo, actualErr := os.Stat(filepath.Clean(actual))
	expectedInfo, expectedErr := os.Stat(filepath.Clean(expected))
	return actualErr == nil && expectedErr == nil && os.SameFile(actualInfo, expectedInfo)
}

func allSSHRemotes(remotes []string) bool {
	for _, remote := range remotes {
		if !gitconfig.IsSSHRemote(remote) {
			return false
		}
	}
	return true
}

func displayRemotes(remotes []string) []string {
	result := make([]string, len(remotes))
	for index, remote := range remotes {
		result[index] = displayRemote(remote)
	}
	return result
}

func displayRemote(remote string) string {
	parsed, err := url.Parse(remote)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		if strings.Contains(remote, "::") || strings.Contains(remote, "://") || strings.ContainsAny(remote, "?#") {
			return "[remote URL redacted]"
		}
		return escapeDisplayControls(remote)
	}
	sshScheme := parsed.Scheme == "ssh" || parsed.Scheme == "git+ssh" || parsed.Scheme == "ssh+git"
	if parsed.User != nil && !sshScheme {
		parsed.User = url.User("redacted")
	} else if parsed.User != nil {
		username := parsed.User.Username()
		if _, hasPassword := parsed.User.Password(); hasPassword {
			parsed.User = url.User(username)
		}
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return escapeDisplayControls(parsed.String())
}

func escapeDisplayControls(value string) string {
	if strings.IndexFunc(value, unicode.IsControl) < 0 {
		return value
	}
	var escaped strings.Builder
	for _, character := range value {
		if !unicode.IsControl(character) {
			escaped.WriteRune(character)
			continue
		}
		if character <= 0xff {
			fmt.Fprintf(&escaped, `\x%02x`, character)
		} else {
			fmt.Fprintf(&escaped, `\u%04x`, character)
		}
	}
	return escaped.String()
}

type simpleOptions struct {
	json bool
	help bool
}

type repoOptions struct {
	profile string
	repo    string
	json    bool
	strict  bool
	help    bool
}

func parseAdd(args []string) (addOptions, error) {
	var options addOptions
	positionals, err := parseOptions(args, map[string]*string{
		"--name":           &options.gitName,
		"--git-name":       &options.gitName,
		"--email":          &options.email,
		"--git-email":      &options.email,
		"--github":         &options.github,
		"--github-user":    &options.github,
		"--ssh-key":        &options.sshKey,
		"--signing-key":    &options.signingKey,
		"--signing-format": &options.signingFormat,
	}, map[string]*bool{
		"--disable-signing": &options.disableSigning,
		"--force":           &options.force,
		"--json":            &options.json,
		"--help":            &options.help,
		"-h":                &options.help,
	})
	if err != nil {
		return options, err
	}
	if len(positionals) > 1 {
		return options, fmt.Errorf("add accepts one profile name")
	}
	if len(positionals) == 1 {
		options.profile = positionals[0]
	}
	return options, nil
}

func parseSimple(args []string) (simpleOptions, error) {
	var options simpleOptions
	positionals, err := parseOptions(args, nil, map[string]*bool{
		"--json": &options.json,
		"--help": &options.help,
		"-h":     &options.help,
	})
	if err != nil {
		return options, err
	}
	if len(positionals) > 0 {
		return options, fmt.Errorf("unexpected argument %q", positionals[0])
	}
	return options, nil
}

func parseRepoCommand(args []string, requireProfile, allowStrict bool) (repoOptions, error) {
	options := repoOptions{repo: "."}
	booleans := map[string]*bool{
		"--json": &options.json,
		"--help": &options.help,
		"-h":     &options.help,
	}
	if allowStrict {
		booleans["--strict"] = &options.strict
	}
	positionals, err := parseOptions(args, map[string]*string{"--repo": &options.repo}, booleans)
	if err != nil {
		return options, err
	}
	if options.repo == "" {
		return options, fmt.Errorf("--repo requires a non-empty path")
	}
	max := 0
	if requireProfile {
		max = 1
	}
	if len(positionals) > max {
		return options, fmt.Errorf("unexpected argument %q", positionals[max])
	}
	if len(positionals) == 1 {
		options.profile = positionals[0]
	}
	return options, nil
}

func parseAuto(args []string) (autoOptions, error) {
	var options autoOptions
	positionals, err := parseOptions(args, nil, map[string]*bool{
		"--force": &options.force,
		"--json":  &options.json,
		"--help":  &options.help,
		"-h":      &options.help,
	})
	if err != nil {
		return options, err
	}
	if len(positionals) == 0 {
		if options.force {
			return options, fmt.Errorf("--force is only valid with auto add")
		}
		return options, nil
	}
	options.action = positionals[0]
	switch options.action {
	case "list", "sync":
		if options.force {
			return options, fmt.Errorf("--force is only valid with auto add")
		}
		if len(positionals) > 1 {
			return options, fmt.Errorf("auto %s does not accept positional arguments", options.action)
		}
	case "add":
		if len(positionals) > 3 {
			return options, fmt.Errorf("auto add accepts one directory and one profile")
		}
		if len(positionals) > 1 {
			options.path = positionals[1]
		}
		if len(positionals) > 2 {
			options.profile = positionals[2]
		}
	case "remove":
		if options.force {
			return options, fmt.Errorf("--force is only valid with auto add")
		}
		if len(positionals) > 2 {
			return options, fmt.Errorf("auto remove accepts one directory")
		}
		if len(positionals) > 1 {
			options.path = positionals[1]
		}
	}
	return options, nil
}

func parseOptions(args []string, values map[string]*string, booleans map[string]*bool) ([]string, error) {
	var positionals []string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}

		name, inline, hasInline := strings.Cut(arg, "=")
		if target, ok := booleans[name]; ok {
			if hasInline {
				switch inline {
				case "true":
					*target = true
				case "false":
					*target = false
				default:
					return nil, fmt.Errorf("%s expects true or false", name)
				}
			} else {
				*target = true
			}
			continue
		}
		if target, ok := values[name]; ok {
			if hasInline {
				*target = inline
				continue
			}
			index++
			if index >= len(args) {
				return nil, fmt.Errorf("%s requires a value", name)
			}
			*target = args[index]
			continue
		}
		return nil, fmt.Errorf("unknown option %q", name)
	}
	return positionals, nil
}

func extractConfigOption(args []string) ([]string, string, error) {
	clean := make([]string, 0, len(args))
	configPath := ""
	if len(args) == 0 {
		return clean, configPath, nil
	}
	clean = append(clean, args[0])
	command := commandName(args)
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			clean = append(clean, args[index:]...)
			break
		}
		if arg == "--config" {
			index++
			if index >= len(args) || args[index] == "" {
				return clean, "", fmt.Errorf("--config requires a value")
			}
			configPath = args[index]
			continue
		}
		if strings.HasPrefix(arg, "--config=") {
			configPath = strings.TrimPrefix(arg, "--config=")
			if configPath == "" {
				return clean, "", fmt.Errorf("--config requires a value")
			}
			continue
		}
		clean = append(clean, arg)
		name, _, hasInline := strings.Cut(arg, "=")
		if !hasInline && optionConsumesValue(command, name) && index+1 < len(args) {
			index++
			clean = append(clean, args[index])
		}
	}
	return clean, configPath, nil
}

func requestsJSON(args []string) bool {
	requested := false
	invalidJSON := false
	command := commandName(args)
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			break
		}
		name, _, hasInline := strings.Cut(arg, "=")
		if !hasInline && optionConsumesValue(command, name) {
			index++
			continue
		}
		if arg == "--json" || arg == "--json=true" {
			requested = true
		} else if arg == "--json=false" {
			requested = false
		} else if name == "--json" && hasInline {
			// An invalid JSON flag still requests a JSON error envelope. Keep
			// that choice sticky so duplicate invalid flags are order-independent.
			invalidJSON = true
		}
	}
	return invalidJSON || requested
}

func optionConsumesValue(command, name string) bool {
	if name == "--config" {
		return true
	}
	switch command {
	case "login":
		switch name {
		case "--client-id", "--github", "--email", "--name":
			return true
		}
	case "setup":
		switch name {
		case "--name", "--email", "--github", "--repo", "--auth", "--ssh-key", "--key-path", "--signing":
			return true
		}
	case "add":
		switch name {
		case "--name", "--git-name", "--email", "--git-email", "--github", "--github-user", "--ssh-key", "--signing-key", "--signing-format":
			return true
		}
	case "use", "current", "doctor", "verify", "fix":
		return name == "--repo"
	}
	return false
}

func commandName(args []string) string {
	if len(args) == 0 {
		return "current"
	}
	switch args[0] {
	case "profiles":
		return "list"
	case "status":
		return "current"
	default:
		return args[0]
	}
}

func (a application) prompt(label string) (string, error) {
	fmt.Fprintf(a.out, "%s: ", label)
	value, err := a.in.ReadString('\n')
	if err != nil && len(value) == 0 {
		return "", fmt.Errorf("read %s: %w", strings.ToLower(label), err)
	}
	return strings.TrimSpace(value), nil
}

func (a application) succeed(data any, warnings []notice) int {
	return a.writeEnvelope(envelope{SchemaVersion: jsonSchema, Command: a.command, OK: true, Data: data, Warnings: warnings})
}

func (a application) fail(exitCode int, code string, err error, hint string) int {
	if a.json {
		if writeCode := a.writeEnvelope(envelope{
			SchemaVersion: jsonSchema,
			Command:       a.command,
			OK:            false,
			Error:         &apiError{Code: code, Message: err.Error(), Hint: hint},
		}); writeCode != exitOK {
			return writeCode
		}
		return exitCode
	}
	fmt.Fprintf(a.err, "gitctx: %s\n", escapeDisplayControls(err.Error()))
	if hint != "" {
		fmt.Fprintln(a.err, escapeDisplayControls(hint))
	}
	return exitCode
}

func friendlyRepositoryError(err error) error {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "not a git repository") || strings.Contains(message, "must be run in a work tree") || strings.Contains(message, "not a working tree") {
		return errors.New("the selected path is not inside a Git repository")
	}
	return err
}

func (a application) writeEnvelope(value envelope) int {
	encoder := json.NewEncoder(a.out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(a.err, "gitctx: write JSON: %v\n", err)
		return exitConfig
	}
	return exitOK
}

func currentWarnings(current currentOutput) []notice {
	var warnings []notice
	if !current.IdentityConfigured {
		warnings = append(warnings, notice{Code: "identity_unconfigured", Message: "Git name or email is not explicitly configured; Git may synthesize a machine-based identity. Run 'gitctx setup personal' before committing."})
	}
	if current.ProfileSource == "local" && current.MultipleWorktrees {
		warnings = append(warnings, notice{Code: "multiple_worktrees_unsafe", Message: "This repository-local profile is shared by multiple linked worktrees; remove extra worktrees or manage worktree-specific Git config manually before relying on the identity."})
	}
	if current.ProfileSource == "auto_missing" {
		warnings = append(warnings, notice{Code: "auto_rule_inactive", Message: "A matching automatic directory rule is configured but not active; run 'gitctx auto sync' before committing."})
	} else if current.Profile != "" && current.ProfileSource != "local" && current.ProfileSource != "auto" {
		warnings = append(warnings, notice{Code: "profile_source_untrusted", Message: "The profile marker does not come from repository-local config or a matching managed directory rule."})
	}
	if current.Authentication == "external (not verified by gitctx)" {
		warnings = append(warnings, notice{Code: "auth_unverified", Message: "Git authentication is external and was not verified."})
	}
	if current.Authentication == "SSH configuration mismatch" {
		warnings = append(warnings, notice{Code: "auth_mismatch", Message: "The repository SSH configuration does not fully match the profile."})
	}
	if current.SSHKeyMismatch {
		warnings = append(warnings, notice{Code: "ssh_key_mismatch", Message: "The saved SSH key is missing, invalid, or no longer matches the profile fingerprint; run 'gitctx doctor' before pushing or signing."})
	}
	if current.SSHManagementStale {
		warnings = append(warnings, notice{Code: "stale_managed_ssh", Message: "Repository-local SSH settings managed by an earlier profile version remain. Run 'gitctx fix' if those values are intact; if they were edited, run 'gitctx doctor' and review the stale local settings manually."})
	}
	if current.Authentication == "repository-scoped SSH (routing unverified)" {
		warnings = append(warnings, notice{Code: "ssh_routing_unverified", Message: "Strict key isolation ignores SSH config, so host routing and connectivity are not tested."})
	}
	if strings.HasPrefix(current.Authentication, "repository-scoped SSH") && !gitconfig.SSHPrivateKeyPermissionsVerified() {
		warnings = append(warnings, notice{Code: "ssh_permissions_unverified", Message: "The SSH key is readable, but its Windows ACL protection was not verified."})
	}
	if current.Authentication == "automatic identity only (SSH not applied)" {
		warnings = append(warnings, notice{Code: "auto_identity_only_ssh", Message: fmt.Sprintf("Automatic rules select identity only; run 'gitctx use %s' to apply the profile's SSH key.", current.Profile)})
	}
	if current.SigningPending {
		warnings = append(warnings, notice{Code: "auto_identity_only_signing", Message: fmt.Sprintf("Automatic rules select identity only; run 'gitctx use %s' to apply the profile's repository signing policy.", current.Profile)})
	}
	if current.SigningManagementMismatch {
		warnings = append(warnings, notice{Code: "signing_mismatch", Message: "The repository signing configuration does not match the selected profile; run 'gitctx doctor' first, and use 'gitctx fix' only if its gitctx-managed value is intact."})
	} else if current.SigningKey != "" && !current.SigningManaged && !current.SigningManagementStale {
		warnings = append(warnings, notice{Code: "signing_inherited", Message: "A signing key is active; run 'gitctx doctor' to confirm that the profile manages it."})
	}
	if current.SigningManagementStale {
		warnings = append(warnings, notice{Code: "stale_managed_signing", Message: "Commit-signing management metadata from an earlier profile version remains. Run 'gitctx fix' if its managed value is intact; if it was edited, run 'gitctx doctor' and review the stale local settings manually."})
	}
	if current.SSHSigningProgramMismatch {
		warnings = append(warnings, notice{Code: "ssh_signing_program_mismatch", Message: "The repository's SSH signing program is not the protected value managed by this profile; signing guarantees are unsafe until it is reviewed."})
	}
	if current.Status == "warning" && current.PushURL == "" && current.Authentication == "repository-scoped SSH" {
		warnings = append(warnings, notice{Code: "push_remote_missing", Message: "No default push remote exists, so push authentication cannot be checked."})
	}
	if current.Status == "mismatch" {
		warnings = append(warnings, notice{Code: "identity_mismatch", Message: "The repository context does not match its selected profile; run 'gitctx doctor' for the exact checks."})
	}
	return warnings
}

func sshKeyPlatformWarnings(selected profile.Profile) []notice {
	if selected.SSHKey == "" || gitconfig.SSHPrivateKeyPermissionsVerified() {
		return nil
	}
	return []notice{{Code: "ssh_permissions_unverified", Message: "The SSH key is readable, but its Windows ACL protection was not verified."}}
}

func identity(name, email string) string { return name + " <" + email + ">" }

func valueOrDash(value string) string { return valueOr(value, "-") }

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func checkLabel(status string) string {
	switch status {
	case statusPass:
		return "PASS"
	case statusWarn:
		return "WARN"
	case statusSkip:
		return "SKIP"
	default:
		return "FAIL"
	}
}

func printHelp(w io.Writer) {
	fmt.Fprintln(w, `gitctx keeps Git commit identity and repository authentication aligned.

Usage:
  gitctx <command> [options]

Commands:
  login [profile]    Add a reusable account with native GitHub browser login
  setup <profile>    Guided first-time setup for one repository
  connect <profile>  Register its public key with GitHub using GitHub CLI
  add <profile>      Create a profile with non-secret identity metadata
  list               List saved profiles
  use <profile>      Apply a profile to one repository
  current            Show the effective repository identity (alias: status)
  doctor             Check identity and authentication configuration
  verify             Test the profile key against the push remote (read-only)
  fix                Re-apply the repository's selected profile
  auto               Manage automatic directory-to-profile rules
  version            Show the current version
  help               Show this help

Core command options (place after the command):
  --config <path>  Use an explicit profile store
  --json           Emit a stable machine-readable response (except login/connect)

Help and version output are always plain text. Run 'gitctx <command> --help' for command options.`)
}

func printAddHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  gitctx add <profile> [options]

Options:
  --name <name>          Git commit author name (prompted when omitted)
  --email <email>        Git commit author email (prompted when omitted)
  --github <username>    GitHub username metadata
  --ssh-key <path>       Private SSH key used only by repositories with this profile
  --signing-key <id>     Git signing key identifier; requires --signing-format
  --signing-format <id>  Required with a signing key: ssh, openpgp, or x509
  --disable-signing      Disable commit signing when this profile is applied
  --force                Replace an existing profile
  --config <path>        Use an explicit profile store
  --json                 Emit machine-readable JSON; requires --name and --email`)
}

func printAutoHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  gitctx auto add <directory> <profile> [--force] [--json] [--config <path>]
  gitctx auto list [--json] [--config <path>]
  gitctx auto remove <directory> [--json] [--config <path>]
  gitctx auto sync [--json] [--config <path>]

Automatic rules use Git's includeIf support. gitctx adds one managed include to
global Git config but does not change global user.name or user.email. Rules select
commit identity only; use a profile explicitly to apply its SSH or signing key.`)
}
