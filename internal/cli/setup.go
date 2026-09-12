package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gitctx/internal/configstore"
	"gitctx/internal/gitconfig"
	"gitctx/internal/profile"
	"gitctx/internal/sshkey"
)

type setupOptions struct {
	profile       string
	repo          string
	gitName       string
	email         string
	github        string
	githubSet     bool
	clearGitHub   bool
	auth          string
	sshKey        string
	keyPath       string
	signing       string
	force         bool
	allowKeyReuse bool
	json          bool
	help          bool
}

type setupOutput struct {
	Name                     string          `json:"name"`
	Profile                  profile.Profile `json:"profile"`
	Repository               string          `json:"repository"`
	GeneratedKey             bool            `json:"generated_key"`
	PublicKeyPath            string          `json:"public_key_path,omitempty"`
	Fingerprint              string          `json:"ssh_fingerprint,omitempty"`
	ConfigPath               string          `json:"config_path"`
	AutomaticRuleDirectories []string        `json:"automatic_rule_directories,omitempty"`
	Diagnosis                diagnosis       `json:"diagnosis"`
}

func (a application) setup(args []string) int {
	options, err := parseSetup(args)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Run 'gitctx setup --help' for usage.")
	}
	if options.help {
		printSetupHelp(a.out)
		return exitOK
	}
	if options.profile == "" {
		return a.fail(exitUsage, "invalid_usage", errors.New("setup requires a profile name"), "Usage: gitctx setup <profile> [options]")
	}
	if err := profile.ValidateName(options.profile); err != nil {
		return a.fail(exitUsage, "invalid_profile", err, "")
	}
	if options.json {
		if options.gitName == "" || options.email == "" || options.auth == "" || options.signing == "" {
			return a.fail(exitUsage, "invalid_usage", errors.New("--json requires --name, --email, --auth, and --signing"), "JSON setup is non-interactive.")
		}
		if err := normalizeSetupIdentity(&options); err != nil {
			return a.fail(exitUsage, "invalid_profile", err, "")
		}
		if err := validateSetupOptions(options); err != nil {
			return a.fail(exitUsage, "invalid_usage", err, "Run 'gitctx setup --help' for compatible options.")
		}
		if options.auth == "generate" {
			return a.fail(exitUsage, "invalid_usage", errors.New("--json cannot generate a key because ssh-keygen requires an interactive passphrase prompt"), "Generate the key interactively first, then use --auth existing --ssh-key <path>.")
		}
	}

	// Resolve the repository and reject a topology that gitctx cannot safely
	// isolate before asking questions or generating any key material.
	preflight, err := a.git.Inspect(options.repo)
	if err != nil {
		return a.fail(exitGit, "not_git_repository", err, "Run setup from inside the repository, or pass --repo <path>.")
	}
	if preflight.MultipleWorktrees {
		return a.fail(exitGit, "multiple_worktrees_unsafe", errors.New("repository has multiple linked worktrees; setup will not change their shared local identity"), "Remove the linked worktrees or manage worktree-specific Git config manually.")
	}
	repository := preflight.Repository

	baseline, err := a.store.Load()
	if err != nil {
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	beforeProfile, profileExists := baseline.Profiles[options.profile]
	baselineAffectedRules := automaticRuleDirectories(baseline, options.profile)
	interactive := !options.json && (options.gitName == "" || options.email == "" || options.auth == "" || options.signing == "")
	if !options.json && ((options.auth == "generate" && options.keyPath == "") || (options.auth == "existing" && options.sshKey == "")) {
		interactive = true
	}

	if profileExists && !options.force {
		if options.json {
			return a.fail(exitProfile, "profile_exists", fmt.Errorf("profile %q already exists", options.profile), "Use --force to update it.")
		}
		fmt.Fprintf(a.out, "Profile %q already exists:\n", options.profile)
		fmt.Fprintf(a.out, "  Git author  %s <%s>\n", escapeDisplayControls(beforeProfile.GitName), escapeDisplayControls(beforeProfile.GitEmail))
		if beforeProfile.SSHKey != "" {
			fmt.Fprintf(a.out, "  SSH key     %s\n", escapeDisplayControls(beforeProfile.SSHKey))
		}
		confirmed, promptErr := a.promptConfirmation("Update this profile and apply it to the repository")
		if promptErr != nil {
			return a.fail(exitUsage, "setup_cancelled", promptErr, "No profile, key, or Git setting was changed.")
		}
		if !confirmed {
			fmt.Fprintln(a.out, "Setup cancelled. Nothing was changed.")
			return exitOK
		}
		options.force = true
		interactive = true
	}

	if !options.json {
		if options.gitName == "" {
			options.gitName, err = a.promptSetupValue("Git name", beforeProfile.GitName, true)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
		}
		if options.email == "" {
			options.email, err = a.promptSetupValue("Git email", beforeProfile.GitEmail, true)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
		}
		if interactive && !options.githubSet {
			options.github, err = a.promptSetupValue("GitHub username (optional)", beforeProfile.GitHubUser, false)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
			options.githubSet = true
		}
		if options.auth == "" {
			defaultAuth := "generate"
			if beforeProfile.SSHKey != "" {
				defaultAuth = "existing"
			} else if beforeProfile.DisableSigning {
				defaultAuth = "identity-only"
			}
			options.auth, err = a.promptSetupChoice("Authentication", []setupChoice{
				{Value: "generate", Label: "Generate a new SSH key (recommended)"},
				{Value: "existing", Label: "Use an existing SSH key"},
				{Value: "identity-only", Label: "Identity only (push authentication is not managed)"},
			}, defaultAuth)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
		}
		if options.auth == "existing" && options.sshKey == "" {
			options.sshKey, err = a.promptSetupValue("Private SSH key path", beforeProfile.SSHKey, true)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
		}
		if options.auth == "generate" && options.keyPath == "" {
			defaultPath, pathErr := sshkey.DefaultPath(options.profile)
			if pathErr != nil {
				return a.fail(exitUsage, "invalid_key_path", pathErr, "")
			}
			options.keyPath, err = a.promptSetupValue("New private SSH key path", defaultPath, true)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
		}
		if options.signing == "" {
			if options.auth == "identity-only" {
				options.signing = "disabled"
			} else {
				defaultSigning := "same-key"
				if beforeProfile.DisableSigning {
					defaultSigning = "disabled"
				}
				options.signing, err = a.promptSetupChoice("Commit signing", []setupChoice{
					{Value: "same-key", Label: "Sign with the same SSH key (recommended)"},
					{Value: "disabled", Label: "Disable signing in this repository"},
				}, defaultSigning)
				if err != nil {
					return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
				}
			}
		}
	}

	if !options.githubSet && profileExists {
		options.github = beforeProfile.GitHubUser
	}
	if err := normalizeSetupIdentity(&options); err != nil {
		return a.fail(exitUsage, "invalid_profile", err, "")
	}
	if err := validateSetupOptions(options); err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Run 'gitctx setup --help' for compatible options.")
	}
	var inheritedSigningKeys []string
	var sshDefaultKeyCommand bool
	if options.auth != "identity-only" {
		inheritedSigningKeys, err = a.git.InheritedSigningKeys(repository)
		if err != nil {
			return a.fail(exitGit, "git_failed", err, "No profile, key, or Git setting was changed.")
		}
		sshDefaultKeyCommand, err = a.git.HasSSHDefaultKeyCommand(repository)
		if err != nil {
			return a.fail(exitGit, "git_failed", err, "No profile, key, or Git setting was changed.")
		}
	}
	if options.auth == "generate" && sshDefaultKeyCommand && !options.allowKeyReuse {
		return a.fail(exitUsage, "inherited_key_unverifiable", errors.New("Git has an SSH default-key command, so gitctx cannot prove that a generated key will remain separate from the inherited signing key"), "Check the configured SSH default-key command yourself, then pass --allow-key-reuse only if proceeding is intentional.")
	}
	if options.auth == "generate" && !isTerminalInput(a.rawIn) {
		return a.fail(exitUsage, "interactive_terminal_required", errors.New("SSH key generation requires an interactive terminal for the passphrase prompt"), "Run 'gitctx setup <profile>' in a terminal, or generate a key separately and use --auth existing.")
	}

	if options.auth != "identity-only" {
		pushURLs := preflight.EffectivePushURLs()
		if (preflight.PushRemoteExplicit || preflight.PushRemote != "") && len(pushURLs) == 0 {
			return a.fail(exitGit, "push_remote_unresolved", errors.New("the configured default push destination is not a resolvable remote"), "Fix the repository's push remote, or choose --auth identity-only.")
		}
		if len(pushURLs) > 0 && !allSSHRemotes(pushURLs) {
			return a.fail(exitGit, "non_ssh_remote", errors.New("the default push destination does not exclusively use SSH"), "Change the remote to an SSH URL, or choose --auth identity-only. gitctx did not rewrite the remote.")
		}
	}

	keyDestination := options.sshKey
	if options.auth == "generate" {
		keyDestination = options.keyPath
	}
	if interactive {
		printSetupPlan(a.out, options, repository, keyDestination, baselineAffectedRules)
		confirmed, promptErr := a.promptConfirmation("Apply this setup")
		if promptErr != nil {
			return a.fail(exitUsage, "setup_cancelled", promptErr, "No profile, key, or Git setting was changed.")
		}
		if !confirmed {
			fmt.Fprintln(a.out, "Setup cancelled. Nothing was changed.")
			return exitOK
		}
	}

	var pair sshkey.Pair
	generated := false
	switch options.auth {
	case "existing":
		pair, err = sshkey.InspectPair(options.sshKey)
		if err != nil {
			return a.fail(exitUsage, "invalid_ssh_key", err, "Provide a private key whose matching public key is at <private-key>.pub.")
		}
	case "generate":
		fmt.Fprintln(a.out, "ssh-keygen will now prompt for a passphrase while it creates and validates the key in a protected temporary location.")
		pair, err = sshkey.Generate(options.profile, options.keyPath, a.rawIn, a.out, a.err)
		if err != nil {
			return a.fail(exitUsage, "key_generation_failed", err, "No profile or Git setting was changed.")
		}
		generated = true
	}

	alreadyPinnedBySameProfile := preflight.Profile == options.profile && preflight.ProfileSource == "local" &&
		beforeProfile.SSHFingerprint != "" && beforeProfile.SSHFingerprint == pair.Fingerprint
	reusedInheritedKey := false
	if pair.PrivatePath != "" {
		// System/global signing keys are always authoritative reuse signals, even
		// on an idempotent rerun. The exemption applies only to the effective
		// repository-local key that this same profile already manages.
		for _, inheritedSigningKey := range inheritedSigningKeys {
			if inheritedKeyMatches(inheritedSigningKey, pair, repository) {
				reusedInheritedKey = true
				break
			}
		}
		if !reusedInheritedKey && !alreadyPinnedBySameProfile && inheritedKeyMatches(preflight.SigningKey, pair, repository) {
			reusedInheritedKey = true
		}
	}
	unverifiableInheritedKey := pair.PrivatePath != "" && sshDefaultKeyCommand
	if reusedInheritedKey && !options.allowKeyReuse {
		hint := "Choose or generate a separate personal key. To intentionally reuse this inherited signing key, pass --allow-key-reuse."
		if generated {
			hint += generatedKeyHint(pair)
		}
		return a.fail(exitUsage, "inherited_key_reuse", errors.New("the selected SSH key is also the repository's inherited signing key"), hint)
	}
	if unverifiableInheritedKey && !options.allowKeyReuse {
		hint := "Choose or generate a separate personal key, or pass --allow-key-reuse only after checking the configured SSH default-key command yourself."
		if generated {
			hint += generatedKeyHint(pair)
		}
		return a.fail(exitUsage, "inherited_key_unverifiable", errors.New("Git has an SSH default-key command, so gitctx cannot prove that the selected key is separate from the inherited signing key"), hint)
	}

	selected := profile.Profile{
		GitName:        options.gitName,
		GitEmail:       options.email,
		GitHubUser:     options.github,
		SSHKey:         pair.PrivatePath,
		SSHFingerprint: pair.Fingerprint,
		DisableSigning: options.signing == "disabled",
	}.Normalize()
	if options.signing == "same-key" {
		selected.SigningKey = pair.PublicPath
		selected.SigningFormat = "ssh"
	}
	if err := selected.Validate(); err != nil {
		hint := ""
		if generated {
			hint = generatedKeyHint(pair)
		}
		return a.fail(exitUsage, "invalid_profile", err, hint)
	}

	var savedConfig configstore.Config
	var configConflict string
	var gitOperationErr error
	err = a.store.WithLock(func() error {
		current, loadErr := a.store.Load()
		if loadErr != nil {
			return loadErr
		}
		currentProfile, existsNow := current.Profiles[options.profile]
		if existsNow != profileExists || (existsNow && currentProfile != beforeProfile) {
			configConflict = "the profile changed"
			return nil
		}
		if existsNow && !options.force {
			configConflict = "the profile now requires update confirmation"
			return nil
		}
		if !sameStrings(automaticRuleDirectories(current, options.profile), baselineAffectedRules) {
			configConflict = "the profile's automatic directory rules changed"
			return nil
		}

		previous := cloneConfig(current)
		current.Profiles[options.profile] = selected
		if saveErr := a.store.Save(current); saveErr != nil {
			return saveErr
		}
		if len(current.Rules) > 0 {
			if syncErr := a.syncRulesWithRollback(previous, current); syncErr != nil {
				return syncErr
			}
		}
		gitOperationErr = a.git.Apply(repository, options.profile, selected)
		if gitOperationErr != nil {
			var rollbackErrors []error
			if restoreErr := a.store.Save(previous); restoreErr != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restore profile store: %w", restoreErr))
			}
			if len(current.Rules) > 0 || len(previous.Rules) > 0 {
				if _, restoreErr := a.autoManager().Sync(previous); restoreErr != nil {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("restore automatic rules: %w", restoreErr))
				}
			}
			if len(rollbackErrors) > 0 {
				gitOperationErr = errors.Join(append([]error{gitOperationErr}, rollbackErrors...)...)
			}
			return gitOperationErr
		}
		savedConfig = current
		return nil
	})
	if configConflict != "" {
		hint := "Run setup again so it can use the latest profile values."
		if generated {
			hint += generatedKeyHint(pair)
		}
		return a.fail(exitProfile, "profile_changed", fmt.Errorf("%s while setup was in progress", configConflict), hint)
	}
	if err != nil {
		hint := ""
		if generated {
			hint = generatedKeyHint(pair)
		}
		if gitOperationErr != nil {
			return a.fail(exitGit, "git_failed", err, hint)
		}
		return a.fail(exitConfig, "config_io", err, hint)
	}

	state, err := a.git.Inspect(repository)
	if err != nil {
		hint := "The profile and repository settings were applied. Run 'gitctx doctor' to verify them."
		if generated {
			hint += generatedKeyHint(pair)
		}
		return a.fail(exitGit, "verification_failed", err, hint)
	}
	state = classifyProfileSource(state, savedConfig, a.store.Path)
	diagnosis := diagnose(state, savedConfig)
	affectedRules := automaticRuleDirectories(savedConfig, options.profile)
	warnings := setupWarnings(options, state, selected, reusedInheritedKey, unverifiableInheritedKey, affectedRules)
	data := setupOutput{
		Name:                     options.profile,
		Profile:                  selected,
		Repository:               state.Repository,
		GeneratedKey:             generated,
		PublicKeyPath:            pair.PublicPath,
		Fingerprint:              pair.Fingerprint,
		ConfigPath:               a.store.Path,
		AutomaticRuleDirectories: affectedRules,
		Diagnosis:                diagnosis,
	}
	if options.json {
		if code := a.succeed(data, warnings); code != exitOK {
			return code
		}
		if diagnosis.Status == "error" {
			return exitUnsafe
		}
		return exitOK
	}

	verb := "Configured"
	if profileExists {
		verb = "Updated"
	}
	fmt.Fprintf(a.out, "%s profile %q for %s.\n", verb, options.profile, escapeDisplayControls(state.Repository))
	fmt.Fprintf(a.out, "  Git author  %s <%s>\n", escapeDisplayControls(selected.GitName), escapeDisplayControls(selected.GitEmail))
	if selected.GitHubUser != "" {
		fmt.Fprintf(a.out, "  GitHub      @%s\n", escapeDisplayControls(selected.GitHubUser))
	}
	if selected.SSHKey == "" {
		fmt.Fprintln(a.out, "  Auth        identity only (not verified by gitctx)")
	} else {
		fmt.Fprintf(a.out, "  SSH key     %s\n", escapeDisplayControls(selected.SSHKey))
		fmt.Fprintf(a.out, "  Public key  %s\n", escapeDisplayControls(pair.PublicPath))
		fmt.Fprintf(a.out, "  Fingerprint %s\n", escapeDisplayControls(pair.Fingerprint))
	}
	if selected.DisableSigning {
		fmt.Fprintln(a.out, "  Signing     blocked for automatic signing and bare -S")
	} else {
		fmt.Fprintln(a.out, "  Signing     enabled with the profile's SSH public key")
	}
	fmt.Fprintln(a.out, "  Global user.name, user.email, and signing settings were not changed.")
	if len(affectedRules) > 0 {
		fmt.Fprintf(a.out, "  Auto rules   synchronized for %d director", len(affectedRules))
		if len(affectedRules) == 1 {
			fmt.Fprintln(a.out, "y")
		} else {
			fmt.Fprintln(a.out, "ies")
		}
	}
	for _, warning := range warnings {
		fmt.Fprintf(a.out, "  Warning     %s\n", escapeDisplayControls(warning.Message))
	}
	if pair.PublicPath != "" {
		account := "the intended Git hosting account"
		if selected.GitHubUser != "" {
			account = "GitHub account @" + selected.GitHubUser
		}
		fmt.Fprintf(a.out, "\nNext: add %s to %s as an authentication key", escapeDisplayControls(pair.PublicPath), escapeDisplayControls(account))
		if selected.SigningKey != "" {
			fmt.Fprint(a.out, " and as a signing key")
		}
		fmt.Fprintln(a.out, ". gitctx did not upload it or test connectivity.")
	}
	fmt.Fprintln(a.out, "\nVerification:")
	for _, item := range diagnosis.Checks {
		fmt.Fprintf(a.out, "  %-4s  %-17s %s\n", checkLabel(item.Status), escapeDisplayControls(item.Name), escapeDisplayControls(item.Message))
	}
	fmt.Fprintf(a.out, "  Result: %s\n", diagnosis.Status)
	if diagnosis.Status == "error" {
		return exitUnsafe
	}
	return exitOK
}

func parseSetup(args []string) (setupOptions, error) {
	options := setupOptions{repo: "."}
	options.githubSet = setupOptionPresent(args, "--github")
	positionals, err := parseOptions(args, map[string]*string{
		"--repo":     &options.repo,
		"--name":     &options.gitName,
		"--email":    &options.email,
		"--github":   &options.github,
		"--auth":     &options.auth,
		"--ssh-key":  &options.sshKey,
		"--key-path": &options.keyPath,
		"--signing":  &options.signing,
	}, map[string]*bool{
		"--force":           &options.force,
		"--allow-key-reuse": &options.allowKeyReuse,
		"--clear-github":    &options.clearGitHub,
		"--json":            &options.json,
		"--help":            &options.help,
		"-h":                &options.help,
	})
	if err != nil {
		return options, err
	}
	if len(positionals) > 1 {
		return options, errors.New("setup accepts one profile name")
	}
	if len(positionals) == 1 {
		options.profile = positionals[0]
	}
	if options.repo == "" {
		return options, errors.New("--repo requires a non-empty path")
	}
	options.auth = strings.ToLower(strings.TrimSpace(options.auth))
	options.signing = strings.ToLower(strings.TrimSpace(options.signing))
	if options.clearGitHub {
		if options.githubSet {
			return options, errors.New("--github and --clear-github cannot be combined")
		}
		options.github = ""
		options.githubSet = true
	}
	return options, nil
}

func setupOptionPresent(args []string, target string) bool {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			return false
		}
		name, _, inline := strings.Cut(arg, "=")
		if name == target {
			return true
		}
		if !inline && optionConsumesValue("setup", name) {
			index++
		}
	}
	return false
}

func validateSetupOptions(options setupOptions) error {
	switch options.auth {
	case "generate":
		if options.sshKey != "" {
			return errors.New("--ssh-key is only valid with --auth existing")
		}
	case "existing":
		if options.sshKey == "" {
			return errors.New("--auth existing requires --ssh-key <private-key-path>")
		}
		if options.keyPath != "" {
			return errors.New("--key-path is only valid with --auth generate")
		}
	case "identity-only":
		if options.sshKey != "" || options.keyPath != "" {
			return errors.New("identity-only setup cannot use --ssh-key or --key-path")
		}
	default:
		return errors.New("--auth must be one of: generate, existing, identity-only")
	}
	switch options.signing {
	case "same-key":
		if options.auth == "identity-only" {
			return errors.New("--signing same-key requires generated or existing SSH authentication")
		}
	case "disabled":
	default:
		return errors.New("--signing must be one of: same-key, disabled")
	}
	return nil
}

func normalizeSetupIdentity(options *setupOptions) error {
	identity := (profile.Profile{
		GitName:    options.gitName,
		GitEmail:   options.email,
		GitHubUser: options.github,
	}).Normalize()
	if err := identity.Validate(); err != nil {
		return err
	}
	options.gitName = identity.GitName
	options.email = identity.GitEmail
	options.github = identity.GitHubUser
	return nil
}

type setupChoice struct {
	Value string
	Label string
}

func (a application) promptSetupValue(label, defaultValue string, required bool) (string, error) {
	if defaultValue == "" {
		fmt.Fprintf(a.out, "%s: ", label)
	} else {
		fmt.Fprintf(a.out, "%s [%s]: ", label, escapeDisplayControls(defaultValue))
	}
	value, err := a.in.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read %s: %w", strings.ToLower(label), err)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		value = defaultValue
	}
	if required && value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return value, nil
}

func (a application) promptSetupChoice(label string, choices []setupChoice, defaultValue string) (string, error) {
	fmt.Fprintf(a.out, "%s:\n", label)
	for index, choice := range choices {
		fmt.Fprintf(a.out, "  %d) %s\n", index+1, choice.Label)
	}
	fmt.Fprintf(a.out, "Choice [%s]: ", defaultValue)
	value, err := a.in.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read %s choice: %w", strings.ToLower(label), err)
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return defaultValue, nil
	}
	for index, choice := range choices {
		if value == choice.Value || value == fmt.Sprintf("%d", index+1) {
			return choice.Value, nil
		}
	}
	return "", fmt.Errorf("invalid %s choice %q", strings.ToLower(label), value)
}

func (a application) promptConfirmation(label string) (bool, error) {
	fmt.Fprintf(a.out, "%s? [y/N]: ", label)
	value, err := a.in.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "y", "yes":
		return true, nil
	case "", "n", "no":
		return false, nil
	default:
		return false, fmt.Errorf("confirmation must be yes or no")
	}
}

func printSetupPlan(w io.Writer, options setupOptions, repository, keyPath string, affectedRules []string) {
	fmt.Fprintln(w, "\nSetup plan:")
	fmt.Fprintf(w, "  Repository  %s\n", escapeDisplayControls(repository))
	fmt.Fprintf(w, "  Profile     %s\n", escapeDisplayControls(options.profile))
	fmt.Fprintf(w, "  Git author  %s <%s>\n", escapeDisplayControls(options.gitName), escapeDisplayControls(options.email))
	if options.github != "" {
		fmt.Fprintf(w, "  GitHub      @%s\n", escapeDisplayControls(options.github))
	} else {
		fmt.Fprintln(w, "  GitHub      -")
	}
	switch options.auth {
	case "generate":
		fmt.Fprintf(w, "  Auth        generate SSH key at %s\n", escapeDisplayControls(keyPath))
	case "existing":
		fmt.Fprintf(w, "  Auth        existing SSH key %s\n", escapeDisplayControls(keyPath))
	default:
		fmt.Fprintln(w, "  Auth        identity only; pushes remain external and unverified")
	}
	if options.signing == "same-key" {
		fmt.Fprintln(w, "  Signing     same SSH key")
	} else {
		fmt.Fprintln(w, "  Signing     block automatic signing and bare -S")
	}
	if len(affectedRules) > 0 {
		fmt.Fprintf(w, "  Auto rules   this profile's identity will also update in %d configured director", len(affectedRules))
		if len(affectedRules) == 1 {
			fmt.Fprintln(w, "y:")
		} else {
			fmt.Fprintln(w, "ies:")
		}
		for _, directory := range affectedRules {
			fmt.Fprintf(w, "               %s\n", escapeDisplayControls(directory))
		}
	}
}

func inheritedKeyMatches(inherited string, pair sshkey.Pair, repository string) bool {
	if inherited == "" {
		return false
	}
	if !strings.HasPrefix(inherited, "key::") && inherited != "~" && !strings.HasPrefix(inherited, "~/") && !filepath.IsAbs(inherited) {
		inherited = filepath.Join(repository, inherited)
	}
	for _, candidate := range []string{pair.PrivatePath, pair.PublicPath} {
		if sameFilesystemPath(inherited, candidate) {
			return true
		}
	}
	if inheritedFingerprint, err := sshkey.Fingerprint(inherited); err == nil && inheritedFingerprint == pair.Fingerprint {
		return true
	}
	return false
}

func sameFilesystemPath(first, second string) bool {
	first, errFirst := gitconfig.ResolvePath(first)
	second, errSecond := gitconfig.ResolvePath(second)
	if errFirst != nil || errSecond != nil {
		return false
	}
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if first == second {
		return true
	}
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	return firstErr == nil && secondErr == nil && os.SameFile(firstInfo, secondInfo)
}

func isTerminalInput(input io.Reader) bool {
	file, ok := input.(*os.File)
	if !ok {
		return false
	}
	return isTerminalFile(file)
}

func generatedKeyHint(pair sshkey.Pair) string {
	return fmt.Sprintf(" The generated key was kept at %s (public key: %s).", pair.PrivatePath, pair.PublicPath)
}

func setupWarnings(options setupOptions, state gitconfig.State, selected profile.Profile, reusedInheritedKey, unverifiableInheritedKey bool, affectedRules []string) []notice {
	warnings := currentWarnings(buildCurrent(state, configstore.Config{Profiles: map[string]profile.Profile{options.profile: selected}}))
	if options.auth == "identity-only" {
		warnings = withoutNotice(warnings, "auth_unverified")
		warnings = append(warnings, notice{Code: "identity_only_auth", Message: "Push authentication is external and was not verified; only identity and the local signing guard are managed."})
	} else {
		warnings = append(warnings, notice{Code: "key_registration_unverified", Message: "The public key was not uploaded and Git-hosting account registration or connectivity was not verified."})
	}
	if options.allowKeyReuse && reusedInheritedKey {
		warnings = append(warnings, notice{Code: "inherited_key_reused", Message: "This profile intentionally reuses an inherited signing key; confirm that this is permitted for both accounts."})
	}
	if options.allowKeyReuse && unverifiableInheritedKey {
		warnings = append(warnings, notice{Code: "inherited_key_reuse_unverified", Message: "An SSH default-key command is configured; gitctx could not verify whether it returns this same key."})
	}
	if len(affectedRules) > 0 {
		warnings = append(warnings, notice{Code: "auto_rules_synchronized", Message: fmt.Sprintf("This profile's automatic identity was synchronized for %d configured director%s.", len(affectedRules), pluralSuffix(len(affectedRules)))})
	}
	return deduplicateNotices(warnings)
}

func withoutNotice(values []notice, code string) []notice {
	result := values[:0]
	for _, value := range values {
		if value.Code != code {
			result = append(result, value)
		}
	}
	return result
}

func automaticRuleDirectories(config configstore.Config, profileName string) []string {
	var directories []string
	for directory, selectedProfile := range config.Rules {
		if selectedProfile == profileName {
			directories = append(directories, directory)
		}
	}
	sort.Strings(directories)
	return directories
}

func sameStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func pluralSuffix(count int) string {
	if count == 1 {
		return "y"
	}
	return "ies"
}

func deduplicateNotices(values []notice) []notice {
	seen := make(map[string]bool, len(values))
	result := make([]notice, 0, len(values))
	for _, value := range values {
		if seen[value.Code] {
			continue
		}
		seen[value.Code] = true
		result = append(result, value)
	}
	return result
}

func printSetupHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  gitctx setup <profile> [options]

Create or update a profile and apply its full SSH/signing context to one
repository. Existing automatic identity rules for that profile are synchronized
and shown before confirmation. The guided flow can generate a separate SSH key,
use an existing key, or manage identity only.
It always makes an explicit repository-local signing choice, and never changes
global Git identity or signing settings. The disabled mode blocks automatic
signing and a bare -S, including fallback through a custom SSH signing program.
Like any local Git setting, a deliberate command-scoped -c override can replace
the guard.

Options:
  --name <name>          Git commit author name
  --email <email>        Git commit author email
  --github <username>    GitHub username metadata
  --clear-github         Remove saved GitHub username metadata
  --repo <path>          Repository to configure (default: current directory)
  --auth <mode>          generate, existing, or identity-only
  --ssh-key <path>       Existing private key; requires --auth existing
  --key-path <path>      Destination for a generated key
  --signing <mode>       same-key or disabled
  --force                Update an existing profile
  --allow-key-reuse      Explicitly allow reuse of an inherited signing key
  --config <path>        Use an explicit profile store
  --json                 Non-interactive JSON; key generation is refused
  --help                 Show this help

In JSON mode, --name, --email, --auth, and --signing are required. Generate keys
interactively so ssh-keygen can request a passphrase without gitctx reading it.`)
}
