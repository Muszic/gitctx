package cli

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
	editRequested := setupEditRequested(args)
	options, err := parseSetup(args)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Run 'gitctx setup --help' for usage.")
	}
	if options.help {
		printSetupHelp(a.out)
		return exitOK
	}
	if options.profile == "" {
		if !options.json && isTerminalInput(a.rawIn) {
			options.profile, err = a.promptSetupValue("Profile name", "personal", true)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
		} else {
			return a.fail(exitUsage, "invalid_usage", errors.New("setup requires a profile name"), "Example: gitctx setup personal")
		}
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
		return a.fail(exitGit, "not_git_repository", friendlyRepositoryError(err), "Change into a Git repository, or run: gitctx setup personal --repo <path>")
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
		defaultAction := "apply"
		if editRequested {
			defaultAction = "edit"
		}
		action, promptErr := a.promptSetupChoice("What would you like to do", []setupChoice{
			{Value: "apply", Label: "Apply this saved profile without changing it (recommended)"},
			{Value: "edit", Label: "Edit the profile, then apply it"},
			{Value: "cancel", Label: "Cancel"},
		}, defaultAction)
		if promptErr != nil {
			return a.fail(exitUsage, "setup_cancelled", promptErr, "No profile, key, or Git setting was changed.")
		}
		if action == "cancel" {
			fmt.Fprintln(a.out, "Setup cancelled. Nothing was changed.")
			return exitOK
		}
		if action == "apply" {
			if beforeProfile.SSHKey != "" {
				if code, remoteErr, hint := setupSSHRemoteError(preflight); remoteErr != nil {
					return a.fail(exitGit, code, remoteErr, hint)
				}
			}
			code := a.use([]string{options.profile, "--repo", repository})
			if code == exitOK {
				if _, registrationErr := a.offerKeyRegistration(options.profile, beforeProfile, preflight); registrationErr != nil {
					return a.fail(exitUnsafe, "key_registration_failed", registrationErr, "Local setup was kept. Retry with 'gitctx connect <profile>' or register the public key manually.")
				}
			}
			return code
		}
		options.force = true
		interactive = true
	}

	if !options.json {
		if interactive {
			printSetupIntroduction(a.out, options.profile, repository, preflight.EffectivePushURLs(), baselineAffectedRules)
		}
		if options.gitName == "" {
			options.gitName, err = a.promptValidatedSetupValue("Commit author name", beforeProfile.GitName, true, validateSetupGitName)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
		}
		if options.email == "" {
			options.email, err = a.promptValidatedSetupValue("Commit author email", beforeProfile.GitEmail, true, validateSetupGitEmail)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
		}
		if interactive && !options.githubSet {
			options.github, err = a.promptValidatedSetupValue("GitHub username (optional; confirms the key-registration account)", beforeProfile.GitHubUser, false, validateSetupGitHubUser)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
			options.githubSet = true
		}
		if err := normalizeSetupIdentity(&options); err != nil {
			return a.fail(exitUsage, "invalid_profile", err, "Fix the commit identity before choosing authentication.")
		}
		if options.auth == "" {
			defaultAuth := "generate"
			if beforeProfile.SSHKey != "" {
				defaultAuth = "existing"
			} else if beforeProfile.DisableSigning {
				defaultAuth = "identity-only"
			} else if !profileExists && len(preflight.EffectivePushURLs()) > 0 && !allSSHRemotes(preflight.EffectivePushURLs()) {
				defaultAuth = "identity-only"
			}
			fmt.Fprintln(a.out, "\nPush account:")
			fmt.Fprintln(a.out, "  A separate SSH key prevents this repository from silently using a different account.")
			authChoices := []setupChoice{
				{Value: "generate", Label: "Create a separate SSH key for this profile (recommended)"},
				{Value: "existing", Label: "Use an SSH key already on this computer"},
				{Value: "identity-only", Label: "Configure commit identity only (push account stays external)"},
			}
			if len(preflight.EffectivePushURLs()) > 0 && !allSSHRemotes(preflight.EffectivePushURLs()) {
				authChoices[0].Label = "Create a separate SSH key (requires changing this remote to SSH first)"
				authChoices[1].Label = "Use an existing SSH key (requires changing this remote to SSH first)"
				authChoices[2].Label = "Configure commit identity only (recommended for the current remote)"
			}
			options.auth, err = a.promptSetupChoice("How should Git authenticate pushes", authChoices, defaultAuth)
			if err != nil {
				return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
			}
		}
		if options.auth == "generate" || options.auth == "existing" {
			if code, remoteErr, hint := setupSSHRemoteError(preflight); remoteErr != nil {
				return a.fail(exitGit, code, remoteErr, hint)
			}
		}
		if options.auth == "existing" && options.sshKey == "" {
			defaultSSHKey := beforeProfile.SSHKey
			for {
				options.sshKey, err = a.promptSetupValue("Private SSH key path (not the .pub file)", defaultSSHKey, true)
				if err != nil {
					return a.fail(exitUsage, "setup_cancelled", err, "Nothing was changed.")
				}
				if _, inspectErr := sshkey.InspectPair(options.sshKey); inspectErr == nil {
					break
				} else {
					fmt.Fprintf(a.out, "  Please try again: %s\n", escapeDisplayControls(inspectErr.Error()))
					defaultSSHKey = ""
				}
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
				fmt.Fprintln(a.out, "\nCommit verification: signing will be disabled here so an inherited work key cannot be used accidentally.")
			} else {
				defaultSigning := "same-key"
				if beforeProfile.DisableSigning {
					defaultSigning = "disabled"
				}
				fmt.Fprintln(a.out, "\nCommit verification:")
				fmt.Fprintln(a.out, "  Signed commits can be shown as Verified by GitHub after the public key is registered there.")
				options.signing, err = a.promptSetupChoice("How should commits be handled", []setupChoice{
					{Value: "same-key", Label: "Sign commits with this profile's SSH key (recommended)"},
					{Value: "disabled", Label: "Do not sign commits in this repository"},
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
		if code, remoteErr, hint := setupSSHRemoteError(preflight); remoteErr != nil {
			return a.fail(exitGit, code, remoteErr, hint)
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
		fmt.Fprintln(a.out, "\nCreating the SSH key")
		fmt.Fprintln(a.out, "  ssh-keygen will show a protected temporary path; gitctx moves the finished key to the path you chose.")
		fmt.Fprintln(a.out, "  A passphrase is recommended. It is read directly by ssh-keygen and is never seen or stored by gitctx.")
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

	fmt.Fprintf(a.out, "\nLocal setup complete for %s\n", escapeDisplayControls(state.Repository))
	fmt.Fprintf(a.out, "  Profile     %s\n", escapeDisplayControls(options.profile))
	fmt.Fprintf(a.out, "  Commits     %s <%s>\n", escapeDisplayControls(selected.GitName), escapeDisplayControls(selected.GitEmail))
	if selected.GitHubUser != "" {
		fmt.Fprintf(a.out, "  GitHub      @%s\n", escapeDisplayControls(selected.GitHubUser))
	}
	if selected.SSHKey == "" {
		fmt.Fprintln(a.out, "  Pushes      account remains external and is not checked by gitctx")
	} else {
		fmt.Fprintf(a.out, "  Pushes      use this profile's separate SSH key\n")
		fmt.Fprintf(a.out, "  Private key %s\n", escapeDisplayControls(selected.SSHKey))
		fmt.Fprintf(a.out, "  Public key  %s\n", escapeDisplayControls(pair.PublicPath))
		fmt.Fprintf(a.out, "  Fingerprint %s\n", escapeDisplayControls(pair.Fingerprint))
	}
	if selected.DisableSigning {
		fmt.Fprintln(a.out, "  Signing     disabled here; an inherited work signing key will not be used")
	} else {
		fmt.Fprintln(a.out, "  Signing     enabled with this profile's SSH key")
	}
	fmt.Fprintln(a.out, "  Global Git  work identity and signing defaults were not changed")
	if len(affectedRules) > 0 {
		fmt.Fprintf(a.out, "  Auto rules   synchronized for %d director", len(affectedRules))
		if len(affectedRules) == 1 {
			fmt.Fprintln(a.out, "y")
		} else {
			fmt.Fprintln(a.out, "ies")
		}
	}
	printSetupCheckSummary(a.out, diagnosis)
	for _, warning := range setupVisibleWarnings(warnings) {
		fmt.Fprintf(a.out, "  Note        %s\n", escapeDisplayControls(warning.Message))
	}
	if pair.PublicPath != "" {
		connected := false
		if diagnosis.Status != "error" {
			var registrationErr error
			connected, registrationErr = a.offerKeyRegistration(options.profile, selected, state)
			if registrationErr != nil {
				printKeyRegistrationSteps(a.out, selected, pair.PublicPath, state)
				return a.fail(exitUnsafe, "key_registration_failed", registrationErr, "Local setup was kept. Retry with 'gitctx connect <profile>' or register the public key manually.")
			}
		}
		if !connected {
			printKeyRegistrationSteps(a.out, selected, pair.PublicPath, state)
		}
	} else {
		fmt.Fprintln(a.out, "\nReady to commit with this identity. Pushes may still use credentials managed outside gitctx.")
	}
	if diagnosis.Status == "error" {
		fmt.Fprintf(a.out, "\nReview the failed checks: gitctx doctor --repo %s\n", shellDisplayQuote(state.Repository))
	}
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

func setupEditRequested(args []string) bool {
	for _, option := range []string{
		"--name", "--email", "--github", "--clear-github", "--auth",
		"--ssh-key", "--key-path", "--signing", "--allow-key-reuse",
	} {
		if setupOptionPresent(args, option) {
			return true
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

func printSetupIntroduction(w io.Writer, profileName, repository string, pushURLs, affectedRules []string) {
	fmt.Fprintf(w, "\nSet up %q for this repository\n", escapeDisplayControls(profileName))
	fmt.Fprintf(w, "  Repository  %s\n", escapeDisplayControls(repository))
	if len(pushURLs) > 0 {
		for index, remote := range pushURLs {
			service, transport := describeRemote(remote)
			label := "Push remote"
			if index > 0 {
				label = ""
			}
			fmt.Fprintf(w, "  %-12s%s over %s: %s\n", label, escapeDisplayControls(service), escapeDisplayControls(transport), displayRemote(remote))
		}
		if !allSSHRemotes(pushURLs) {
			fmt.Fprintln(w, "              a repository-specific SSH key will work only after this remote is changed to SSH")
		}
	} else {
		fmt.Fprintln(w, "  Pushes to   no remote is configured yet")
	}
	if len(affectedRules) == 0 {
		fmt.Fprintln(w, "  Scope       only this repository; your global work identity and signing defaults stay unchanged")
	} else {
		fmt.Fprintf(w, "  Scope       this repository; %d existing automatic identity rule", len(affectedRules))
		if len(affectedRules) == 1 {
			fmt.Fprintln(w, " will also be synchronized after confirmation")
		} else {
			fmt.Fprintln(w, "s will also be synchronized after confirmation")
		}
		fmt.Fprintln(w, "              your global work identity and signing defaults stay unchanged")
	}
	fmt.Fprintln(w, "\nA profile keeps three things aligned:")
	fmt.Fprintln(w, "  Commits     the name and email recorded in history")
	fmt.Fprintln(w, "  Pushes      the account key used to reach the remote")
	fmt.Fprintln(w, "  Signing     proof that a commit came from this profile")
}

func describeRemote(remote string) (string, string) {
	if host, ok := gitconfig.SSHRemoteHost(remote); ok {
		return hostingService(host), "SSH"
	}
	parsed, err := url.Parse(remote)
	if err == nil && parsed.Hostname() != "" {
		transport := strings.ToUpper(parsed.Scheme)
		if transport == "" {
			transport = "a non-SSH transport"
		}
		return hostingService(parsed.Hostname()), transport
	}
	return "Git hosting", "a non-SSH transport"
}

func setupSSHRemoteError(state gitconfig.State) (string, error, string) {
	pushURLs := state.EffectivePushURLs()
	if (state.PushRemoteExplicit || state.PushRemote != "") && len(pushURLs) == 0 {
		return "push_remote_unresolved", errors.New("the configured default push destination is not a resolvable remote"), "Fix the repository's push remote, or choose identity-only setup."
	}
	if len(pushURLs) == 0 || allSSHRemotes(pushURLs) {
		return "", nil, ""
	}
	remoteName := state.PushRemote
	if remoteName == "" {
		remoteName = "origin"
	}
	problem := fmt.Errorf("push remote %q uses %s; a repository-specific SSH key would not be used", remoteName, strings.Join(displayRemotes(pushURLs), ", "))
	hint := "Change this remote to the SSH URL for the same repository, or choose identity-only setup. gitctx did not rewrite the remote."
	if len(pushURLs) == 1 {
		if converted, ok := sshConversionURL(pushURLs[0]); ok {
			hint = fmt.Sprintf("Change the push URL explicitly with: git remote set-url --push %s %s — or choose identity-only setup. gitctx did not rewrite the remote.", shellDisplayQuote(remoteName), shellDisplayQuote(converted))
		}
	}
	return "non_ssh_remote", problem, hint
}

func sshConversionURL(remote string) (string, bool) {
	parsed, err := url.Parse(remote)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	switch host {
	case "github.com", "gitlab.com", "bitbucket.org":
	default:
		return "", false
	}
	path := strings.TrimPrefix(parsed.EscapedPath(), "/")
	lowerPath := strings.ToLower(path)
	if path == "" || strings.Contains(lowerPath, "%2f") || strings.Contains(lowerPath, "%5c") {
		return "", false
	}
	decodedPath, err := url.PathUnescape(path)
	if err != nil || strings.ContainsAny(decodedPath, "\\\r\n") {
		return "", false
	}
	segments := strings.Split(strings.TrimSuffix(decodedPath, "/"), "/")
	if len(segments) < 2 {
		return "", false
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", false
		}
	}
	if (host == "github.com" || host == "bitbucket.org") && len(segments) != 2 {
		return "", false
	}
	if host == "gitlab.com" {
		for _, segment := range segments {
			if segment == "-" {
				return "", false
			}
		}
	}
	return "git@" + host + ":" + decodedPath, true
}

func validateSetupGitName(value string) error {
	return (profile.Profile{GitName: value, GitEmail: "gitctx@example.com"}).Normalize().Validate()
}

func validateSetupGitEmail(value string) error {
	return (profile.Profile{GitName: "gitctx user", GitEmail: value}).Normalize().Validate()
}

func validateSetupGitHubUser(value string) error {
	return (profile.Profile{GitName: "gitctx user", GitEmail: "gitctx@example.com", GitHubUser: value}).Normalize().Validate()
}

func (a application) promptValidatedSetupValue(label, defaultValue string, required bool, validate func(string) error) (string, error) {
	for {
		value, err := a.promptSetupValue(label, defaultValue, required)
		if err != nil {
			return "", err
		}
		if err := validate(value); err != nil {
			fmt.Fprintf(a.out, "  Please try again: %s\n", escapeDisplayControls(err.Error()))
			defaultValue = ""
			continue
		}
		return value, nil
	}
}

func (a application) promptSetupValue(label, defaultValue string, required bool) (string, error) {
	for {
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
			fmt.Fprintln(a.out, "  A value is required. Please try again.")
			continue
		}
		return value, nil
	}
}

func (a application) promptSetupChoice(label string, choices []setupChoice, defaultValue string) (string, error) {
	defaultChoice := defaultValue
	for index, choice := range choices {
		if choice.Value == defaultValue {
			defaultChoice = fmt.Sprintf("%d", index+1)
			break
		}
	}
	for {
		fmt.Fprintf(a.out, "%s:\n", label)
		for index, choice := range choices {
			fmt.Fprintf(a.out, "  %d) %s\n", index+1, choice.Label)
		}
		fmt.Fprintf(a.out, "Choice [%s]: ", defaultChoice)
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
		fmt.Fprintf(a.out, "  Please choose a number from 1 to %d.\n", len(choices))
	}
}

func (a application) promptConfirmation(label string) (bool, error) {
	for {
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
			fmt.Fprintln(a.out, "  Please answer yes or no.")
		}
	}
}

func printSetupPlan(w io.Writer, options setupOptions, repository, keyPath string, affectedRules []string) {
	fmt.Fprintln(w, "\nReady to apply:")
	fmt.Fprintf(w, "  Repository  %s\n", escapeDisplayControls(repository))
	fmt.Fprintf(w, "  Profile     %s\n", escapeDisplayControls(options.profile))
	fmt.Fprintf(w, "  Commits     %s <%s>\n", escapeDisplayControls(options.gitName), escapeDisplayControls(options.email))
	fmt.Fprintln(w, "              this email is stored in commit history and may become public")
	if options.github != "" {
		fmt.Fprintf(w, "  GitHub      @%s\n", escapeDisplayControls(options.github))
	} else {
		fmt.Fprintln(w, "  GitHub      -")
	}
	switch options.auth {
	case "generate":
		fmt.Fprintf(w, "  Pushes      create a separate SSH key at %s\n", escapeDisplayControls(keyPath))
	case "existing":
		fmt.Fprintf(w, "  Pushes      use existing SSH key %s\n", escapeDisplayControls(keyPath))
	default:
		fmt.Fprintln(w, "  Pushes      stay external and are not checked by gitctx")
	}
	if options.signing == "same-key" {
		fmt.Fprintln(w, "  Signing     sign commits with this profile's SSH key")
	} else {
		fmt.Fprintln(w, "  Signing     disabled here so an inherited work key is not used")
	}
	fmt.Fprintln(w, "  Global Git  work identity and signing defaults stay unchanged")
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

func printSetupCheckSummary(w io.Writer, result diagnosis) {
	counts := map[string]int{}
	for _, item := range result.Checks {
		counts[item.Status]++
	}
	fmt.Fprintf(w, "  Local check %d passed", counts[statusPass])
	if counts[statusWarn] > 0 {
		fmt.Fprintf(w, ", %d warning", counts[statusWarn])
		if counts[statusWarn] != 1 {
			fmt.Fprint(w, "s")
		}
	}
	if counts[statusFail] > 0 {
		fmt.Fprintf(w, ", %d failed", counts[statusFail])
	}
	fmt.Fprintln(w)
	for _, item := range result.Checks {
		if item.Status == statusFail {
			fmt.Fprintf(w, "  FAIL        %s: %s\n", escapeDisplayControls(item.Name), escapeDisplayControls(item.Message))
		} else if item.ID == "ssh_route" && item.Status == statusWarn && strings.Contains(item.Message, "Host alias") {
			fmt.Fprintf(w, "  WARN        %s: %s\n", escapeDisplayControls(item.Name), escapeDisplayControls(item.Message))
		}
	}
	fmt.Fprintln(w, "  Details     run 'gitctx doctor' for the full local checklist")
}

func printKeyRegistrationSteps(w io.Writer, selected profile.Profile, publicKeyPath string, state gitconfig.State) {
	targets := registrationDestinations(state.EffectivePushURLs(), selected.GitHubUser != "")
	fmt.Fprintln(w, "\nFinish connecting this profile key")
	if selected.GitHubUser != "" {
		fmt.Fprintf(w, "  Expected GitHub account: @%s (saved as guidance, not used to log in)\n", escapeDisplayControls(selected.GitHubUser))
	}
	fmt.Fprintln(w, "  The public key is safe to share. Never upload or copy the private key.")
	fmt.Fprintln(w, "  1. Copy the public key:")
	fmt.Fprintf(w, "       %s\n", publicKeyCopyCommand(publicKeyPath))
	step := 2
	for _, target := range targets {
		if target.SettingsURL != "" {
			fmt.Fprintf(w, "  %d. Open %s\n", step, target.SettingsURL)
			fmt.Fprintf(w, "     Add the copied key as an Authentication Key for %s.\n", escapeDisplayControls(target.Service))
		} else {
			fmt.Fprintf(w, "  %d. Add the copied key as an Authentication Key in your %s account.\n", step, escapeDisplayControls(target.Service))
		}
		step++
		if selected.SigningKey != "" {
			if target.SeparateSigningKey {
				fmt.Fprintf(w, "  %d. Add the same public key to %s a second time as a Signing Key.\n", step, escapeDisplayControls(target.Service))
			} else {
				fmt.Fprintf(w, "  %d. Commit signing is enabled locally; follow %s's SSH signing-key instructions if it requires separate registration.\n", step, escapeDisplayControls(target.Service))
			}
			step++
		}
	}
	if len(state.EffectivePushURLs()) == 0 {
		fmt.Fprintf(w, "  %d. Add a default SSH remote for this repository", step)
		if selected.GitHubUser != "" {
			fmt.Fprintln(w, ", replacing REPOSITORY:")
			fmt.Fprintf(w, "       git remote add origin %s\n", shellDisplayQuote("git@github.com:"+selected.GitHubUser+"/REPOSITORY.git"))
		} else {
			fmt.Fprintln(w, ".")
		}
		step++
	}
	fmt.Fprintf(w, "  %d. Check the connection without pushing anything:\n", step)
	fmt.Fprintf(w, "       gitctx verify --repo %s\n", shellDisplayQuote(state.Repository))
}

type registrationTarget struct {
	Service            string
	SettingsURL        string
	SeparateSigningKey bool
}

func registrationDestinations(remotes []string, hasGitHubMetadata bool) []registrationTarget {
	var result []registrationTarget
	seen := map[string]bool{}
	for _, remote := range remotes {
		host, ok := gitconfig.SSHRemoteHost(remote)
		if !ok {
			continue
		}
		host = strings.ToLower(host)
		target := registrationTarget{Service: hostingService(host)}
		switch strings.ToLower(host) {
		case "github.com", "ssh.github.com":
			target.SettingsURL = "https://github.com/settings/ssh/new"
			target.SeparateSigningKey = true
		case "gitlab.com":
			target.SettingsURL = "https://gitlab.com/-/user_settings/ssh_keys"
		case "bitbucket.org":
			target.SettingsURL = "https://bitbucket.org/account/settings/ssh-keys/"
		}
		key := host
		if target.SettingsURL != "" {
			key = target.SettingsURL
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, target)
	}
	if len(result) == 0 {
		if hasGitHubMetadata {
			return []registrationTarget{{Service: "GitHub", SettingsURL: "https://github.com/settings/ssh/new", SeparateSigningKey: true}}
		}
		return []registrationTarget{{Service: "Git hosting"}}
	}
	return result
}

func setupVisibleWarnings(warnings []notice) []notice {
	result := make([]notice, 0, len(warnings))
	for _, warning := range warnings {
		switch warning.Code {
		case "key_registration_unverified", "push_remote_missing", "ssh_routing_unverified":
			continue
		default:
			result = append(result, warning)
		}
	}
	return result
}

func publicKeyCopyCommand(path string) string {
	quoted := shellDisplayQuote(path)
	if runtime.GOOS == "darwin" {
		return "pbcopy < " + quoted
	}
	return "cat " + quoted
}

func inheritedKeyMatches(inherited string, pair sshkey.Pair, repository string) bool {
	if inherited == "" {
		return false
	}
	if !strings.HasPrefix(inherited, "key::") && !gitconfig.IsHomeRelativePath(inherited) && !filepath.IsAbs(inherited) {
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

Run this inside a repository for a guided first-time setup. It explains and
aligns the commit name/email, push account key, and commit-signing key. The flow
detects the default remote, previews every change, and can create a separate SSH
key, reuse an existing key, or configure commit identity only. In a terminal,
omitting <profile> prompts with "personal" as the example/default.

SSH authentication and signing are configured only for the selected repository.
Global work identity and signing defaults are not changed. Existing automatic
identity rules for an edited profile are shown and synchronized. After
registering an SSH public key with the hosting account, run 'gitctx verify' for
a read-only connection check. Interactive GitHub setup offers public-key
registration using an existing GitHub CLI login. Retry it later with
'gitctx connect <profile>'. JSON setup never uploads keys.

Options:
  --name <name>          Git commit author name
  --email <email>        Git commit author email
  --github <username>    Expected GitHub account for key registration
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
