package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gitctx/internal/gitconfig"
	"gitctx/internal/sshkey"
)

type verifyOptions struct {
	repo string
	json bool
	help bool
}

type remoteVerification struct {
	Remote  string `json:"remote"`
	Host    string `json:"host"`
	Service string `json:"service"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type verifyOutput struct {
	Repository    string               `json:"repository"`
	Profile       string               `json:"profile,omitempty"`
	GitHubUser    string               `json:"github_user,omitempty"`
	PublicKeyPath string               `json:"public_key_path,omitempty"`
	Fingerprint   string               `json:"ssh_fingerprint,omitempty"`
	Status        string               `json:"status"`
	Reason        string               `json:"reason,omitempty"`
	Local         diagnosis            `json:"local"`
	Remotes       []remoteVerification `json:"remotes,omitempty"`
}

func (a application) verify(args []string) int {
	options, err := parseVerify(args)
	if err != nil {
		return a.fail(exitUsage, "invalid_usage", err, "Run 'gitctx verify --help' for usage.")
	}
	if options.help {
		printVerifyHelp(a.out)
		return exitOK
	}

	state, err := a.git.Inspect(options.repo)
	if err != nil {
		return a.fail(exitGit, "not_git_repository", friendlyRepositoryError(err), "Change into a Git repository, or pass --repo <path>.")
	}
	config, err := a.store.Load()
	if err != nil {
		return a.fail(exitConfig, "config_invalid", err, "")
	}
	state = classifyProfileSource(state, config, a.store.Path)
	local := diagnose(state, config)
	data := verifyOutput{
		Repository: state.Repository,
		Profile:    state.Profile,
		Status:     "not_ready",
		Local:      local,
	}

	selected, found := config.Profiles[state.Profile]
	if found {
		data.GitHubUser = selected.GitHubUser
		data.Fingerprint = selected.SSHFingerprint
		if selected.SSHKey != "" {
			if pair, pairErr := sshkey.InspectPair(selected.SSHKey); pairErr == nil {
				data.PublicKeyPath = pair.PublicPath
			}
		}
	}

	var reason string
	switch {
	case !found:
		reason = "The selected profile is missing from the profile store."
	case local.Status == "error":
		reason = "The repository's local profile settings are not safe yet."
	case state.ProfileSource != "local":
		reason = fmt.Sprintf("Run 'gitctx use %s' first so this repository uses the profile's SSH key.", state.Profile)
	case selected.SSHKey == "":
		reason = "This profile manages commit identity only, so there is no SSH key to verify."
	case state.SSHOverrideSet:
		reason = "An SSH environment override would bypass the repository-specific key."
	}

	pushURLs := state.EffectivePushURLs()
	if reason == "" && len(pushURLs) == 0 {
		reason = "No default push remote is configured. Add an SSH remote, then run verify again."
	}
	if reason == "" && !allSSHRemotes(pushURLs) {
		reason = "The default push destination is not entirely SSH, so the profile key cannot be verified."
	}
	if reason == "" {
		for _, remote := range pushURLs {
			host, _ := gitconfig.SSHRemoteHost(remote)
			service := hostingService(host)
			item := remoteVerification{
				Remote:  displayRemote(remote),
				Host:    host,
				Service: service,
				Status:  statusPass,
				Message: fmt.Sprintf("the profile key can read this %s remote", service),
			}
			if accessErr := a.git.VerifyRemoteAccess(state.Repository, remote, state.SSHCommand); accessErr != nil {
				item.Status = statusFail
				item.Message = fmt.Sprintf("the profile key could not read this %s remote", service)
				reason = remoteAccessHint(accessErr)
			}
			data.Remotes = append(data.Remotes, item)
		}
	}
	if reason == "" {
		data.Status = "ready"
		data.Local = markLiveRoutingVerified(data.Local)
	} else {
		data.Reason = reason
	}

	warnings := currentWarnings(buildCurrent(state, config))
	if data.Status == "ready" {
		warnings = withoutNotice(warnings, "ssh_routing_unverified")
	}
	if options.json {
		if code := a.succeed(data, warnings); code != exitOK {
			return code
		}
		if data.Status != "ready" {
			return exitUnsafe
		}
		return exitOK
	}

	printVerifyResult(a.out, data, reason)
	if data.Status != "ready" {
		return exitUnsafe
	}
	return exitOK
}

func markLiveRoutingVerified(local diagnosis) diagnosis {
	for index := range local.Checks {
		if local.Checks[index].ID == "ssh_route" && local.Checks[index].Status == statusWarn {
			local.Checks[index].Status = statusPass
			local.Checks[index].Message = "a live read-only check reached every default SSH remote with the profile key"
		}
	}
	local.Status = diagnosisStatus(local.Checks)
	return local
}

func parseVerify(args []string) (verifyOptions, error) {
	options := verifyOptions{repo: "."}
	positionals, err := parseOptions(args, map[string]*string{
		"--repo": &options.repo,
	}, map[string]*bool{
		"--json": &options.json,
		"--help": &options.help,
		"-h":     &options.help,
	})
	if err != nil {
		return options, err
	}
	if len(positionals) != 0 {
		return options, errors.New("verify does not accept positional arguments")
	}
	if options.repo == "" {
		return options, errors.New("--repo requires a non-empty path")
	}
	return options, nil
}

func hostingService(host string) string {
	switch strings.ToLower(host) {
	case "github.com", "ssh.github.com":
		return "GitHub"
	case "gitlab.com":
		return "GitLab"
	case "bitbucket.org":
		return "Bitbucket"
	default:
		if host == "" {
			return "Git"
		}
		return host
	}
}

func remoteAccessHint(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "timed out"):
		return "The connection timed out. Check the network and SSH host, then retry."
	case strings.Contains(message, "permission denied"), strings.Contains(message, "publickey"):
		return "The host rejected this key. Register the public key with the intended account; if it has a passphrase, load it with ssh-add, then retry."
	case strings.Contains(message, "host key verification failed"):
		return "SSH does not trust this host yet. Verify the host fingerprint in a normal SSH connection, then retry."
	default:
		return "Remote access failed. Check the remote URL, network, key registration, and ssh-agent, then retry."
	}
}

func shellDisplayQuote(value string) string {
	value = escapeDisplayControls(value)
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func printVerifyResult(w io.Writer, data verifyOutput, reason string) {
	fmt.Fprintln(w, "Connection check")
	fmt.Fprintf(w, "  Repository  %s\n", escapeDisplayControls(data.Repository))
	fmt.Fprintf(w, "  Profile     %s\n", escapeDisplayControls(valueOrDash(data.Profile)))
	if data.GitHubUser != "" {
		fmt.Fprintf(w, "  Expected    GitHub account @%s (profile metadata only)\n", escapeDisplayControls(data.GitHubUser))
	}
	if data.Local.Status == "error" {
		fmt.Fprintln(w, "  FAIL        local identity, SSH, or signing settings need attention")
	} else if data.Local.Status == "warning" {
		fmt.Fprintln(w, "  WARN        local settings are aligned, with details to review in 'gitctx doctor'")
	} else {
		fmt.Fprintln(w, "  PASS        local identity, SSH, and signing settings are aligned")
	}
	for _, remote := range data.Remotes {
		fmt.Fprintf(w, "  %-4s        %s access: %s\n", checkLabel(remote.Status), escapeDisplayControls(remote.Service), escapeDisplayControls(remote.Remote))
	}
	if data.Status == "ready" {
		fmt.Fprintln(w, "\nReady: the repository-specific key can read every default SSH remote.")
		fmt.Fprintln(w, "This was a read-only check; it did not push and does not prove write permission or which account owns the key.")
		return
	}
	fmt.Fprintf(w, "\nNot ready: %s\n", escapeDisplayControls(reason))
	if data.PublicKeyPath != "" {
		fmt.Fprintf(w, "  Public key  %s\n", escapeDisplayControls(data.PublicKeyPath))
	}
	fmt.Fprintf(w, "  Retry       gitctx verify --repo %s\n", shellDisplayQuote(data.Repository))
}

func printVerifyHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  gitctx verify [options]

Check the repository's saved identity, SSH key, and signing policy, then make a
read-only connection to every default SSH push URL. This proves that the
repository-specific key can access the remote now. It does not push, upload a
key, change Git settings, or permanently cache the result.

Options:
  --repo <path>    Repository to check (default: current directory)
  --config <path>  Use an explicit profile store
  --json           Emit machine-readable JSON
  --help           Show this help`)
}
