// Package profile defines the non-secret metadata stored for a Git identity.
package profile

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var validGitHubUser = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
var validSSHFingerprint = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// Profile describes commit identity and optional repository-scoped SSH/signing
// configuration. Its fields are intended for non-secret metadata only.
type Profile struct {
	GitName         string `json:"git_name"`
	GitEmail        string `json:"git_email"`
	GitHubUser      string `json:"github_user,omitempty"`
	SSHKey          string `json:"ssh_key,omitempty"`
	SSHFingerprint  string `json:"ssh_fingerprint,omitempty"`
	SigningKey      string `json:"signing_key,omitempty"`
	SigningFormat   string `json:"signing_format,omitempty"`
	DisableSigning  bool   `json:"disable_signing,omitempty"`
	ManagedKeyID    string `json:"managed_key_id,omitempty"`
	GitHubAccountID int64  `json:"github_account_id,omitempty"`
	GitHubConnected bool   `json:"github_connected,omitempty"`
}

// ValidateName checks a profile identifier used on the command line.
func ValidateName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("profile name %q must start with a letter or number, be at most 64 characters, and contain only letters, numbers, '.', '_' or '-'", name)
	}
	return nil
}

// Validate checks required commit identity fields.
func (p Profile) Validate() error {
	for label, value := range map[string]string{
		"Git name":        p.GitName,
		"Git email":       p.GitEmail,
		"GitHub username": p.GitHubUser,
		"SSH key path":    p.SSHKey,
		"SSH fingerprint": p.SSHFingerprint,
		"signing key":     p.SigningKey,
		"signing format":  p.SigningFormat,
	} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("%s cannot contain control characters", label)
		}
	}

	if strings.TrimSpace(p.GitName) == "" {
		return fmt.Errorf("Git name is required")
	}
	if strings.ContainsAny(p.GitName, "<>") {
		return fmt.Errorf("Git name cannot contain '<' or '>'")
	}

	email := strings.TrimSpace(p.GitEmail)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return fmt.Errorf("Git email %q is not a valid email address", p.GitEmail)
	}

	if p.GitHubUser != "" && (!validGitHubUser.MatchString(p.GitHubUser) || strings.Contains(p.GitHubUser, "--")) {
		return fmt.Errorf("GitHub username must be 1-39 letters, numbers, or single hyphens and cannot start or end with a hyphen")
	}
	if p.SSHFingerprint != "" && !validSSHFingerprint.MatchString(p.SSHFingerprint) {
		return fmt.Errorf("SSH fingerprint must use the OpenSSH SHA256 format")
	}
	if p.SSHFingerprint != "" && p.SSHKey == "" {
		return fmt.Errorf("SSH fingerprint requires an SSH private-key path")
	}
	if p.SigningFormat != "" {
		switch p.SigningFormat {
		case "ssh", "openpgp", "x509":
		default:
			return fmt.Errorf("signing format must be one of: ssh, openpgp, x509")
		}
		if p.SigningKey == "" {
			return fmt.Errorf("signing format requires a signing key")
		}
	}
	if p.SigningKey != "" && p.SigningFormat == "" {
		return fmt.Errorf("signing key requires a signing format")
	}
	if p.DisableSigning && (p.SigningKey != "" || p.SigningFormat != "") {
		return fmt.Errorf("disabled signing cannot be combined with a signing key or format")
	}
	if p.ManagedKeyID != "" {
		if len(p.ManagedKeyID) != 32 || strings.Trim(p.ManagedKeyID, "0123456789abcdef") != "" || p.SSHKey == "" || p.SSHFingerprint == "" || p.GitHubUser == "" || p.GitHubAccountID <= 0 {
			return fmt.Errorf("managed keys require a valid vault identifier, pinned SSH key and GitHub account")
		}
	}
	if p.GitHubConnected && p.ManagedKeyID == "" {
		return fmt.Errorf("native connection state requires a managed key")
	}

	return nil
}

// Normalize trims user input and accepts GitHub usernames with a leading @.
func (p Profile) Normalize() Profile {
	p.GitName = strings.TrimSpace(p.GitName)
	p.GitEmail = strings.TrimSpace(p.GitEmail)
	p.GitHubUser = strings.TrimPrefix(strings.TrimSpace(p.GitHubUser), "@")
	p.SSHKey = strings.TrimSpace(p.SSHKey)
	p.SSHFingerprint = strings.TrimSpace(p.SSHFingerprint)
	p.SigningKey = strings.TrimSpace(p.SigningKey)
	p.SigningFormat = strings.ToLower(strings.TrimSpace(p.SigningFormat))
	return p
}
