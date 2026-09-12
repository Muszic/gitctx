package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProfileValidation(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		wantErr bool
	}{
		{name: "valid", profile: Profile{GitName: "Ada Lovelace", GitEmail: "ada@example.com"}},
		{name: "valid GitHub username", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", GitHubUser: "ada-lovelace"}},
		{name: "valid SSH fingerprint", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SSHKey: "/keys/personal", SSHFingerprint: "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"}},
		{name: "signing key without format", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningKey: "ABC123"}, wantErr: true},
		{name: "valid SSH signing format", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningKey: "key.pub", SigningFormat: "ssh"}},
		{name: "valid OpenPGP signing format", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningKey: "ABC123", SigningFormat: "openpgp"}},
		{name: "valid X.509 signing format", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningKey: "ABC123", SigningFormat: "x509"}},
		{name: "valid disabled signing", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", DisableSigning: true}},
		{name: "missing name", profile: Profile{GitEmail: "ada@example.com"}, wantErr: true},
		{name: "unsafe angle bracket in name", profile: Profile{GitName: "Ada <work>", GitEmail: "ada@example.com"}, wantErr: true},
		{name: "invalid email", profile: Profile{GitName: "Ada", GitEmail: "not-an-email"}, wantErr: true},
		{name: "unsafe email", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com\nother@example.com"}, wantErr: true},
		{name: "unsafe key path", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SSHKey: "key\nother"}, wantErr: true},
		{name: "invalid SSH fingerprint algorithm", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SSHFingerprint: "MD5:00:11:22"}, wantErr: true},
		{name: "invalid SSH fingerprint length", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SSHFingerprint: "SHA256:short"}, wantErr: true},
		{name: "SSH fingerprint without key", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SSHFingerprint: "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"}, wantErr: true},
		{name: "terminal control", profile: Profile{GitName: "Ada\x1b[2J", GitEmail: "ada@example.com"}, wantErr: true},
		{name: "token-like GitHub value", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", GitHubUser: "ghp_example"}, wantErr: true},
		{name: "GitHub username starts hyphen", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", GitHubUser: "-ada"}, wantErr: true},
		{name: "GitHub username consecutive hyphens", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", GitHubUser: "ada--lovelace"}, wantErr: true},
		{name: "GitHub username too long", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", GitHubUser: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, wantErr: true},
		{name: "conflicting signing policy", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningKey: "ABC123", DisableSigning: true}, wantErr: true},
		{name: "conflicting signing format policy", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningFormat: "ssh", DisableSigning: true}, wantErr: true},
		{name: "signing format without key", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningFormat: "ssh"}, wantErr: true},
		{name: "unsupported signing format", profile: Profile{GitName: "Ada", GitEmail: "ada@example.com", SigningKey: "ABC123", SigningFormat: "smime"}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.profile.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestLegacySigningKeyWithoutFormatNeedsMigration(t *testing.T) {
	var legacy Profile
	if err := json.Unmarshal([]byte(`{"git_name":"Ada","git_email":"ada@example.com","signing_key":"ABC123"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.DisableSigning || legacy.SigningFormat != "" {
		t.Fatalf("legacy profile gained a signing policy: %#v", legacy)
	}
	if err := legacy.Validate(); err == nil || !strings.Contains(err.Error(), "requires a signing format") {
		t.Fatalf("legacy ambiguous signing profile validation error = %v", err)
	}

	normalized := (Profile{SigningFormat: " SSH "}).Normalize()
	if normalized.SigningFormat != "ssh" {
		t.Fatalf("Normalize().SigningFormat = %q, want ssh", normalized.SigningFormat)
	}
}

func TestInvalidGitHubUsernameErrorDoesNotEchoValue(t *testing.T) {
	const accidentalSecret = "ghp_accidentalSecretValue"
	err := (Profile{GitName: "Ada", GitEmail: "ada@example.com", GitHubUser: accidentalSecret}).Validate()
	if err == nil {
		t.Fatal("Validate() error = nil")
	}
	if got := err.Error(); got == "" || strings.Contains(got, accidentalSecret) {
		t.Fatalf("Validate() error exposed invalid value: %q", got)
	}
}
