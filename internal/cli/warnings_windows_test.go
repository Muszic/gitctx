//go:build windows

package cli

import "testing"

func TestCurrentWarningsReportsUnverifiedWindowsKeyACL(t *testing.T) {
	warnings := currentWarnings(currentOutput{Authentication: "repository-scoped SSH"})
	if !hasNotice(warnings, "ssh_permissions_unverified") {
		t.Fatalf("warnings = %#v, want ssh_permissions_unverified", warnings)
	}
}
