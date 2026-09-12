//go:build windows

package configstore

import "testing"

func TestIsFilesystemRootRecognizesWindowsRoots(t *testing.T) {
	for _, path := range []string{`C:\`, `\\server\share`, `\\server\share\`} {
		if !IsFilesystemRoot(path) {
			t.Errorf("IsFilesystemRoot(%q) = false, want true", path)
		}
	}
	if IsFilesystemRoot(`C:\code`) {
		t.Fatal(`IsFilesystemRoot("C:\\code") = true, want false`)
	}
}
