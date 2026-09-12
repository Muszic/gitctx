package filelock

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAcquireReleaseAndReacquire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.lock")

	first, err := Acquire(path, 0)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("lock metadata is empty")
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("second Release() error = %v", err)
	}

	second, err := Acquire(path, 0)
	if err != nil {
		t.Fatalf("second Acquire() error = %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("second lock Release() error = %v", err)
	}
}

func TestAcquireTimesOutWhileHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "held.lock")
	held, err := Acquire(path, 0)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer held.Release()

	started := time.Now()
	_, err = Acquire(path, 45*time.Millisecond)
	elapsed := time.Since(started)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Acquire() error = %v, want ErrTimeout", err)
	}
	if elapsed < 35*time.Millisecond || elapsed > time.Second {
		t.Fatalf("Acquire() elapsed = %v, want a bounded wait near timeout", elapsed)
	}
}

func TestAcquireDoesNotSucceedAfterDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deadline.lock")
	if err := os.WriteFile(path, []byte("occupied\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	calls := 0
	now := func() time.Time {
		calls++
		if calls == 4 {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove lock at deadline: %v", err)
			}
			return started.Add(time.Second)
		}
		return started
	}
	if _, err := acquire(path, time.Second, time.Nanosecond, now); !errors.Is(err, ErrTimeout) {
		t.Fatalf("acquire() error = %v, want ErrTimeout", err)
	}
}

func TestAcquireSerializesConcurrentCriticalSections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.lock")
	const workers = 16

	var wait sync.WaitGroup
	wait.Add(workers)
	inside := 0
	maximumInside := 0
	var stateMu sync.Mutex
	start := make(chan struct{})
	errorsFound := make(chan error, workers)

	for range workers {
		go func() {
			defer wait.Done()
			<-start
			lock, err := Acquire(path, 3*time.Second)
			if err != nil {
				errorsFound <- err
				return
			}

			stateMu.Lock()
			inside++
			if inside > maximumInside {
				maximumInside = inside
			}
			stateMu.Unlock()

			time.Sleep(time.Millisecond)

			stateMu.Lock()
			inside--
			stateMu.Unlock()
			if err := lock.Release(); err != nil {
				errorsFound <- err
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent lock operation error = %v", err)
	}
	if maximumInside != 1 {
		t.Fatalf("maximum simultaneous critical sections = %d, want 1", maximumInside)
	}
}

func TestAcquireNeverReclaimsStaleLock(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "stale.lock")
	current := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	old := current.Add(-2 * time.Hour)
	owner := metadata{
		Format:  lockFormat,
		Token:   "0123456789abcdef0123456789abcdef",
		PID:     1234,
		Created: old,
	}
	writeMetadataForTest(t, path, owner, old)

	_, err := acquire(path, 0, time.Millisecond, func() time.Time { return current })
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("acquire(stale) error = %v, want ErrTimeout", err)
	}
	preserved, readErr := readMetadata(path)
	if readErr != nil {
		t.Fatalf("stale lock was removed: %v", readErr)
	}
	if preserved.Token != owner.Token {
		t.Fatalf("stale lock token = %q, want preserved token %q", preserved.Token, owner.Token)
	}

	unknownPath := filepath.Join(directory, "unknown.lock")
	if err := os.WriteFile(unknownPath, []byte("not a gitctx lock\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chtimes(unknownPath, old, old); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}
	_, err = acquire(unknownPath, 0, time.Millisecond, func() time.Time { return current })
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("acquire(unknown) error = %v, want ErrTimeout", err)
	}
	data, readErr := os.ReadFile(unknownPath)
	if readErr != nil {
		t.Fatalf("unknown lock was removed: %v", readErr)
	}
	if string(data) != "not a gitctx lock\n" {
		t.Fatalf("unknown lock content = %q", data)
	}
}

func TestReleasePreservesReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow replacing this deliberately open test file")
	}
	path := filepath.Join(t.TempDir(), "replace.lock")
	lock, err := Acquire(path, 0)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	replacement := []byte("someone else's file\n")
	if err := os.WriteFile(path, replacement, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := lock.Release(); !errors.Is(err, ErrLockLost) {
		t.Fatalf("Release() error = %v, want ErrLockLost", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if string(data) != string(replacement) {
		t.Fatalf("replacement content = %q", data)
	}
}

func TestReleaseReportsMissingLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow deleting this deliberately open test file")
	}
	path := filepath.Join(t.TempDir(), "missing.lock")
	lock, err := Acquire(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); !errors.Is(err, ErrLockLost) {
		t.Fatalf("Release() error = %v, want ErrLockLost", err)
	}
}

func TestReleaseCanRetryTransientRemovalFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retry-release.lock")
	lock, err := Acquire(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	lock.remove = func(path string) error {
		attempts++
		if attempts == 1 {
			return errors.New("temporary remove failure")
		}
		return os.Remove(path)
	}
	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "temporary remove failure") {
		t.Fatalf("first Release() error = %v, want temporary failure", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock file missing after failed release: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("second Release() error = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock file still exists after retry: %v", err)
	}
}

func TestAcquireRejectsInvalidArguments(t *testing.T) {
	for _, test := range []struct {
		name    string
		path    string
		timeout time.Duration
	}{
		{name: "empty path", path: ""},
		{name: "whitespace path", path: "  "},
		{name: "negative timeout", path: filepath.Join(t.TempDir(), "negative.lock"), timeout: -time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Acquire(test.path, test.timeout); err == nil {
				t.Fatal("Acquire() error = nil, want error")
			}
		})
	}
}

func writeMetadataForTest(t *testing.T, path string, owner metadata, modified time.Time) {
	t.Helper()
	data, err := jsonMarshal(owner)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}
}

func jsonMarshal(value metadata) ([]byte, error) {
	return json.Marshal(value)
}
