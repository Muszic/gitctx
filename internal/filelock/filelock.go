// Package filelock provides a small cross-platform lock-file primitive.
package filelock

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	lockFormat        = "gitctx-lock-v1"
	defaultRetryDelay = 20 * time.Millisecond
)

// ErrTimeout is returned when a lock cannot be acquired before the timeout.
var ErrTimeout = errors.New("timed out waiting for lock")

// ErrLockLost is returned by Release when the lock path no longer refers to
// the file created by this Lock. The replacement is left untouched.
var ErrLockLost = errors.New("lock ownership lost")

// Lock owns an exclusive lock file until Release is called.
type Lock struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	fileInfo os.FileInfo
	token    string
	remove   func(string) error
	closed   bool
	closeErr error
	released bool
}

type metadata struct {
	Format   string    `json:"format"`
	Token    string    `json:"token"`
	PID      int       `json:"pid"`
	Hostname string    `json:"hostname,omitempty"`
	Created  time.Time `json:"created"`
}

// Acquire creates path exclusively and waits up to timeout if another owner
// holds it. A timeout of zero makes one immediate attempt.
//
// Lock files are never reclaimed automatically: deleting one safely requires
// knowing that no process still owns it. A timeout reports the exact path so a
// user can inspect the metadata and remove a crash-left lock deliberately.
func Acquire(path string, timeout time.Duration) (*Lock, error) {
	return acquire(path, timeout, defaultRetryDelay, time.Now)
}

func acquire(
	path string,
	timeout time.Duration,
	retryDelay time.Duration,
	now func() time.Time,
) (*Lock, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("lock path is required")
	}
	if timeout < 0 {
		return nil, errors.New("lock timeout cannot be negative")
	}
	if retryDelay <= 0 {
		return nil, errors.New("lock retry delay must be positive")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve lock path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o700); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}

	started := now()
	deadline := started.Add(timeout)
	attempted := false
	for {
		if attempted {
			current := now()
			if timeout == 0 || !current.Before(deadline) {
				return nil, timeoutError(absPath)
			}
		}
		attempted = true
		lock, err := tryAcquire(absPath, now())
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("acquire lock %q: %w", absPath, err)
		}

		remaining := deadline.Sub(now())
		if timeout == 0 || remaining <= 0 {
			return nil, timeoutError(absPath)
		}
		if remaining < retryDelay {
			time.Sleep(remaining)
		} else {
			time.Sleep(retryDelay)
		}
	}
}

func timeoutError(path string) error {
	return fmt.Errorf("%w: %s (if no gitctx process is running, inspect and remove this lock file)", ErrTimeout, path)
}

func tryAcquire(path string, created time.Time) (*Lock, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}

	token, err := randomToken()
	if err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("create lock token: %w", err)
	}
	hostname, _ := os.Hostname()
	owner := metadata{
		Format:   lockFormat,
		Token:    token,
		PID:      os.Getpid(),
		Hostname: hostname,
		Created:  created.UTC(),
	}
	if err := json.NewEncoder(file).Encode(owner); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write lock metadata: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync lock metadata: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("inspect acquired lock: %w", err)
	}

	return &Lock{
		path:     path,
		file:     file,
		fileInfo: info,
		token:    token,
		remove:   os.Remove,
	}, nil
}

func randomToken() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func readMetadata(path string) (metadata, error) {
	var owner metadata
	file, err := os.Open(path)
	if err != nil {
		return owner, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&owner); err != nil {
		return metadata{}, err
	}
	return owner, nil
}

// Release closes the lock file and removes it if this Lock still owns the
// path. Release is idempotent.
func (lock *Lock) Release() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.released {
		return nil
	}
	if !lock.closed {
		lock.closeErr = lock.file.Close()
		lock.file = nil
		lock.closed = true
	}

	info, err := os.Lstat(lock.path)
	if errors.Is(err, os.ErrNotExist) {
		lock.released = true
		return errors.Join(lock.closeErr, fmt.Errorf("%w: %s", ErrLockLost, lock.path))
	}
	if err != nil {
		return errors.Join(lock.closeErr, fmt.Errorf("inspect lock during release: %w", err))
	}
	owner, metadataErr := readMetadata(lock.path)
	if !os.SameFile(lock.fileInfo, info) || metadataErr != nil || owner.Token != lock.token {
		lock.released = true
		return errors.Join(lock.closeErr, fmt.Errorf("%w: %s", ErrLockLost, lock.path))
	}
	removeErr := lock.remove(lock.path)
	if errors.Is(removeErr, os.ErrNotExist) {
		lock.released = true
		return errors.Join(lock.closeErr, fmt.Errorf("%w: %s", ErrLockLost, lock.path))
	}
	if removeErr != nil {
		return errors.Join(lock.closeErr, removeErr)
	}
	lock.released = true
	return lock.closeErr
}
