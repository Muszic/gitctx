// Package configstore persists gitctx profile metadata without credentials.
package configstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"gitctx/internal/filelock"
	"gitctx/internal/profile"
)

const currentSchemaVersion = 1

// Config is the on-disk gitctx configuration.
type Config struct {
	SchemaVersion int                        `json:"schema_version"`
	Profiles      map[string]profile.Profile `json:"profiles"`
	Rules         map[string]string          `json:"rules,omitempty"`
}

// Store reads one configuration file and replaces it atomically on supported
// Unix targets.
type Store struct {
	Path string
}

// WithLock serializes a read-modify-write transaction for this store across
// processes. Callers should perform both Load and Save inside fn.
func (s Store) WithLock(fn func() error) (err error) {
	if fn == nil {
		return fmt.Errorf("config transaction is required")
	}
	lock, err := filelock.Acquire(s.Path+".lock", 10*time.Second)
	if err != nil {
		return fmt.Errorf("lock config %s: %w", s.Path, err)
	}
	defer func() {
		if releaseErr := lock.Release(); releaseErr != nil {
			err = errors.Join(err, fmt.Errorf("unlock config %s: %w", s.Path, releaseErr))
		}
	}()
	return fn()
}

// DefaultPath returns the profile store path. GITCTX_CONFIG is intended for
// tests and portable installations that need an explicit location.
func DefaultPath() (string, error) {
	if path := os.Getenv("GITCTX_CONFIG"); path != "" {
		return filepath.Abs(path)
	}
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Abs(filepath.Join(base, "gitctx", "config.json"))
	}

	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(base, "gitctx", "config.json"), nil
}

// Load returns an empty versioned configuration when the file does not exist.
func (s Store) Load() (Config, error) {
	config := Config{SchemaVersion: currentSchemaVersion, Profiles: make(map[string]profile.Profile), Rules: make(map[string]string)}

	if err := validateConfigTarget(s.Path); err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return config, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", s.Path, err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", s.Path, err)
	}
	if config.SchemaVersion != currentSchemaVersion {
		return Config{}, fmt.Errorf("config %s uses unsupported schema version %d", s.Path, config.SchemaVersion)
	}
	if config.Profiles == nil {
		config.Profiles = make(map[string]profile.Profile)
	} else {
		config.Profiles = normalizedProfiles(config.Profiles)
	}
	if config.Rules == nil {
		config.Rules = make(map[string]string)
	}
	if err := validateConfig(config, s.Path); err != nil {
		return Config{}, err
	}
	return config, nil
}

func validateConfig(config Config, path string) error {
	for name, saved := range config.Profiles {
		if err := profile.ValidateName(name); err != nil {
			return fmt.Errorf("config %s: %w", path, err)
		}
		if err := saved.Validate(); err != nil {
			return fmt.Errorf("config %s profile %q: %w", path, name, err)
		}
	}
	for rulePath, profileName := range config.Rules {
		if err := ValidateRulePath(rulePath); err != nil {
			return fmt.Errorf("config %s: %w", path, err)
		}
		if _, exists := config.Profiles[profileName]; !exists {
			return fmt.Errorf("config %s rule %q references missing profile %q", path, rulePath, profileName)
		}
	}
	return nil
}

// ValidateRulePath enforces the subset of literal paths that can be safely
// represented by a Git includeIf gitdir condition.
func ValidateRulePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("rule path %q is not absolute", path)
	}
	if IsFilesystemRoot(path) {
		return fmt.Errorf("rule path %q targets a filesystem root", path)
	}
	if strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return fmt.Errorf("rule path %q contains control characters", path)
	}
	if strings.ContainsAny(filepath.ToSlash(path), `*?[]\`) {
		return fmt.Errorf("rule path %q contains Git pattern metacharacters (*, ?, [, ], or backslash)", path)
	}
	return nil
}

// IsFilesystemRoot reports whether path names the root of its filesystem
// volume. Automatic identity rules must always target a narrower directory.
func IsFilesystemRoot(path string) bool {
	clean := filepath.Clean(path)
	return filepath.IsAbs(clean) && filepath.Dir(clean) == clean
}

// Save writes a configuration with restrictive permissions and replaces the
// old file atomically on supported Unix targets.
func (s Store) Save(config Config) error {
	config.SchemaVersion = currentSchemaVersion
	if config.Profiles == nil {
		config.Profiles = make(map[string]profile.Profile)
	} else {
		config.Profiles = normalizedProfiles(config.Profiles)
	}
	if config.Rules == nil {
		config.Rules = make(map[string]string)
	}
	if err := validateConfig(config, s.Path); err != nil {
		return err
	}
	if err := validateConfigTarget(s.Path); err != nil {
		return err
	}

	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory %s: %w", dir, err)
	}

	temp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("protect temporary config: %w", err)
	}
	encoder := json.NewEncoder(temp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		temp.Close()
		return fmt.Errorf("encode config: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := validateConfigTarget(s.Path); err != nil {
		return err
	}
	if err := os.Rename(tempPath, s.Path); err != nil {
		return fmt.Errorf("replace config %s: %w", s.Path, err)
	}
	return nil
}

func validateConfigTarget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect config %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config path %s is a symbolic link; use its resolved target path", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config path %s is not a regular file", path)
	}
	return nil
}

func normalizedProfiles(profiles map[string]profile.Profile) map[string]profile.Profile {
	normalized := make(map[string]profile.Profile, len(profiles))
	for name, saved := range profiles {
		normalized[name] = saved.Normalize()
	}
	return normalized
}
