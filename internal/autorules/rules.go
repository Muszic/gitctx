// Package autorules manages Git includeIf rules generated from gitctx config.
package autorules

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"gitctx/internal/configstore"
	"gitctx/internal/filelock"
	"gitctx/internal/profile"
)

const generatedManifestPrefix = "auto-"

// Manager synchronizes generated profile files and one global include entry.
type Manager struct {
	ConfigPath        string
	LegacyConfigPaths []string
	Env               []string
}

// NewManager creates an auto-rule manager beside the gitctx profile store.
func NewManager(configPath string) *Manager {
	return &Manager{ConfigPath: configPath, Env: os.Environ()}
}

// Generation returns a deterministic identifier for one complete automatic
// rule snapshot. JSON map keys are sorted by encoding/json.
func Generation(config configstore.Config) string {
	data, _ := json.Marshal(config)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}

// ProfilePath returns the immutable generated fragment for profile in config.
func (m *Manager) ProfilePath(config configstore.Config, profileName string) string {
	profilesDir := filepath.Join(artifactRoot(m.ConfigPath), "generations", Generation(config))
	return profilePathInDirectory(profilesDir, profileName)
}

func artifactRoot(configPath string) string {
	clean := filepath.Clean(configPath)
	sum := sha256.Sum256([]byte(clean))
	return filepath.Join(filepath.Dir(clean), "stores", hex.EncodeToString(sum[:16]))
}

func profilePathInDirectory(directory, profileName string) string {
	sum := sha256.Sum256([]byte(profileName))
	return filepath.Join(directory, hex.EncodeToString(sum[:16])+".gitconfig")
}

// Sync regenerates files from config and adds or removes gitctx's one global
// include. It never writes global identity values.
func (m *Manager) Sync(config configstore.Config) (string, error) {
	if err := m.requireCompatibleGit(); err != nil {
		return "", err
	}
	for rulePath := range config.Rules {
		if err := configstore.ValidateRulePath(rulePath); err != nil {
			return "", fmt.Errorf("invalid auto-rule directory: %w", err)
		}
		canonical, err := CanonicalPathAllowMissing(rulePath)
		if err != nil {
			return "", fmt.Errorf("resolve auto-rule directory %s: %w", rulePath, err)
		}
		if configstore.IsFilesystemRoot(canonical) {
			return "", fmt.Errorf("automatic rules cannot target filesystem root %s", canonical)
		}
		if err := configstore.ValidateRulePath(canonical); err != nil {
			return "", fmt.Errorf("invalid canonical auto-rule directory: %w", err)
		}
	}
	base := artifactRoot(m.ConfigPath)
	profilesDir := filepath.Join(base, "generations", Generation(config))
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		return "", fmt.Errorf("create generated profile directory: %w", err)
	}

	usedProfiles := make(map[string]bool)
	for _, profileName := range config.Rules {
		usedProfiles[profileName] = true
	}
	names := make([]string, 0, len(usedProfiles))
	for name := range usedProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		selected, exists := config.Profiles[name]
		if !exists {
			return "", fmt.Errorf("auto rule references missing profile %q", name)
		}
		path := profilePathInDirectory(profilesDir, name)
		if err := m.writeProfile(path, name, selected); err != nil {
			return "", err
		}
	}

	manifestPath := ""
	if len(config.Rules) > 0 {
		var err error
		manifestPath, err = m.newManifestPath(profilesDir)
		if err != nil {
			return "", err
		}
		if err := m.writeManifest(config, profilesDir, manifestPath); err != nil {
			return "", err
		}
	}
	if err := m.setGlobalInclude(manifestPath, len(config.Rules) > 0); err != nil {
		return "", err
	}
	return manifestPath, nil
}

func (m *Manager) requireCompatibleGit() error {
	if err := m.validateGlobalConfigEnvironment(); err != nil {
		return err
	}
	out, err := m.run(m.commandDir(), "version")
	if err != nil {
		return fmt.Errorf("check Git version: %w", err)
	}
	var major, minor int
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "git version %d.%d", &major, &minor); err != nil {
		return fmt.Errorf("check Git version: unrecognized output")
	}
	if major < 2 || (major == 2 && minor < 30) {
		return fmt.Errorf("automatic rules require Git 2.30 or newer")
	}
	return nil
}

func (m *Manager) writeProfile(path, name string, selected profile.Profile) error {
	if err := m.writeConfigFile(path, profileEntries(name, selected)); err != nil {
		return fmt.Errorf("generate profile %q: %w", name, err)
	}
	return nil
}

func profileEntries(name string, selected profile.Profile) []entry {
	return []entry{
		{key: "user.name", value: selected.GitName},
		{key: "user.email", value: selected.GitEmail},
		{key: "gitctx.profile", value: name},
	}
}

func (m *Manager) writeManifest(config configstore.Config, profilesDir, manifestPath string) error {
	entries, err := m.manifestEntries(config, profilesDir)
	if err != nil {
		return err
	}
	if err := m.writeConfigFile(manifestPath, entries); err != nil {
		return fmt.Errorf("generate auto-rule manifest: %w", err)
	}
	return nil
}

func (m *Manager) manifestEntries(config configstore.Config, profilesDir string) ([]entry, error) {
	rules := make(map[string]string, len(config.Rules))
	for path, profileName := range config.Rules {
		canonical, err := CanonicalPathAllowMissing(path)
		if err != nil {
			return nil, fmt.Errorf("resolve auto-rule directory %s: %w", path, err)
		}
		if existing, found := rules[canonical]; found && existing != profileName {
			return nil, fmt.Errorf("auto-rule directories %s resolve to the same location with different profiles", path)
		}
		rules[canonical] = profileName
	}
	paths := make([]string, 0, len(rules))
	for path := range rules {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		leftDepth := strings.Count(filepath.Clean(paths[i]), string(filepath.Separator))
		rightDepth := strings.Count(filepath.Clean(paths[j]), string(filepath.Separator))
		if leftDepth == rightDepth {
			return paths[i] < paths[j]
		}
		return leftDepth < rightDepth
	})

	entries := make([]entry, 0, len(paths))
	for _, path := range paths {
		pattern := filepath.ToSlash(path)
		if !strings.HasSuffix(pattern, "/") {
			pattern += "/"
		}
		profilePath := profilePathInDirectory(profilesDir, rules[path])
		entries = append(entries, entry{
			key:   "includeif.gitdir:" + pattern + "**/.git.path",
			value: profilePath,
		})
	}
	return entries, nil
}

func (m *Manager) newManifestPath(profilesDir string) (string, error) {
	for attempts := 0; attempts < 10; attempts++ {
		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			return "", fmt.Errorf("create unique auto-rule manifest name: %w", err)
		}
		path := filepath.Join(profilesDir, generatedManifestPrefix+hex.EncodeToString(token[:])+".gitconfig")
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return path, nil
		} else if err != nil {
			return "", fmt.Errorf("check auto-rule manifest path: %w", err)
		}
	}
	return "", fmt.Errorf("create unique auto-rule manifest name: too many collisions")
}

// CanonicalPathAllowMissing resolves symlinks and on-disk path spelling in the longest existing parent
// while preserving any missing suffix. This keeps Git's gitdir match stable on
// systems where a temporary-directory prefix such as /var is itself a symlink.
func CanonicalPathAllowMissing(path string) (string, error) {
	current := filepath.Clean(path)
	var suffix []string
	for {
		canonical, err := filepath.EvalSymlinks(current)
		if err == nil {
			canonical, err = canonicalExistingCase(canonical)
			if err != nil {
				return "", err
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				canonical = filepath.Join(canonical, suffix[index])
			}
			return filepath.Clean(canonical), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func canonicalExistingCase(path string) (string, error) {
	path = filepath.Clean(path)
	parent := filepath.Dir(path)
	if parent == path {
		return path, nil
	}
	canonicalParent, err := canonicalExistingCase(parent)
	if err != nil {
		return "", err
	}
	target, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(canonicalParent)
	if err != nil {
		return "", err
	}
	base := filepath.Base(path)
	for _, entry := range entries {
		if entry.Name() == base {
			return filepath.Join(canonicalParent, entry.Name()), nil
		}
	}
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr == nil && os.SameFile(target, info) {
			return filepath.Join(canonicalParent, entry.Name()), nil
		}
	}
	return "", fmt.Errorf("cannot determine canonical spelling for %s", path)
}

type entry struct {
	key   string
	value string
}

func (m *Manager) writeConfigFile(path string, entries []entry) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".gitconfig-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		os.Remove(tempPath)
		return err
	}
	defer os.Remove(tempPath)

	for _, item := range entries {
		if _, err := m.run(dir, "config", "--file", tempPath, "--add", "--", item.key, item.value); err != nil {
			return err
		}
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return err
	}
	file, err := os.OpenFile(tempPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func (m *Manager) setGlobalInclude(manifest string, enabled bool) (err error) {
	lockPaths, err := m.globalLockPaths()
	if err != nil {
		return err
	}
	locks := make([]*filelock.Lock, 0, len(lockPaths))
	for _, lockPath := range lockPaths {
		lock, acquireErr := filelock.Acquire(lockPath, 10*time.Second)
		if acquireErr != nil {
			for index := len(locks) - 1; index >= 0; index-- {
				acquireErr = errors.Join(acquireErr, locks[index].Release())
			}
			return fmt.Errorf("lock automatic global Git configuration: %w", acquireErr)
		}
		locks = append(locks, lock)
	}
	defer func() {
		for index := len(locks) - 1; index >= 0; index-- {
			if releaseErr := locks[index].Release(); releaseErr != nil {
				err = errors.Join(err, fmt.Errorf("unlock automatic global Git configuration: %w", releaseErr))
			}
		}
	}()

	if err := m.cleanupAbandonedStages(); err != nil {
		return err
	}
	includes, err := m.globalIncludes()
	if err != nil {
		return err
	}
	managed := make([]globalInclude, 0)
	seen := make(map[string]bool)
	for _, include := range includes {
		if m.isManagedManifestPath(include.Value) {
			key := include.Origin + "\x00" + include.Value
			if !seen[key] {
				managed = append(managed, include)
				seen[key] = true
			}
			continue
		}
		if looksLikeGeneratedManifestPath(include.Value) {
			return foreignManifestError(include.Value)
		}
	}

	// Activate the fully written replacement at the end of the global config.
	// If this process is interrupted, Git sees either the old snapshot or the
	// new snapshot, never a gap that falls back to a different global identity.
	if enabled {
		if manifest == "" || !m.isManagedManifestPath(manifest) {
			return fmt.Errorf("invalid generated auto-rule manifest path")
		}
		if err := m.activateManifestAtEnd(manifest); err != nil {
			return err
		}
	}

	for _, oldManifest := range managed {
		if enabled && oldManifest.Value == manifest {
			continue
		}
		origin, ok := strings.CutPrefix(oldManifest.Origin, "file:")
		if !ok || !filepath.IsAbs(origin) {
			return fmt.Errorf("cannot safely update global Git include from origin %q", oldManifest.Origin)
		}
		if _, err := m.run(m.commandDir(), "config", "--file", origin, "--fixed-value", "--unset-all", "--", "include.path", oldManifest.Value); err != nil {
			return fmt.Errorf("remove superseded gitctx manifest from global Git config: %w", err)
		}
	}
	return nil
}

func (m *Manager) globalLockPaths() ([]string, error) {
	if global := m.environmentValue("GIT_CONFIG_GLOBAL"); global != "" {
		if !filepath.IsAbs(global) {
			return nil, fmt.Errorf("GIT_CONFIG_GLOBAL must be an absolute path for automatic rules")
		}
		canonical, err := CanonicalPathAllowMissing(global)
		if err != nil {
			return nil, fmt.Errorf("resolve global Git config for automatic lock: %w", err)
		}
		return []string{canonical + ".gitctx-auto.lock"}, nil
	}
	home := m.environmentValue("HOME")
	if home == "" {
		home = m.environmentValue("USERPROFILE")
	}
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("find home directory for automatic Git config lock: %w", err)
		}
	}
	if !filepath.IsAbs(home) {
		return nil, fmt.Errorf("HOME must be an absolute path for automatic rules")
	}
	xdgHome := m.environmentValue("XDG_CONFIG_HOME")
	if xdgHome == "" {
		xdgHome = filepath.Join(home, ".config")
	} else if !filepath.IsAbs(xdgHome) {
		return nil, fmt.Errorf("XDG_CONFIG_HOME must be an absolute path for automatic rules")
	}
	targets := []string{
		filepath.Join(home, ".gitconfig"),
		filepath.Join(xdgHome, "git", "config"),
	}
	locks := make([]string, 0, len(targets))
	seen := make(map[string]bool)
	for _, target := range targets {
		canonical, err := CanonicalPathAllowMissing(target)
		if err != nil {
			return nil, fmt.Errorf("resolve global Git config for automatic lock: %w", err)
		}
		lockPath := canonical + ".gitctx-auto.lock"
		if !seen[lockPath] {
			locks = append(locks, lockPath)
			seen[lockPath] = true
		}
	}
	sort.Strings(locks)
	return locks, nil
}

func (m *Manager) environmentValue(name string) string {
	environment := m.Env
	if environment == nil {
		environment = os.Environ()
	}
	for index := len(environment) - 1; index >= 0; index-- {
		key, value, found := strings.Cut(environment[index], "=")
		matches := key == name
		if runtime.GOOS == "windows" {
			matches = strings.EqualFold(key, name)
		}
		if found && matches {
			return value
		}
	}
	return ""
}

func (m *Manager) activateManifestAtEnd(manifest string) error {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return fmt.Errorf("create unique global Git config section: %w", err)
	}
	section := "gitctxstage" + hex.EncodeToString(token[:])
	dir := m.commandDir()
	if _, err := m.run(dir, "config", "--global", "--add", "--", section+".path", manifest); err != nil {
		return fmt.Errorf("stage gitctx manifest in global Git config: %w", err)
	}
	if _, err := m.run(dir, "config", "--global", "--rename-section", section, "include"); err != nil {
		_, cleanupErr := m.run(dir, "config", "--global", "--remove-section", section)
		if cleanupErr != nil {
			return errors.Join(
				fmt.Errorf("activate gitctx manifest in global Git config: %w", err),
				fmt.Errorf("remove staged global Git config section: %w", cleanupErr),
			)
		}
		return fmt.Errorf("activate gitctx manifest in global Git config: %w", err)
	}
	return nil
}

// cleanupAbandonedStages removes inert staging sections left if a previous
// process stopped after adding the section but before renaming it to include.
// It only touches well-formed sections that point into this manager's own
// artifact namespace (or a recognized legacy namespace).
func (m *Manager) cleanupAbandonedStages() error {
	out, err := m.run(
		m.commandDir(),
		"config", "--no-includes", "--show-scope", "--show-origin", "--null",
		"--get-regexp", `^gitctxstage[0-9a-f]*\.path$`,
	)
	if err != nil {
		var commandErr *commandError
		if errors.As(err, &commandErr) && commandErr.Code == 1 {
			return nil
		}
		return fmt.Errorf("read staged automatic Git configuration: %w", err)
	}
	fields := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
	if len(fields)%3 != 0 {
		return fmt.Errorf("read staged automatic Git configuration: Git returned an unexpected scoped result")
	}
	type stagedSection struct {
		origin  string
		section string
	}
	staged := make([]stagedSection, 0, len(fields)/3)
	seen := make(map[string]bool)
	for index := 0; index < len(fields); index += 3 {
		if fields[index] != "global" {
			continue
		}
		key, value, found := strings.Cut(fields[index+2], "\n")
		if !found {
			return fmt.Errorf("read staged automatic Git configuration: Git returned an unexpected key-value result")
		}
		section, found := strings.CutSuffix(key, ".path")
		if !found || !strings.HasPrefix(section, "gitctxstage") || !lowerHex(strings.TrimPrefix(section, "gitctxstage"), 32) || !m.isManagedManifestPath(value) {
			continue
		}
		origin, found := strings.CutPrefix(fields[index+1], "file:")
		if !found || !filepath.IsAbs(origin) {
			return fmt.Errorf("cannot safely remove staged Git configuration from origin %q", fields[index+1])
		}
		identity := origin + "\x00" + section
		if !seen[identity] {
			staged = append(staged, stagedSection{origin: origin, section: section})
			seen[identity] = true
		}
	}
	for _, item := range staged {
		if _, err := m.run(m.commandDir(), "config", "--file", item.origin, "--remove-section", item.section); err != nil {
			return fmt.Errorf("remove abandoned automatic Git configuration stage: %w", err)
		}
	}
	return nil
}

// ActiveManifestPath returns the last active gitctx-managed manifest from the
// global Git config. A successful sync normally leaves exactly one.
func (m *Manager) ActiveManifestPath() (string, error) {
	includes, err := m.globalIncludes()
	if err != nil {
		return "", err
	}
	active := ""
	managedCount := 0
	for _, include := range includes {
		if m.isManagedManifestPath(include.Value) {
			active = include.Value
			managedCount++
		} else if looksLikeGeneratedManifestPath(include.Value) {
			return "", foreignManifestError(include.Value)
		}
	}
	if managedCount > 1 {
		return "", fmt.Errorf("global Git config contains multiple active gitctx manifests; run 'gitctx auto sync' to reconcile them")
	}
	return active, nil
}

// ManifestMatchesConfig reports whether an active manifest represents the
// complete current configuration snapshot.
func (m *Manager) ManifestMatchesConfig(config configstore.Config, path string) bool {
	if !m.isManagedManifestPath(path) || filepath.Base(filepath.Dir(path)) != Generation(config) {
		return false
	}
	profilesDir := filepath.Dir(path)
	manifestEntries, err := m.manifestEntries(config, profilesDir)
	if err != nil || !m.configFileMatches(path, manifestEntries) {
		return false
	}
	usedProfiles := make(map[string]bool)
	for _, name := range config.Rules {
		usedProfiles[name] = true
	}
	for name := range usedProfiles {
		selected, found := config.Profiles[name]
		if !found || !m.configFileMatches(profilePathInDirectory(profilesDir, name), profileEntries(name, selected)) {
			return false
		}
	}
	return true
}

func (m *Manager) configFileMatches(path string, expected []entry) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	out, err := m.run(filepath.Dir(path), "config", "--no-includes", "--file", path, "--null", "--list")
	if err != nil {
		return false
	}
	actual := make([]entry, 0)
	if out != "" {
		for _, record := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
			key, value, found := strings.Cut(record, "\n")
			if !found {
				return false
			}
			actual = append(actual, entry{key: key, value: value})
		}
	}
	return sameEntries(actual, expected)
}

func sameEntries(left, right []entry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (m *Manager) isManagedManifestPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	configPaths := append([]string{m.ConfigPath}, m.LegacyConfigPaths...)
	for _, configPath := range configPaths {
		base := artifactRoot(configPath)
		relative, err := filepath.Rel(filepath.Join(base, "generations"), path)
		if err != nil || filepath.IsAbs(relative) {
			continue
		}
		parts := strings.Split(relative, string(filepath.Separator))
		if len(parts) == 2 && lowerHex(parts[0], 32) && generatedManifestName(parts[1]) {
			return true
		}
	}
	return false
}

func generatedManifestName(name string) bool {
	if !strings.HasPrefix(name, generatedManifestPrefix) || !strings.HasSuffix(name, ".gitconfig") {
		return false
	}
	token := strings.TrimSuffix(strings.TrimPrefix(name, generatedManifestPrefix), ".gitconfig")
	return lowerHex(token, 32)
}

func looksLikeGeneratedManifestPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !generatedManifestName(filepath.Base(path)) {
		return false
	}
	generationDir := filepath.Dir(path)
	generationsDir := filepath.Dir(generationDir)
	storeDir := filepath.Dir(generationsDir)
	storesDir := filepath.Dir(storeDir)
	return lowerHex(filepath.Base(generationDir), 32) &&
		filepath.Base(generationsDir) == "generations" &&
		lowerHex(filepath.Base(storeDir), 32) &&
		filepath.Base(storesDir) == "stores"
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

type globalInclude struct {
	Origin string
	Value  string
}

func (m *Manager) globalIncludes() ([]globalInclude, error) {
	if err := m.validateGlobalConfigEnvironment(); err != nil {
		return nil, err
	}
	out, err := m.run(m.commandDir(), "config", "--no-includes", "--show-scope", "--show-origin", "--null", "--get-all", "include.path")
	if err != nil {
		var commandErr *commandError
		if errors.As(err, &commandErr) && commandErr.Code == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("read global Git includes: %w", err)
	}
	fields := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
	if len(fields)%3 != 0 {
		return nil, fmt.Errorf("read global Git includes: Git returned an unexpected scoped result")
	}
	includes := make([]globalInclude, 0, len(fields)/3)
	for index := 0; index < len(fields); index += 3 {
		if fields[index] != "global" {
			continue
		}
		includes = append(includes, globalInclude{Origin: fields[index+1], Value: fields[index+2]})
	}
	return includes, nil
}

func (m *Manager) validateGlobalConfigEnvironment() error {
	global := m.environmentValue("GIT_CONFIG_GLOBAL")
	if global != "" && !filepath.IsAbs(global) {
		return fmt.Errorf("GIT_CONFIG_GLOBAL must be an absolute path for automatic rules")
	}
	return nil
}

func (m *Manager) commandDir() string {
	dir := filepath.Dir(m.ConfigPath)
	for {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func foreignManifestError(path string) error {
	return fmt.Errorf("global Git config still includes a gitctx manifest from another or moved profile store: %q; disable the other store first, or recreate the prior config-path symlink and run this command through that path", path)
}

func (m *Manager) run(dir string, args ...string) (string, error) {
	command := exec.Command("git", args...)
	command.Dir = dir
	if m.Env != nil {
		command.Env = m.Env
	}
	output, err := command.CombinedOutput()
	if err == nil {
		return string(output), nil
	}
	code := -1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		message = err.Error()
	}
	return "", &commandError{Code: code, Message: message}
}

type commandError struct {
	Code    int
	Message string
}

func (e *commandError) Error() string { return e.Message }
