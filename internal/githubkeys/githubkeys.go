// Package githubkeys registers public keys using a GitHub CLI login. It never
// changes gh's active account or persists its credential.
package githubkeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	Registered = "registered"
	Existing   = "already registered"
	Pending    = "pending"
	NotNeeded  = "not requested"
	maxBody    = 1024 * 1024
)

// Result reports each registration separately, including partial success.
type Result struct {
	Authentication string
	Signing        string
}

// Session pins one credential and verified account for the entire operation.
// A concurrent change to gh's active account cannot redirect an upload.
type Session struct {
	token   string
	login   string
	account Account
	client  *http.Client
}

// Account is the identity returned by GitHub, not the username typed locally.
type Account struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
}

func (s *Session) Account() Account { return s.account }

// Open uses gh's current github.com credential without logging in, switching
// accounts, or requesting extra permissions. Credential output is never printed.
func Open(ctx context.Context) (*Session, error) {
	executable, err := exec.LookPath("gh")
	if err != nil {
		return nil, errors.New("GitHub CLI (gh) is not installed; install it from https://cli.github.com or register the public key manually")
	}
	tokenCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(tokenCtx, executable, "auth", "token", "--hostname", "github.com")
	command.WaitDelay = time.Second
	// Do not inherit debugging that could expose credentials on stderr.
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		if !strings.EqualFold(name, "GH_DEBUG") && !strings.EqualFold(name, "GH_PROMPT_DISABLED") {
			command.Env = append(command.Env, variable)
		}
	}
	command.Env = append(command.Env, "GH_PROMPT_DISABLED=1")
	var output limitedBuffer
	command.Stdout = &output
	if err := command.Run(); err != nil {
		if tokenCtx.Err() != nil {
			return nil, errors.New("reading the GitHub CLI login timed out")
		}
		return nil, errors.New("GitHub CLI has no usable github.com login; sign in with gh yourself or use manual key registration")
	}
	token := strings.TrimSpace(output.String())
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("GitHub CLI returned an invalid credential")
	}
	return openSession(ctx, token, newHTTPClient())
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func openSession(ctx context.Context, token string, client *http.Client) (*Session, error) {
	session := &Session{token: token, client: client}
	var account Account
	if err := session.request(ctx, "GET", "/user", nil, &account); err != nil {
		return nil, err
	}
	// Enterprise Managed Users include an underscore before their enterprise
	// shortcode. Accept those authenticated identities too, so the caller can
	// report a useful account mismatch instead of a malformed-response error.
	if account.ID <= 0 || account.Login == "" || len(account.Login) > 39 || strings.Trim(account.Login, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		return nil, errors.New("GitHub returned an invalid account identity")
	}
	session.login = account.Login
	session.account = account
	return session, nil
}

func (s *Session) Login() string { return s.login }

// Close drops the session credential. Go cannot guarantee zeroing every copy
// of a string in memory; no copy is written to disk, logs, or subprocess args.
func (s *Session) Close() { s.token = "" }

// ReadPublicKey snapshots and checks the public file against the validated pair
// fingerprint. Only the algorithm and key bytes are returned, without comments.
func ReadPublicKey(path, fingerprint string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot read the profile's public key")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("the public key must be a regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 16*1024+1))
	if err != nil || len(contents) > 16*1024 {
		return "", errors.New("the public key is unreadable or too large")
	}
	key, err := canonicalKey(string(contents))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(key)
	blob, _ := base64.StdEncoding.DecodeString(fields[1])
	digest := sha256.Sum256(blob)
	actual := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	if actual != fingerprint {
		return "", errors.New("the public key changed after validation; inspect the profile before retrying")
	}
	return key, nil
}

func canonicalKey(value string) (string, error) {
	value = strings.TrimSpace(value)
	fields := strings.Fields(value)
	if len(fields) < 2 || strings.ContainsAny(value, "\r\n") || !(strings.HasPrefix(fields[0], "ssh-") || strings.HasPrefix(fields[0], "ecdsa-") || strings.HasPrefix(fields[0], "sk-")) {
		return "", errors.New("expected one OpenSSH public key; private keys and authorized_keys options cannot be uploaded")
	}
	if blob, err := base64.StdEncoding.DecodeString(fields[1]); err != nil || len(blob) == 0 {
		return "", errors.New("invalid public-key encoding")
	}
	return fields[0] + " " + fields[1], nil
}

// Inspect checks both requested registrations before any remote write.
func (s *Session) Inspect(ctx context.Context, key string, signing bool) (Result, error) {
	result := Result{Authentication: Pending, Signing: NotNeeded}
	found, err := s.contains(ctx, "/user/keys", key)
	if err != nil {
		return result, err
	}
	if found {
		result.Authentication = Existing
	}
	if signing {
		result.Signing = Pending
		found, err = s.contains(ctx, "/user/ssh_signing_keys", key)
		if err != nil {
			return result, err
		}
		if found {
			result.Signing = Existing
		}
	}
	return result, nil
}

// Register reconciles existing keys and preserves partial success. It never
// deletes remote keys, including when a request's outcome is ambiguous.
func (s *Session) Register(ctx context.Context, key, title string, signing bool) (Result, error) {
	key, err := canonicalKey(key)
	if err != nil {
		return Result{}, err
	}
	result, err := s.Inspect(ctx, key, signing)
	if err != nil {
		return result, err
	}
	if result.Authentication == Pending {
		result.Authentication, err = s.add(ctx, "/user/keys", key, title)
		if err != nil {
			return result, err
		}
	}
	if signing && result.Signing == Pending {
		result.Signing, err = s.add(ctx, "/user/ssh_signing_keys", key, title)
	}
	return result, err
}

func (s *Session) contains(ctx context.Context, endpoint, key string) (bool, error) {
	for page := 1; page <= 20; page++ {
		var keys []struct {
			Key string `json:"key"`
		}
		if err := s.request(ctx, "GET", fmt.Sprintf("%s?per_page=100&page=%d", endpoint, page), nil, &keys); err != nil {
			return false, err
		}
		for _, candidate := range keys {
			if normalized, err := canonicalKey(candidate.Key); err == nil && normalized == key {
				return true, nil
			}
		}
		if len(keys) < 100 {
			return false, nil
		}
	}
	return false, errors.New("GitHub returned too many keys to check safely; use manual registration")
}

func (s *Session) add(ctx context.Context, endpoint, key, title string) (string, error) {
	payload, _ := json.Marshal(map[string]string{"key": key, "title": title})
	var created struct {
		Key string `json:"key"`
	}
	err := s.request(ctx, "POST", endpoint, payload, &created)
	if err == nil {
		if normalized, normalizeErr := canonicalKey(created.Key); normalizeErr != nil || normalized != key {
			return "outcome unknown", errors.New("GitHub returned an unexpected key; retry to reconcile the registration")
		}
		return Registered, nil
	}
	// A concurrent registration or a lost response can make POST ambiguous.
	// Re-read instead of creating duplicates or deleting a successful upload.
	if ctx.Err() == nil {
		if found, checkErr := s.contains(ctx, endpoint, key); checkErr == nil && found {
			return Existing, nil
		}
	}
	return "not confirmed", err
}

func (s *Session) request(ctx context.Context, method, endpoint string, payload []byte, result any) error {
	if s.token == "" {
		return errors.New("the GitHub registration session is closed")
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+endpoint, bytes.NewReader(payload))
	if err != nil {
		return errors.New("cannot prepare GitHub request")
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "gitctx")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := s.client.Do(req)
	if err != nil {
		return errors.New("GitHub request failed or timed out; check connectivity and retry")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		switch response.StatusCode {
		case 401:
			return errors.New("GitHub rejected the login credential; review your GitHub authorization")
		case 403, 404:
			return errors.New("GitHub denied access; the login may need write:public_key and write:ssh_signing_key permissions, or an account/organization policy may block registration")
		case 422:
			return errors.New("GitHub rejected the public key; it may already belong to another account or be invalid")
		default:
			return fmt.Errorf("GitHub returned HTTP %d; retry later", response.StatusCode)
		}
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(contents) > maxBody || json.Unmarshal(contents, result) != nil {
		return errors.New("GitHub returned an unreadable response; retry to check the registration")
	}
	return nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(value []byte) (int, error) {
	if b.Len()+len(value) > 4096 {
		return 0, errors.New("credential output exceeded its limit")
	}
	return b.Buffer.Write(value)
}
