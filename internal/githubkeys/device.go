package githubkeys

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// OAuthClientID is public application metadata, optionally embedded by the
// distributor with -ldflags. No client secret is needed or shipped.
var OAuthClientID string

var validClientID = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)
var validUserCode = regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4}$`)

const deviceScope = "write:public_key write:ssh_signing_key"
const deviceURL = "https://github.com/login/device"

// ValidateClientID rejects missing configuration before opening a browser or
// creating keys. A GitHub app registration is a distributor prerequisite.
func ValidateClientID(id string) error {
	if !validClientID.MatchString(id) {
		return errors.New("native login needs the gitctx GitHub application's public Client ID; set GITCTX_GITHUB_CLIENT_ID or pass --client-id (never a client secret)")
	}
	return nil
}

// AuthorizeDevice authorizes directly with GitHub, without gh, a server-side
// client secret, redirects, a persistent token, or changes to another login.
// announce receives only the public verification code and the fixed GitHub URL.
func AuthorizeDevice(ctx context.Context, clientID string, announce func(code, verificationURL string)) (*Session, error) {
	return authorizeDevice(ctx, clientID, announce, newHTTPClient(), waitDevice)
}

func authorizeDevice(ctx context.Context, clientID string, announce func(string, string), client *http.Client, wait func(context.Context, time.Duration) error) (*Session, error) {
	if err := ValidateClientID(clientID); err != nil {
		return nil, err
	}
	var device struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		Error           string `json:"error"`
	}
	if err := deviceRequest(ctx, client, "/login/device/code", url.Values{"client_id": {clientID}, "scope": {deviceScope}}, &device); err != nil {
		return nil, err
	}
	if device.Error != "" {
		return nil, deviceError(device.Error)
	}
	if len(device.DeviceCode) < 16 || len(device.DeviceCode) > 512 || strings.Trim(device.DeviceCode, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" ||
		!validUserCode.MatchString(device.UserCode) || device.VerificationURI != deviceURL || device.ExpiresIn < 1 || device.ExpiresIn > 900 || device.Interval < 1 || device.Interval > 60 {
		return nil, errors.New("GitHub returned an invalid device authorization response")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(device.ExpiresIn)*time.Second)
	defer cancel()
	if announce != nil {
		announce(device.UserCode, deviceURL)
	}
	interval := time.Duration(device.Interval) * time.Second
	for {
		if err := wait(ctx, interval); err != nil {
			return nil, errors.New("GitHub authorization expired or was cancelled; run login again")
		}
		var response struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Scope       string `json:"scope"`
			Error       string `json:"error"`
		}
		if err := deviceRequest(ctx, client, "/login/oauth/access_token", url.Values{
			"client_id": {clientID}, "device_code": {device.DeviceCode}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
		}, &response); err != nil {
			return nil, err
		}
		switch response.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "":
		default:
			return nil, deviceError(response.Error)
		}
		if response.AccessToken == "" || len(response.AccessToken) > 4096 || strings.ContainsAny(response.AccessToken, " \t\r\n") || !strings.EqualFold(response.TokenType, "bearer") {
			return nil, errors.New("GitHub returned an invalid authorization credential")
		}
		scopes := map[string]bool{}
		for _, scope := range strings.Fields(strings.ReplaceAll(response.Scope, ",", " ")) {
			scopes[scope] = true
		}
		if !(scopes["write:public_key"] || scopes["admin:public_key"]) || !(scopes["write:ssh_signing_key"] || scopes["admin:ssh_signing_key"]) {
			return nil, errors.New("GitHub did not grant the required authentication-key and signing-key permissions; no keys were uploaded")
		}
		return openSession(ctx, response.AccessToken, client)
	}
}

func deviceRequest(ctx context.Context, client *http.Client, path string, fields url.Values, result any) error {
	request, err := http.NewRequestWithContext(ctx, "POST", "https://github.com"+path, strings.NewReader(fields.Encode()))
	if err != nil {
		return errors.New("cannot prepare GitHub authorization")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "gitctx")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("GitHub authorization request failed or timed out; check connectivity and retry")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 400 {
		return errors.New("GitHub refused the authorization request; check the app registration and retry")
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	if err != nil || len(contents) > 16*1024 || json.Unmarshal(contents, result) != nil {
		return errors.New("GitHub returned an unreadable authorization response")
	}
	return nil
}

func deviceError(code string) error {
	switch code {
	case "access_denied":
		return errors.New("GitHub authorization was declined; no keys were uploaded")
	case "expired_token", "token_expired":
		return errors.New("GitHub authorization expired; run login again")
	case "device_flow_disabled":
		return errors.New("enable Device Flow in the gitctx GitHub application's settings")
	case "incorrect_client_credentials", "invalid_client":
		return errors.New("GitHub rejected the public Client ID; check the gitctx app registration")
	default:
		return errors.New("GitHub could not complete authorization; check the app registration and retry")
	}
}

func waitDevice(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
