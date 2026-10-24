package githubkeys

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const deviceFixture = `{"device_code":"0123456789012345678901234567890123456789","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}`
const tokenFixture = `{"access_token":"native-test-token","token_type":"bearer","scope":"write:public_key,write:ssh_signing_key"}`

func TestNativeDeviceFlowPinsHostScopeAndIdentity(t *testing.T) {
	var sleeps []time.Duration
	polls, announced, accounts := 0, 0, 0
	client := newHTTPClient()
	client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme != "https" {
			t.Fatal("non-TLS request")
		}
		switch req.URL.Path {
		case "/login/device/code":
			if req.URL.Host != "github.com" || req.Method != "POST" || req.Header.Get("Authorization") != "" {
				t.Fatal("wrong device target or leaked credential")
			}
			if err := req.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if req.Form.Get("client_id") != "test-client-id" || req.Form.Get("scope") != deviceScope || len(req.Form) != 2 {
				t.Fatalf("unexpected device request: %v", req.Form)
			}
			return jsonResponse(200, deviceFixture), nil
		case "/login/oauth/access_token":
			polls++
			if req.URL.Host != "github.com" {
				t.Fatal("credential endpoint changed")
			}
			if err := req.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if len(req.Form) != 3 || req.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || req.Form.Get("client_secret") != "" {
				t.Fatal("unexpected token request")
			}
			if polls == 1 {
				return jsonResponse(200, `{"error":"authorization_pending"}`), nil
			}
			if polls == 2 {
				return jsonResponse(200, `{"error":"slow_down"}`), nil
			}
			return jsonResponse(200, tokenFixture), nil
		case "/user":
			accounts++
			if req.URL.Host != "api.github.com" || req.Header.Get("Authorization") != "Bearer native-test-token" {
				t.Fatal("account credential escaped API host")
			}
			return jsonResponse(200, `{"login":"Ada","id":42,"name":"Ada Lovelace"}`), nil
		default:
			t.Fatalf("unexpected URL: %s", req.URL)
			return nil, errors.New("unexpected request")
		}
	})
	session, err := authorizeDevice(context.Background(), "test-client-id", func(code, uri string) {
		announced++
		if code != "ABCD-1234" || uri != deviceURL {
			t.Fatal("unexpected browser challenge")
		}
	}, client, func(_ context.Context, duration time.Duration) error { sleeps = append(sleeps, duration); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if announced != 1 || accounts != 1 || polls != 3 || fmt.Sprint(sleeps) != "[5s 5s 10s]" || session.Account().ID != 42 || session.Account().Name != "Ada Lovelace" {
		t.Fatalf("unexpected flow: polls=%d waits=%v account=%+v", polls, sleeps, session.Account())
	}
	session.Close()
	if session.token != "" {
		t.Fatal("credential retained after close")
	}
}

func TestNativeDeviceFlowRejectsUnsafeResponses(t *testing.T) {
	for _, test := range []struct{ name, device, token, want string }{
		{"denial", deviceFixture, `{"error":"access_denied"}`, "declined"},
		{"expired", deviceFixture, `{"error":"expired_token"}`, "expired"},
		{"missing permissions", deviceFixture, `{"access_token":"native-test-token","token_type":"bearer","scope":"read:user"}`, "permissions"},
		{"credential injection", deviceFixture, `{"access_token":"native-test-token\nLEAK","token_type":"bearer","scope":"write:public_key,write:ssh_signing_key"}`, "invalid authorization"},
		{"phishing URL", strings.Replace(deviceFixture, deviceURL, "https://evil.invalid/login/device", 1), tokenFixture, "invalid device"},
		{"terminal control", strings.Replace(deviceFixture, "ABCD-1234", `ABCD-12\n4`, 1), tokenFixture, "invalid device"},
		{"zero interval", strings.Replace(deviceFixture, `"interval":5`, `"interval":0`, 1), tokenFixture, "invalid device"},
		{"unbounded expiry", strings.Replace(deviceFixture, `"expires_in":900`, `"expires_in":900000`, 1), tokenFixture, "invalid device"},
		{"device flow disabled", `{"error":"device_flow_disabled"}`, "", "Device Flow"},
		{"server debug redacted", deviceFixture, `{"error":"native-test-token-LEAK"}`, "could not complete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newHTTPClient()
			client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/login/device/code" {
					return jsonResponse(200, test.device), nil
				}
				if req.URL.Path == "/login/oauth/access_token" {
					return jsonResponse(200, test.token), nil
				}
				t.Fatal("unsafe flow continued to the account API")
				return nil, errors.New("unsafe flow")
			})
			_, err := authorizeDevice(context.Background(), "test-client-id", nil, client, func(context.Context, time.Duration) error { return nil })
			if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "native-test-token") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestNativeDeviceFlowCancellationAndNoConfiguration(t *testing.T) {
	calls := 0
	client := newHTTPClient()
	client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return jsonResponse(200, deviceFixture), nil })
	if _, err := authorizeDevice(context.Background(), "", nil, client, waitDevice); err == nil || calls != 0 {
		t.Fatal("missing registration made a network request")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := authorizeDevice(ctx, "test-client-id", nil, client, waitDevice); err == nil {
		t.Fatal("cancelled authorization succeeded")
	}
}

func TestNativeAuthorizationDoesNotFollowRedirectsOrExposeBodies(t *testing.T) {
	client := newHTTPClient()
	client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		r := jsonResponse(302, `native-test-token`)
		r.Header.Set("Location", "https://evil.invalid/")
		return r, nil
	})
	_, err := authorizeDevice(context.Background(), "test-client-id", nil, client, waitDevice)
	if err == nil || strings.Contains(err.Error(), "native-test-token") {
		t.Fatalf("unsafe response: %v", err)
	}
	for _, body := range []string{strings.Repeat("x", 17*1024), "not json"} {
		client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		if _, err := authorizeDevice(context.Background(), "test-client-id", nil, client, waitDevice); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
}
