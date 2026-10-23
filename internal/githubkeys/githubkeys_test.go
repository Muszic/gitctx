package githubkeys

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6QTRtJ0t8hWLLFm7mjfB32c1nSe4NGWqYbTq/7UQ2J"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func testSession(t *testing.T, handler roundTripFunc) *Session {
	t.Helper()
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme != "https" || req.URL.Host != "api.github.com" || req.Header.Get("Authorization") != "Bearer private-test-token" {
			t.Fatal("request target or pinned authorization changed")
		}
		if req.URL.Path == "/user" {
			return jsonResponse(200, `{"login":"Ada","id":42}`), nil
		}
		return handler(req)
	})}
	session, err := openSession(context.Background(), "private-test-token", client)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestAccountIdentityAcceptsManagedUsersAndRejectsMalformedResponses(t *testing.T) {
	for _, test := range []struct {
		name, response string
		wantLogin      string
	}{
		{name: "personal", response: `{"login":"Ada","id":42}`, wantLogin: "Ada"},
		{name: "enterprise managed", response: `{"login":"mona-cat_octo","id":43}`, wantLogin: "mona-cat_octo"},
		{name: "missing ID", response: `{"login":"Ada"}`},
		{name: "missing login", response: `{"id":42}`},
		{name: "control character", response: `{"login":"Ada\nadmin","id":42}`},
		{name: "unexpected symbol", response: `{"login":"Ada/admin","id":42}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != "GET" || req.URL.Path != "/user" {
					t.Fatal("identity check attempted an unexpected operation")
				}
				return jsonResponse(200, test.response), nil
			})}
			session, err := openSession(context.Background(), "private-test-token", client)
			if test.wantLogin == "" {
				if err == nil {
					t.Fatal("accepted an invalid account response")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if session.Login() != test.wantLogin {
				t.Fatalf("login=%q want=%q", session.Login(), test.wantLogin)
			}
		})
	}
}

func TestRegistrationIsIdempotentAndUploadsOnlyPublicKey(t *testing.T) {
	keys := map[string]bool{}
	var posts []string
	session := testSession(t, func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case "GET":
			if keys[req.URL.Path] {
				body, _ := json.Marshal([]map[string]string{{"key": testKey + " old-comment"}})
				return jsonResponse(200, string(body)), nil
			}
			return jsonResponse(200, "[]"), nil
		case "POST":
			var body map[string]string
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 2 || body["key"] != testKey || body["title"] != "gitctx:personal" {
				t.Fatalf("unexpected upload body: %#v", body)
			}
			keys[req.URL.Path] = true
			posts = append(posts, req.URL.Path)
			encoded, _ := json.Marshal(body)
			return jsonResponse(201, string(encoded)), nil
		default:
			t.Fatalf("unexpected method: %s", req.Method)
			return nil, errors.New("unexpected method")
		}
	})
	defer session.Close()
	result, err := session.Register(context.Background(), testKey+" user-comment", "gitctx:personal", true)
	if err != nil || result.Authentication != Registered || result.Signing != Registered || len(posts) != 2 {
		t.Fatalf("initial result = %#v, posts = %v, error = %v", result, posts, err)
	}
	result, err = session.Register(context.Background(), testKey, "gitctx:personal", true)
	if err != nil || result.Authentication != Existing || result.Signing != Existing || len(posts) != 2 {
		t.Fatalf("repeat result = %#v, posts = %v, error = %v", result, posts, err)
	}
}

func TestPermissionPreflightMakesNoWrites(t *testing.T) {
	posts := 0
	session := testSession(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != "GET" {
			posts++
		}
		if req.URL.Path == "/user/ssh_signing_keys" {
			return jsonResponse(403, `{"message":"private-test-token"}`), nil
		}
		return jsonResponse(200, "[]"), nil
	})
	_, err := session.Register(context.Background(), testKey, "gitctx:personal", true)
	if err == nil || posts != 0 || strings.Contains(err.Error(), "private-test-token") {
		t.Fatalf("posts=%d, error=%v", posts, err)
	}
}

func TestPartialRegistrationCanBeRetriedWithoutDeletingKeys(t *testing.T) {
	authExists, allowSigning := false, false
	authPosts := 0
	session := testSession(t, func(req *http.Request) (*http.Response, error) {
		if req.Method == "GET" {
			if req.URL.Path == "/user/keys" && authExists {
				body, _ := json.Marshal([]map[string]string{{"key": testKey}})
				return jsonResponse(200, string(body)), nil
			}
			return jsonResponse(200, "[]"), nil
		}
		if req.Method != "POST" {
			t.Fatal("registration attempted to delete or modify existing data")
		}
		if req.URL.Path == "/user/keys" {
			authExists = true
			authPosts++
		} else if !allowSigning {
			return jsonResponse(403, "{}"), nil
		}
		body, _ := json.Marshal(map[string]string{"key": testKey})
		return jsonResponse(201, string(body)), nil
	})
	result, err := session.Register(context.Background(), testKey, "gitctx:personal", true)
	if err == nil || result.Authentication != Registered || result.Signing != "not confirmed" || !authExists {
		t.Fatalf("partial result=%#v error=%v", result, err)
	}
	allowSigning = true
	result, err = session.Register(context.Background(), testKey, "gitctx:personal", true)
	if err != nil || result.Authentication != Existing || result.Signing != Registered || authPosts != 1 {
		t.Fatalf("retry result=%#v authPosts=%d error=%v", result, authPosts, err)
	}
}

func TestConcurrentDuplicateAndLostResponseAreReconciled(t *testing.T) {
	for _, lostResponse := range []bool{false, true} {
		t.Run(fmt.Sprint(lostResponse), func(t *testing.T) {
			exists := false
			session := testSession(t, func(req *http.Request) (*http.Response, error) {
				if req.Method == "POST" {
					exists = true
					if lostResponse {
						return nil, errors.New("a transport error containing private-test-token")
					}
					return jsonResponse(422, "{}"), nil
				}
				if exists {
					body, _ := json.Marshal([]map[string]string{{"key": testKey}})
					return jsonResponse(200, string(body)), nil
				}
				return jsonResponse(200, "[]"), nil
			})
			result, err := session.Register(context.Background(), testKey, "gitctx:personal", false)
			if err != nil || result.Authentication != Existing || result.Signing != NotNeeded {
				t.Fatalf("result=%#v error=%v", result, err)
			}
		})
	}
}

func TestPaginationFindsExistingKeyAndClosedSessionRefusesRequests(t *testing.T) {
	requests := 0
	session := testSession(t, func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Method != "GET" {
			t.Fatal("existing key caused a write")
		}
		if req.URL.Query().Get("page") == "1" {
			keys := make([]map[string]string, 100)
			body, _ := json.Marshal(keys)
			return jsonResponse(200, string(body)), nil
		}
		body, _ := json.Marshal([]map[string]string{{"key": testKey}})
		return jsonResponse(200, string(body)), nil
	})
	result, err := session.Register(context.Background(), testKey, "gitctx:personal", false)
	if err != nil || result.Authentication != Existing || requests != 2 {
		t.Fatalf("result=%#v requests=%d error=%v", result, requests, err)
	}
	session.Close()
	_, err = session.Inspect(context.Background(), testKey, false)
	if err == nil || requests != 2 {
		t.Fatalf("closed session made requests: %d, error=%v", requests, err)
	}
}

func TestPublicKeySnapshotRejectsReplacementAndPrivateMaterial(t *testing.T) {
	blob, _ := base64.StdEncoding.DecodeString(strings.Fields(testKey)[1])
	digest := sha256.Sum256(blob)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	path := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(path, []byte(testKey+" email@example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := ReadPublicKey(path, fingerprint)
	if err != nil || key != testKey {
		t.Fatalf("key=%q error=%v", key, err)
	}
	if _, err := ReadPublicKey(path, "SHA256:replacement"); err == nil {
		t.Fatal("accepted a replaced public key")
	}
	for _, contents := range []string{
		"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----",
		testKey + "\n" + testKey,
		"command=evil " + testKey,
	} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPublicKey(path, fingerprint); err == nil {
			t.Fatal("accepted unsafe key contents")
		}
	}
}

func TestRedirectCannotForwardCredentialAndErrorsOmitSecrets(t *testing.T) {
	client := newHTTPClient()
	requests := 0
	client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Host != "api.github.com" {
			t.Fatal("credential was forwarded to a different host")
		}
		response := jsonResponse(302, `{"message":"private-test-token"}`)
		response.Header.Set("Location", "https://untrusted.example/user")
		return response, nil
	})
	_, err := openSession(context.Background(), "private-test-token", client)
	if err == nil || strings.Contains(err.Error(), "private-test-token") || requests != 1 {
		t.Fatalf("requests=%d error=%v", requests, err)
	}
}
