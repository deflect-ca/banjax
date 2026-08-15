// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

func testDeflectChallengeConfig(t *testing.T, sites map[string]bool) *Config {
	t.Helper()
	return &Config{
		SitesToDeflectChallenge:   sites,
		DeflectChallengeKeyDir:    t.TempDir(),
		DeflectChallengeMaxLength: defaultDeflectChallengeMaxLength,
	}
}

func newTestDeflectChallengeKeys(t *testing.T, config *Config) *DeflectChallengeKeys {
	t.Helper()
	keys, err := NewDeflectChallengeKeys(config)
	if err != nil {
		t.Fatalf("NewDeflectChallengeKeys: %v", err)
	}
	return keys
}

// The signed message is a wire contract shared with challenge-client's shell
// implementation, so pin the exact bytes rather than round-tripping through the
// same function that produces them.
func TestDeflectChallengeMessage(t *testing.T) {
	got := string(DeflectChallengeMessage("example.com", "nonce123"))
	want := "deflect-challenge-v1\nexample.com\nnonce123"

	if got != want {
		t.Errorf("DeflectChallengeMessage = %q, want %q", got, want)
	}
	if strings.HasSuffix(got, "\n") {
		t.Error("DeflectChallengeMessage must not end with a newline")
	}
}

func TestDeflectChallengeKeyIDIsStable(t *testing.T) {
	// A fixed public key must always give the same ID, or a client that derived
	// the ID from the key it was handed would reject a legitimate edge.
	public := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))

	first := DeflectChallengeKeyID(public)
	if first != DeflectChallengeKeyID(public) {
		t.Error("DeflectChallengeKeyID is not deterministic")
	}
	if len(first) != 16 {
		t.Errorf("DeflectChallengeKeyID = %q, want 16 hex chars", first)
	}
}

func TestDeflectChallengeSignAndVerify(t *testing.T) {
	config := testDeflectChallengeConfig(t, map[string]bool{"example.com": true})
	keys := newTestDeflectChallengeKeys(t, config)

	key, ok := keys.Get("example.com")
	if !ok {
		t.Fatal("no key for an enabled domain")
	}

	keyID, signature, err := keys.Sign("example.com", "a-nonce")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if keyID != key.KeyID {
		t.Errorf("Sign returned key id %q, want %q", keyID, key.KeyID)
	}

	if !ed25519.Verify(key.Public, DeflectChallengeMessage("example.com", "a-nonce"), signature) {
		t.Error("a genuine signature failed to verify")
	}

	// The negative cases are the point: without these, a verifier that always
	// returned true would pass the check above.
	if ed25519.Verify(key.Public, DeflectChallengeMessage("evil.example", "a-nonce"), signature) {
		t.Error("a signature verified against the wrong domain")
	}
	if ed25519.Verify(key.Public, DeflectChallengeMessage("example.com", "another-nonce"), signature) {
		t.Error("a signature verified against the wrong nonce")
	}

	tampered := make([]byte, len(signature))
	copy(tampered, signature)
	tampered[0] ^= 1
	if ed25519.Verify(key.Public, DeflectChallengeMessage("example.com", "a-nonce"), tampered) {
		t.Error("a tampered signature verified")
	}

	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if ed25519.Verify(other, DeflectChallengeMessage("example.com", "a-nonce"), signature) {
		t.Error("a signature verified under an impostor key")
	}
}

func TestDeflectChallengeKeyPersistence(t *testing.T) {
	config := testDeflectChallengeConfig(t, map[string]bool{"example.com": true})

	first := newTestDeflectChallengeKeys(t, config)
	firstKey, ok := first.Get("example.com")
	if !ok {
		t.Fatal("no key generated for an enabled domain")
	}

	path := filepath.Join(config.DeflectChallengeKeyDir, "example.com.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no key file at %v: %v", path, err)
	}
	// The file holds a private key, so anything looser than 0600 is a leak.
	if perm := info.Mode().Perm(); perm != deflectChallengeKeyFileMode {
		t.Errorf("key file mode is %v, want %v", perm, os.FileMode(deflectChallengeKeyFileMode))
	}

	// A restart must load the existing key, not mint a new one: regenerating
	// would silently invalidate whatever public key clients were already given.
	second := newTestDeflectChallengeKeys(t, config)
	secondKey, ok := second.Get("example.com")
	if !ok {
		t.Fatal("key did not survive a reload")
	}
	if secondKey.KeyID != firstKey.KeyID {
		t.Errorf("key id changed across a reload: %q then %q", firstKey.KeyID, secondKey.KeyID)
	}
	if !secondKey.Public.Equal(firstKey.Public) {
		t.Error("public key changed across a reload")
	}
}

func TestDeflectChallengeDisableAndReEnable(t *testing.T) {
	config := testDeflectChallengeConfig(t, map[string]bool{"example.com": true})
	keys := newTestDeflectChallengeKeys(t, config)

	original, _ := keys.Get("example.com")

	config.SitesToDeflectChallenge = map[string]bool{"example.com": false}
	if err := keys.UpdateFromConfig(config); err != nil {
		t.Fatalf("UpdateFromConfig: %v", err)
	}
	if _, ok := keys.Get("example.com"); ok {
		t.Error("a disabled domain still answers")
	}

	// Re-enabling must restore the same keypair, so flipping the config off and
	// on again does not break clients holding the public key.
	config.SitesToDeflectChallenge = map[string]bool{"example.com": true}
	if err := keys.UpdateFromConfig(config); err != nil {
		t.Fatalf("UpdateFromConfig: %v", err)
	}
	restored, ok := keys.Get("example.com")
	if !ok {
		t.Fatal("a re-enabled domain does not answer")
	}
	if restored.KeyID != original.KeyID {
		t.Errorf("key id changed across a disable/enable: %q then %q", original.KeyID, restored.KeyID)
	}
}

func TestDeflectChallengeDomainsAreIndependent(t *testing.T) {
	config := testDeflectChallengeConfig(t, map[string]bool{"a.example": true, "b.example": true})
	keys := newTestDeflectChallengeKeys(t, config)

	a, okA := keys.Get("a.example")
	b, okB := keys.Get("b.example")
	if !okA || !okB {
		t.Fatal("both domains should have keys")
	}
	if a.KeyID == b.KeyID {
		t.Error("two domains share a keypair")
	}

	// The domain is inside the signed message, so a.example's signature must not
	// verify as proof of b.example even though the same edge holds both keys.
	_, signature, err := keys.Sign("a.example", "nonce")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if ed25519.Verify(b.Public, DeflectChallengeMessage("b.example", "nonce"), signature) {
		t.Error("a signature for one domain verified as another")
	}
}

func TestDeflectChallengeRefusesUnsafeDomains(t *testing.T) {
	// A config typo must not be able to write outside the key directory.
	unsafe := []string{"../escape", "a/b", "", "a..b", "domain with space"}

	config := testDeflectChallengeConfig(t, map[string]bool{})
	for _, domain := range unsafe {
		config.SitesToDeflectChallenge = map[string]bool{domain: true}
		if err := config.deflectChallengeUpdate(t); err != nil {
			t.Fatalf("UpdateFromConfig(%q): %v", domain, err)
		}
	}

	entries, err := os.ReadDir(config.DeflectChallengeKeyDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("unsafe domains wrote %d key files, want 0", len(entries))
	}
}

// deflectChallengeUpdate is a small helper so the unsafe-domain loop above stays
// readable; each iteration needs a fresh store over the same directory.
func (config *Config) deflectChallengeUpdate(t *testing.T) error {
	t.Helper()
	keys := &DeflectChallengeKeys{dir: config.DeflectChallengeKeyDir}
	keys.content.Store(&deflectChallengeContent{
		known:   map[string]*DeflectChallengeKey{},
		enabled: map[string]*DeflectChallengeKey{},
	})
	return keys.UpdateFromConfig(config)
}

func TestDeflectChallengeCorruptKeyFileIsNotOverwritten(t *testing.T) {
	config := testDeflectChallengeConfig(t, map[string]bool{"example.com": true})
	path := filepath.Join(config.DeflectChallengeKeyDir, "example.com.json")

	if err := os.WriteFile(path, []byte("{not json"), deflectChallengeKeyFileMode); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	keys := newTestDeflectChallengeKeys(t, config)
	if _, ok := keys.Get("example.com"); ok {
		t.Error("a domain with a corrupt key file should not answer")
	}

	// Overwriting would destroy the only copy of a key clients may still hold,
	// so a broken file has to be fixed by hand.
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(contents) != "{not json" {
		t.Error("a corrupt key file was overwritten")
	}
}

func TestValidateDeflectChallenge(t *testing.T) {
	const maxLength = 32

	cases := []struct {
		name      string
		challenge string
		wantErr   bool
	}{
		{"typical nonce", "cUYUS7YvOsMCkuXbSVblbA==", false},
		{"single character", "x", false},
		{"base64 padding and slashes", "a+b/c=", false},
		{"at the limit", strings.Repeat("x", maxLength), false},
		{"empty", "", true},
		{"one over the limit", strings.Repeat("x", maxLength+1), true},
		{"embedded space", "has a space", true},
		{"embedded newline", "has\nnewline", true},
		{"embedded NUL", "has\x00nul", true},
		{"non ascii", "héllo", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDeflectChallenge(tc.challenge, maxLength)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateDeflectChallenge(%q) error = %v, wantErr %v", tc.challenge, err, tc.wantErr)
			}
		})
	}
}

func TestDeflectChallengeConcurrentSigning(t *testing.T) {
	// Readers must never need the mutex, even while UpdateFromConfig is
	// rebuilding the map. Run with -race.
	config := testDeflectChallengeConfig(t, map[string]bool{"example.com": true})
	keys := newTestDeflectChallengeKeys(t, config)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				keys.Get("example.com")
				_, _, _ = keys.Sign("example.com", "nonce")
				keys.PublicKeys()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 25; j++ {
			if err := keys.UpdateFromConfig(config); err != nil {
				t.Errorf("UpdateFromConfig: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

// newDeflectChallengeTestServer wires only the endpoint under test, so the
// handler's behaviour is checked without the rest of the decision path.
func newDeflectChallengeTestServer(t *testing.T, config *Config) (*gin.Engine, *DeflectChallengeKeys) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	keys := newTestDeflectChallengeKeys(t, config)

	holder := &ConfigHolder{}
	holder.config.Store(config)

	r := gin.New()
	r.Any("/deflect_challenge", deflectChallenge(holder, keys))

	return r, keys
}

func doDeflectChallenge(r *gin.Engine, method string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/deflect_challenge", nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	return recorder
}

func TestDeflectChallengeHandler(t *testing.T) {
	config := testDeflectChallengeConfig(t, map[string]bool{"example.com": true})
	r, keys := newDeflectChallengeTestServer(t, config)
	key, _ := keys.Get("example.com")

	t.Run("signs for an enabled host", func(t *testing.T) {
		w := doDeflectChallenge(r, http.MethodPost, map[string]string{
			"X-Requested-Host":     "example.com",
			DeflectChallengeHeader: "a-nonce",
		})

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if got := w.Header().Get(DeflectChallengeKeyIDHeader); got != key.KeyID {
			t.Errorf("%s = %q, want %q", DeflectChallengeKeyIDHeader, got, key.KeyID)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}

		signature, err := base64.StdEncoding.DecodeString(w.Header().Get(DeflectChallengeResponseHeader))
		if err != nil {
			t.Fatalf("undecodable signature: %v", err)
		}
		if !ed25519.Verify(key.Public, DeflectChallengeMessage("example.com", "a-nonce"), signature) {
			t.Error("the returned signature does not verify")
		}

		// The body must agree with the headers, since the client checks both.
		var body struct {
			Domain    string `json:"domain"`
			KeyID     string `json:"key_id"`
			Challenge string `json:"challenge"`
			Response  string `json:"response"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unparseable body: %v", err)
		}
		if body.Challenge != "a-nonce" || body.Domain != "example.com" || body.KeyID != key.KeyID {
			t.Errorf("body does not echo the request: %+v", body)
		}
		if body.Response != w.Header().Get(DeflectChallengeResponseHeader) {
			t.Error("body signature differs from the header")
		}
	})

	t.Run("falls back to Host when nginx did not set X-Requested-Host", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/deflect_challenge", nil)
		request.Host = "example.com"
		request.Header.Set(DeflectChallengeHeader, "a-nonce")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, request)

		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("X-Requested-Host wins over Host", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/deflect_challenge", nil)
		request.Host = "not-enabled.example"
		request.Header.Set("X-Requested-Host", "example.com")
		request.Header.Set(DeflectChallengeHeader, "a-nonce")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, request)

		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("host is matched case insensitively", func(t *testing.T) {
		w := doDeflectChallenge(r, http.MethodPost, map[string]string{
			"X-Requested-Host":     "EXAMPLE.com",
			DeflectChallengeHeader: "a-nonce",
		})
		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("a mismatched key id still signs with the current key", func(t *testing.T) {
		// Advisory, not a demand: the client decides whether the returned ID is
		// one it trusts, which is what will make rotation possible.
		w := doDeflectChallenge(r, http.MethodPost, map[string]string{
			"X-Requested-Host":          "example.com",
			DeflectChallengeHeader:      "a-nonce",
			DeflectChallengeKeyIDHeader: "0000000000000000",
		})

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if got := w.Header().Get(DeflectChallengeKeyIDHeader); got != key.KeyID {
			t.Errorf("%s = %q, want the real key id %q", DeflectChallengeKeyIDHeader, got, key.KeyID)
		}
	})

	t.Run("a disabled host is 404", func(t *testing.T) {
		w := doDeflectChallenge(r, http.MethodPost, map[string]string{
			"X-Requested-Host":     "not-enabled.example",
			DeflectChallengeHeader: "a-nonce",
		})
		if w.Code != 404 {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})

	t.Run("a missing challenge is 400", func(t *testing.T) {
		w := doDeflectChallenge(r, http.MethodPost, map[string]string{"X-Requested-Host": "example.com"})
		if w.Code != 400 {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})

	t.Run("an oversized challenge is 400", func(t *testing.T) {
		w := doDeflectChallenge(r, http.MethodPost, map[string]string{
			"X-Requested-Host":     "example.com",
			DeflectChallengeHeader: strings.Repeat("x", config.DeflectChallengeMaxLength+1),
		})
		if w.Code != 400 {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})

	t.Run("two challenge headers are 400", func(t *testing.T) {
		// Two nonces and one signature would leave it ambiguous which was signed.
		request := httptest.NewRequest(http.MethodPost, "/deflect_challenge", nil)
		request.Header.Set("X-Requested-Host", "example.com")
		request.Header.Add(DeflectChallengeHeader, "first")
		request.Header.Add(DeflectChallengeHeader, "second")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, request)

		if w.Code != 400 {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})

	t.Run("GET is 405", func(t *testing.T) {
		w := doDeflectChallenge(r, http.MethodGet, map[string]string{
			"X-Requested-Host":     "example.com",
			DeflectChallengeHeader: "a-nonce",
		})
		if w.Code != 405 {
			t.Errorf("status = %d, want 405", w.Code)
		}
		if got := w.Header().Get("Allow"); got != http.MethodPost {
			t.Errorf("Allow = %q, want POST", got)
		}
	})
}

func TestDeflectChallengePublicKeyExportsNoPrivateKey(t *testing.T) {
	// The banjax admin vhost is reachable by anyone who can set a Host header,
	// so this endpoint must never carry private key material.
	config := testDeflectChallengeConfig(t, map[string]bool{"example.com": true})
	keys := newTestDeflectChallengeKeys(t, config)

	publicKey, ok := keys.PublicKey("example.com")
	if !ok {
		t.Fatal("no public key for an enabled domain")
	}

	encoded, err := json.Marshal(publicKey)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	key, _ := keys.Get("example.com")
	seed := base64.StdEncoding.EncodeToString(key.private.Seed())
	if strings.Contains(string(encoded), seed) {
		t.Error("the public key export contains the private key seed")
	}
	for _, forbidden := range []string{"seed", "private", "secret"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Errorf("the public key export mentions %q: %s", forbidden, encoded)
		}
	}

	if publicKey.PublicKey != base64.StdEncoding.EncodeToString(key.Public) {
		t.Error("the exported public key does not match the live one")
	}
}
