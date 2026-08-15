// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// The label that opens every signed message. Bumping it invalidates every
	// signature made under the old construction, which is the point: a client
	// that only knows v1 can never be fooled into accepting a v2 signature, and
	// vice versa.
	DeflectChallengeContext = "deflect-challenge-v1"

	DeflectChallengeHeader         = "X-Deflect-Challenge"
	DeflectChallengeResponseHeader = "X-Deflect-Challenge-Response"
	DeflectChallengeKeyIDHeader    = "X-Deflect-Challenge-Key-ID"

	DeflectChallengeAlgorithm = "ed25519"

	defaultDeflectChallengeKeyDir    = "/etc/banjax/deflect_challenge_keys"
	defaultDeflectChallengeMaxLength = 512

	deflectChallengeKeyFileVersion = 1
	deflectChallengeKeyDirMode     = 0o700
	deflectChallengeKeyFileMode    = 0o600
)

// DeflectChallengeMessage is the exact byte string signed by the edge and
// reconstructed by the client. Nothing else may ever be signed with these keys.
//
// The context label gives domain separation from any other protocol that might
// one day use an Ed25519 key here, and the host binds a signature to one site so
// a signature collected from domain A cannot be replayed as proof of domain B by
// an edge that holds keys for both.
//
// Layout, with no trailing newline:
//
//	deflect-challenge-v1 LF <host> LF <challenge>
//
// This is a wire contract shared with supporting-containers/challenge-client.
// Changing it means changing the version label too.
func DeflectChallengeMessage(host string, challenge string) []byte {
	return []byte(DeflectChallengeContext + "\n" + host + "\n" + challenge)
}

// DeflectChallengeKeyID derives a short, stable identifier from the public key
// itself, so it needs no counter and no registry: a client holding the public
// key can compute the expected ID and check the edge returned the right one.
func DeflectChallengeKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:8])
}

// DeflectChallengeKey is one domain's live keypair.
type DeflectChallengeKey struct {
	Domain    string
	KeyID     string
	CreatedAt time.Time
	Public    ed25519.PublicKey

	private ed25519.PrivateKey
}

// DeflectChallengePublicKey is the public half, in the shape the admin endpoint
// serves it. There is deliberately no field here that could hold private key
// material: the type itself is the guarantee.
type DeflectChallengePublicKey struct {
	Domain    string `json:"domain"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"` // base64 of the 32 raw bytes
	CreatedAt string `json:"created_at"`
}

// deflectChallengeKeyFile is the on-disk form. Only the 32-byte seed is stored;
// the expanded private key is derived on load.
type deflectChallengeKeyFile struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	Domain    string `json:"domain"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // base64 of the 32 raw bytes
	Seed      string `json:"seed"`       // base64 of the 32 raw seed bytes
	CreatedAt string `json:"created_at"`
}

// DeflectChallengeKeys holds one Ed25519 keypair per domain that has the feature
// turned on. It follows the PasswordProtectedPaths shape (derived state behind
// an atomic pointer, rebuilt by UpdateFromConfig on SIGHUP) and adds a mutex,
// because unlike that type this one generates keys and writes them to disk.
type DeflectChallengeKeys struct {
	// mutex serialises generate-and-persist. Readers never take it.
	mutex   sync.Mutex
	content atomic.Pointer[deflectChallengeContent]
	dir     string
}

type deflectChallengeContent struct {
	// known holds every key loaded or generated so far, including domains whose
	// config flag has since been turned off. Keeping them means re-enabling a
	// domain restores the same keypair rather than invalidating whatever public
	// key was already handed out.
	known map[string]*DeflectChallengeKey
	// enabled is the subset that currently answers the endpoint.
	enabled map[string]*DeflectChallengeKey
}

// NewDeflectChallengeKeys always returns a usable store, even alongside an
// error. A broken key directory should degrade this one endpoint to a 404, not
// take down an edge that is otherwise serving traffic fine.
func NewDeflectChallengeKeys(config *Config) (*DeflectChallengeKeys, error) {
	keys := &DeflectChallengeKeys{
		dir: config.DeflectChallengeKeyDir,
	}
	keys.content.Store(&deflectChallengeContent{
		known:   map[string]*DeflectChallengeKey{},
		enabled: map[string]*DeflectChallengeKey{},
	})

	return keys, keys.UpdateFromConfig(config)
}

// UpdateFromConfig mints a keypair for every newly enabled domain and rebuilds
// the enabled set. This is what implements "the key pair is generated the first
// time the domain name turns this feature on": adding a domain to
// deflect_challenge_sites and sending SIGHUP is the whole flow.
//
// It returns an error only for problems that affect every domain (an unusable
// key directory). A single bad domain or unreadable key file is logged and
// skipped, so one broken entry cannot take the feature down for the rest.
func (k *DeflectChallengeKeys) UpdateFromConfig(config *Config) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.dir = config.DeflectChallengeKeyDir

	if len(config.SitesToDeflectChallenge) == 0 {
		k.content.Store(&deflectChallengeContent{
			known:   k.content.Load().known,
			enabled: map[string]*DeflectChallengeKey{},
		})
		return nil
	}

	if err := os.MkdirAll(k.dir, deflectChallengeKeyDirMode); err != nil {
		return fmt.Errorf("deflect challenge key dir %v is unusable: %w", k.dir, err)
	}

	old := k.content.Load()

	// Copy-on-write: the old snapshot stays valid for any reader mid-request.
	known := make(map[string]*DeflectChallengeKey, len(old.known))
	for domain, key := range old.known {
		known[domain] = key
	}
	enabled := make(map[string]*DeflectChallengeKey)

	for domain, on := range config.SitesToDeflectChallenge {
		if !on {
			continue
		}
		domain = strings.ToLower(strings.TrimSpace(domain))

		if err := validateDeflectChallengeDomain(domain); err != nil {
			log.Printf("DEFLECT-CHALLENGE: refusing domain %q: %v", domain, err)
			continue
		}

		key, ok := known[domain]
		if !ok {
			var err error
			key, err = k.loadOrGenerateKey(domain, config.DeflectChallengeGenerateMissingKeys)
			if err != nil {
				log.Printf("DEFLECT-CHALLENGE: no key for %q: %v", domain, err)
				continue
			}
			known[domain] = key
		}
		enabled[domain] = key
	}

	k.content.Store(&deflectChallengeContent{known: known, enabled: enabled})

	return nil
}

// Get returns the key for a domain that currently has the feature enabled.
func (k *DeflectChallengeKeys) Get(domain string) (*DeflectChallengeKey, bool) {
	key, ok := k.content.Load().enabled[strings.ToLower(domain)]
	return key, ok
}

// Sign produces a signature over the domain-bound message. The returned key ID
// is the one actually used, which is what the client verifies against.
func (k *DeflectChallengeKeys) Sign(domain string, challenge string) (string, []byte, error) {
	key, ok := k.Get(domain)
	if !ok {
		return "", nil, fmt.Errorf("no deflect challenge key for domain %v", domain)
	}
	return key.KeyID, ed25519.Sign(key.private, DeflectChallengeMessage(key.Domain, challenge)), nil
}

// PublicKey returns the exportable half for one enabled domain.
func (k *DeflectChallengeKeys) PublicKey(domain string) (DeflectChallengePublicKey, bool) {
	key, ok := k.Get(domain)
	if !ok {
		return DeflectChallengePublicKey{}, false
	}
	return key.publicKey(), true
}

// PublicKeys returns the exportable halves for every enabled domain, sorted so
// the output is stable across calls.
func (k *DeflectChallengeKeys) PublicKeys() []DeflectChallengePublicKey {
	enabled := k.content.Load().enabled

	result := make([]DeflectChallengePublicKey, 0, len(enabled))
	for _, key := range enabled {
		result = append(result, key.publicKey())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Domain < result[j].Domain })

	return result
}

func (key *DeflectChallengeKey) publicKey() DeflectChallengePublicKey {
	return DeflectChallengePublicKey{
		Domain:    key.Domain,
		KeyID:     key.KeyID,
		Algorithm: DeflectChallengeAlgorithm,
		PublicKey: base64.StdEncoding.EncodeToString(key.Public),
		CreatedAt: key.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// validateDeflectChallengeDomain keeps a config typo from being able to write
// outside the key directory. Domains are refused rather than sanitised: silently
// mangling "a/b" into "a_b" would put two different sites on one key.
func validateDeflectChallengeDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("empty domain")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain is too long")
	}
	if strings.Contains(domain, "..") {
		return fmt.Errorf("domain contains \"..\"")
	}
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == ':':
		default:
			return fmt.Errorf("domain contains an unsupported character %q", c)
		}
	}
	return nil
}

// keyPath maps a domain to its key file. The domain is already validated, so the
// only substitution needed is the colon in a "host:port" domain, which is legal
// on Linux but awkward everywhere else.
func (k *DeflectChallengeKeys) keyPath(domain string) string {
	return filepath.Join(k.dir, strings.ReplaceAll(domain, ":", "_")+".json")
}

// loadOrGenerateKey prefers whatever is already on disk. Generating a fresh key
// for a domain that already has one would invalidate the public key that was
// handed to clients out of band, so a readable existing file always wins.
//
// generateMissing comes from deflect_challenge_generate_missing_keys and is off
// in production, where a provisioning script writes the key files.
func (k *DeflectChallengeKeys) loadOrGenerateKey(domain string, generateMissing bool) (*DeflectChallengeKey, error) {
	key, err := k.loadKey(domain)
	if err == nil {
		log.Printf("DEFLECT-CHALLENGE: loaded ed25519 key for %v key_id=%v", domain, key.KeyID)
		return key, nil
	}
	if !os.IsNotExist(err) {
		// A corrupt or unreadable file is not a licence to overwrite it: that
		// would destroy the only copy of a key clients may still be using.
		return nil, fmt.Errorf("existing key file is unusable (not overwriting): %w", err)
	}

	if !generateMissing {
		// Minting one here would produce a key whose public half nobody holds,
		// so every client would fail to verify -- a symptom indistinguishable
		// from the compromised edge this feature exists to detect. Better to
		// serve nothing for this domain and say why.
		return nil, fmt.Errorf(
			"no key file at %v and deflect_challenge_generate_missing_keys is off; "+
				"the provisioning script should have written one", k.keyPath(domain))
	}

	key, err = k.generateKey(domain)
	if err != nil {
		return nil, err
	}
	log.Printf("DEFLECT-CHALLENGE: generated ed25519 key for %v key_id=%v", domain, key.KeyID)

	return key, nil
}

func (k *DeflectChallengeKeys) loadKey(domain string) (*DeflectChallengeKey, error) {
	path := k.keyPath(domain)

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err // may be os.IsNotExist, which the caller checks for
	}

	var onDisk deflectChallengeKeyFile
	if err := json.Unmarshal(contents, &onDisk); err != nil {
		return nil, fmt.Errorf("failed to parse %v: %w", path, err)
	}

	if onDisk.Version != deflectChallengeKeyFileVersion {
		return nil, fmt.Errorf("%v has unsupported version %d", path, onDisk.Version)
	}
	if onDisk.Algorithm != DeflectChallengeAlgorithm {
		return nil, fmt.Errorf("%v has unsupported algorithm %q", path, onDisk.Algorithm)
	}
	if onDisk.Domain != domain {
		return nil, fmt.Errorf("%v holds a key for %q, not %q", path, onDisk.Domain, domain)
	}

	seed, err := base64.StdEncoding.DecodeString(onDisk.Seed)
	if err != nil {
		return nil, fmt.Errorf("%v has an undecodable seed: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%v has a %d byte seed, want %d", path, len(seed), ed25519.SeedSize)
	}

	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)

	// The stored public key and key ID are conveniences for anyone reading the
	// file; the seed is the source of truth. Disagreement means the file was
	// edited by hand, so refuse it rather than serve a key ID that does not
	// match the signatures we would produce.
	if base64.StdEncoding.EncodeToString(public) != onDisk.PublicKey {
		return nil, fmt.Errorf("%v public_key does not match its seed", path)
	}
	if keyID := DeflectChallengeKeyID(public); keyID != onDisk.KeyID {
		return nil, fmt.Errorf("%v key_id does not match its public key", path)
	}

	createdAt, err := time.Parse(time.RFC3339, onDisk.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("%v has an unparseable created_at: %w", path, err)
	}

	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		log.Printf("DEFLECT-CHALLENGE: %v is group/world readable (mode %v); private key is exposed",
			path, info.Mode().Perm())
	}

	return &DeflectChallengeKey{
		Domain:    onDisk.Domain,
		KeyID:     onDisk.KeyID,
		CreatedAt: createdAt,
		Public:    public,
		private:   private,
	}, nil
}

func (k *DeflectChallengeKeys) generateKey(domain string) (*DeflectChallengeKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate an ed25519 key: %w", err)
	}

	key := &DeflectChallengeKey{
		Domain:    domain,
		KeyID:     DeflectChallengeKeyID(public),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		Public:    public,
		private:   private,
	}

	if err := k.writeKey(key); err != nil {
		return nil, err
	}

	return key, nil
}

// writeKey persists a key with temp-file-plus-rename, so a crash mid-write can
// never leave a truncated key where a whole one used to be.
func (k *DeflectChallengeKeys) writeKey(key *DeflectChallengeKey) error {
	path := k.keyPath(key.Domain)

	onDisk := deflectChallengeKeyFile{
		Version:   deflectChallengeKeyFileVersion,
		Algorithm: DeflectChallengeAlgorithm,
		Domain:    key.Domain,
		KeyID:     key.KeyID,
		PublicKey: base64.StdEncoding.EncodeToString(key.Public),
		Seed:      base64.StdEncoding.EncodeToString(key.private.Seed()),
		CreatedAt: key.CreatedAt.Format(time.RFC3339),
	}
	contents, err := json.MarshalIndent(onDisk, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key file: %w", err)
	}
	contents = append(contents, '\n')

	tmp, err := os.CreateTemp(k.dir, ".deflect-challenge-*.json.tmp")
	if err != nil {
		return fmt.Errorf("failed to create a temp key file: %w", err)
	}
	// Harmless once the rename below has succeeded.
	defer os.Remove(tmp.Name())

	// Chmod before writing, so the private key is never briefly world readable.
	if err := tmp.Chmod(deflectChallengeKeyFileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to chmod the temp key file: %w", err)
	}
	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write the temp key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync the temp key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close the temp key file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("failed to rename the temp key file into place: %w", err)
	}

	// Sync the directory too, so the rename itself survives a power loss.
	if dir, err := os.Open(k.dir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}

	return nil
}

// deflectChallenge answers a client's nonce with a signature over it, proving
// the responder holds the domain's private key and is therefore a Deflect edge.
//
// Unlike decisionForNginx this handler's response is the response the client
// sees, so everything it sets on the way out is part of the protocol.
func deflectChallenge(configHolder *ConfigHolder, keys *DeflectChallengeKeys) gin.HandlerFunc {
	return func(c *gin.Context) {
		config := configHolder.Get()

		// A signature is never reusable, so it must never be cached anywhere.
		c.Header("Cache-Control", "no-store")

		if c.Request.Method != http.MethodPost {
			c.Header("Allow", http.MethodPost)
			c.JSON(405, gin.H{"error": "deflect challenge requires POST"})
			return
		}

		// nginx sets X-Requested-Host from $host. The fallback covers hitting
		// banjax directly, which is what standalone testing does.
		host := c.Request.Header.Get("X-Requested-Host")
		if host == "" {
			host = c.Request.Host
		}
		host = strings.ToLower(strings.TrimSpace(host))

		// One 404 for both "unknown host" and "feature off": which one it is
		// tells an unauthenticated caller something about the edge's config.
		key, ok := keys.Get(host)
		if !ok {
			c.JSON(404, gin.H{
				"error": "deflect challenge is not enabled for this host",
				"host":  host,
			})
			return
		}

		// Exactly one challenge header. Two would leave it ambiguous which value
		// the single returned signature covers.
		challenges := c.Request.Header.Values(DeflectChallengeHeader)
		if len(challenges) > 1 {
			c.JSON(400, gin.H{
				"error": fmt.Sprintf("expected one %s header, got %d",
					DeflectChallengeHeader, len(challenges)),
			})
			return
		}
		challenge := ""
		if len(challenges) == 1 {
			challenge = challenges[0]
		}
		if err := ValidateDeflectChallenge(challenge, config.DeflectChallengeMaxLength); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		signature := ed25519.Sign(key.private, DeflectChallengeMessage(key.Domain, challenge))
		encoded := base64.StdEncoding.EncodeToString(signature)

		// The request's key ID is advisory. Signing with the current key and
		// returning its real ID leaves it to the client to decide whether that
		// ID is one it trusts, which is what makes key rotation possible later
		// without a protocol change.
		c.Header(DeflectChallengeKeyIDHeader, key.KeyID)
		c.Header(DeflectChallengeResponseHeader, encoded)

		// The body repeats the headers so the endpoint is debuggable with curl
		// alone, and echoes the challenge back so a client can confirm nothing
		// in the middle mangled it.
		c.JSON(200, gin.H{
			"domain":    key.Domain,
			"key_id":    key.KeyID,
			"algorithm": DeflectChallengeAlgorithm,
			"challenge": challenge,
			"response":  encoded,
		})
	}
}

// ValidateDeflectChallenge bounds what the edge is willing to sign.
//
// Printable non-space ASCII keeps the value round-trippable through a header,
// keeps it unambiguous inside the newline-separated signed message, and keeps it
// safe to echo back in a JSON body.
func ValidateDeflectChallenge(challenge string, maxLength int) error {
	if challenge == "" {
		return fmt.Errorf("missing or empty %s header", DeflectChallengeHeader)
	}
	if len(challenge) > maxLength {
		return fmt.Errorf("challenge is %d bytes, the maximum is %d", len(challenge), maxLength)
	}
	for i := 0; i < len(challenge); i++ {
		if challenge[i] < 0x21 || challenge[i] > 0x7e {
			return fmt.Errorf("challenge must be printable non-space ASCII")
		}
	}
	return nil
}
