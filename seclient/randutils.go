package seclient

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// randomEmailLocalPart generates a cryptographically random base64 string
// used as the local-part of the anonymous subscriber email.
// Previously took an io.Reader (wrapping a math/rand.Rand backed by a
// crypto/rand source) — now calls crypto/rand.Reader directly, removing the
// intermediate rand.Rand wrapper and the secureRandomSource adapter.
func randomEmailLocalPart() (string, error) {
	b := make([]byte, ANON_EMAIL_LOCALPART_BYTES)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// randomCapitalHexString generates length cryptographically random bytes and
// returns them as an upper-case hex string.
func randomCapitalHexString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(b)), nil
}
