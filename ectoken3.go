// Package ectoken3 implements EdgeCast V3 Token generation.
package ectoken3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
)

const (
	ivsize       = 12 // 12 byte IV
	aesblocksize = 32 // AES-256
)

// Encrypt implements EdgeCast token encryption.
// AES-GCM-256 and SHA256 of 'secret' as 32 byte key.
func Encrypt(secret string, plaintext string) (string, error) {
	iv := make([]byte, ivsize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	keyhash := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(keyhash[:aesblocksize])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	return base64encode(gcm.Seal(iv, iv, []byte(plaintext), []byte{})), nil
}

// Newer versions of the base64 package add a WithPadding() method and
// at some point this is obsolete.
func base64encode(a []byte) string {
	enc := base64.URLEncoding.EncodeToString(a)
	return strings.TrimRight(enc, "=")
}
