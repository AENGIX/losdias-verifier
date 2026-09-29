package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func TestPlayIntegrityJWS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	challenge := "abc123"
	userID := "42"
	sum := sha256.Sum256([]byte(challenge + "&&" + userID))
	nonce := base64.RawURLEncoding.EncodeToString(sum[:])
	payload := `{"requestDetails":{"requestPackageName":"com.aengix.losdias.android","nonce":"` + nonce + `","timestampMillis":"1700000000000"},"appIntegrity":{"packageName":"com.aengix.losdias.android","appRecognitionVerdict":"PLAY_RECOGNIZED","certificateSha256Digest":["cQ2dQ0f2n2v3m3nQh2m2nQ=="]},"deviceIntegrity":{"deviceRecognitionVerdict":["MEETS_STRONG_INTEGRITY"]}}`
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(header + "." + body))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := append(pad32(r.Bytes()), pad32(s.Bytes())...)
	jws := header + "." + body + "." + base64.RawURLEncoding.EncodeToString(raw)
	detail, err := verifyPlayIntegrityWithPEM(jws, pubPEM, challenge, userID, "com.aengix.losdias.android", nil, 1_700_000_100_000_000, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "PLAY_RECOGNIZED") || !strings.Contains(detail, "MEETS_STRONG_INTEGRITY") {
		t.Fatalf("detail %s", detail)
	}
	if _, err := verifyPlayIntegrityWithPEM(jws, pubPEM, "other", userID, "com.aengix.losdias.android", nil, 1_700_000_100_000_000, 1_000_000); err == nil {
		t.Fatal("nonce mismatch was accepted")
	}
	if _, err := verifyPlayIntegrityWithPEM(jws, pubPEM, challenge, userID, "com.aengix.losdias.android", nil, 1_600_000_000_000_000, 0); err == nil {
		t.Fatal("verdict after the stream was accepted")
	}
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func TestPlayTimestampSeconds(t *testing.T) {
	if got := normalizePlayMillis(1_617_893_780); got != 1_617_893_780_000 {
		t.Fatalf("got %d", got)
	}
}
