package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const playIntegrityVerificationPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvR96Wn2cMcDLgtI0aGEwIP4FZYZB
Jh6qLzQN25+HoyHPpPYW1j3AgpYEzReyRJky/LYh3hs1s4kOb5CHKASsAw==
-----END PUBLIC KEY-----
`

func verifyPlayIntegrityJWS(compact, challenge, userID, pkg string, digests []string, startMidp, startRadi uint64) (string, error) {
	return verifyPlayIntegrityWithPEM(compact, playIntegrityVerificationPEM, challenge, userID, pkg, digests, startMidp, startRadi)
}

func verifyPlayIntegrityWithPEM(compact, verificationPEM, challenge, userID, pkg string, digests []string, startMidp, startRadi uint64) (string, error) {
	block, _ := pem.Decode([]byte(verificationPEM))
	if block == nil {
		return "", fmt.Errorf("Play Integrity verification key is not a PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("Play Integrity verification key: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("Play Integrity verification key is not ECDSA")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("Play Integrity verdict is not a compact JWS")
	}
	headerJSON, err := decodeB64URL(parts[0])
	if err != nil {
		return "", fmt.Errorf("Play Integrity header is not base64url")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil || header.Alg != "ES256" {
		return "", fmt.Errorf("Play Integrity verdict is not signed with ES256")
	}
	sig, err := decodeB64URL(parts[2])
	if err != nil || len(sig) != 64 {
		return "", fmt.Errorf("Play Integrity signature is not a P-256 signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return "", fmt.Errorf("Play Integrity verdict signature does not verify")
	}
	payloadJSON, err := decodeB64URL(parts[1])
	if err != nil {
		return "", fmt.Errorf("Play Integrity payload is not base64url")
	}
	var payload struct {
		RequestDetails struct {
			RequestPackageName string          `json:"requestPackageName"`
			Nonce              string          `json:"nonce"`
			TimestampMillis    json.RawMessage `json:"timestampMillis"`
		} `json:"requestDetails"`
		AppIntegrity struct {
			PackageName             string   `json:"packageName"`
			AppRecognitionVerdict   string   `json:"appRecognitionVerdict"`
			CertificateSha256Digest []string `json:"certificateSha256Digest"`
		} `json:"appIntegrity"`
		DeviceIntegrity struct {
			DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
		} `json:"deviceIntegrity"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", fmt.Errorf("Play Integrity payload is not JSON")
	}
	if payload.RequestDetails.RequestPackageName != pkg || payload.AppIntegrity.PackageName != pkg {
		found := payload.AppIntegrity.PackageName
		if found == "" {
			found = payload.RequestDetails.RequestPackageName
		}
		if found == "" {
			found = "missing"
		}
		return "", fmt.Errorf("Play Integrity package is %s, expected %s", found, pkg)
	}
	nonceInput := sha256.Sum256([]byte(challenge + "&&" + userID))
	wantNonce := base64.RawURLEncoding.EncodeToString(nonceInput[:])
	gotNonce := strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(payload.RequestDetails.Nonce), "=")
	if gotNonce == "" || gotNonce != wantNonce {
		return "", fmt.Errorf("Play Integrity nonce is not bound to the registration challenge")
	}
	if payload.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		verdict := payload.AppIntegrity.AppRecognitionVerdict
		if verdict == "" {
			verdict = "missing"
		}
		return "", fmt.Errorf("app recognition is %s", verdict)
	}
	strong := false
	for _, item := range payload.DeviceIntegrity.DeviceRecognitionVerdict {
		if item == "MEETS_STRONG_INTEGRITY" {
			strong = true
			break
		}
	}
	if !strong {
		listed := strings.Join(payload.DeviceIntegrity.DeviceRecognitionVerdict, ", ")
		if listed == "" {
			listed = "none"
		}
		return "", fmt.Errorf("device recognition is %s", listed)
	}
	if len(payload.AppIntegrity.CertificateSha256Digest) > 0 && len(digests) > 0 {
		if !playCertMatches(payload.AppIntegrity.CertificateSha256Digest, digests) {
			return "", fmt.Errorf("Play Integrity signing certificate does not match the hardware attestation")
		}
	}
	ts, err := playTimestamp(payload.RequestDetails.TimestampMillis)
	if err != nil {
		return "", err
	}
	if startMidp > 0 {
		limit := int64(startMidp/1000) + int64(startRadi/1000) + 120_000
		if ts > limit {
			return "", fmt.Errorf("Play Integrity verdict is after the stream started")
		}
	}
	when := time.UnixMilli(ts).UTC().Format(time.RFC3339)
	return fmt.Sprintf("PLAY_RECOGNIZED, MEETS_STRONG_INTEGRITY, package %s, nonce matches the registration challenge, verdict %s", pkg, when), nil
}

func playTimestamp(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("Play Integrity timestamp is missing")
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		ts, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("Play Integrity timestamp is not a number")
		}
		return normalizePlayMillis(ts), nil
	}
	var number int64
	if json.Unmarshal(raw, &number) == nil {
		return normalizePlayMillis(number), nil
	}
	return 0, fmt.Errorf("Play Integrity timestamp is not a number")
}

func normalizePlayMillis(ts int64) int64 {
	if ts > 0 && ts < 1_000_000_000_000 {
		return ts * 1000
	}
	return ts
}

func playCertMatches(encoded, hexDigests []string) bool {
	want := map[string]bool{}
	for _, item := range hexDigests {
		want[strings.ToLower(item)] = true
	}
	for _, item := range encoded {
		raw, err := decodeB64URL(item)
		if err != nil {
			continue
		}
		if want[hex.EncodeToString(raw)] {
			return true
		}
	}
	return false
}

func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(s), "=")
	return base64.RawURLEncoding.DecodeString(s)
}
