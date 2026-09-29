package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var appleNonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

func verifyAppleAttestation(blob, challenge, userID, keyID, pemText, appID string) (*ecdsa.PublicKey, string, error) {
	raw, err := decodeB64(blob)
	if err != nil {
		return nil, "", fmt.Errorf("attestation is not base64")
	}
	decoded, err := decodeCBOR(raw)
	if err != nil {
		return nil, "", fmt.Errorf("attestation: %w", err)
	}
	obj, err := cborMap(decoded)
	if err != nil {
		return nil, "", err
	}
	fmtName, err := cborText(obj, "fmt")
	if err != nil || fmtName != "apple-appattest" {
		return nil, "", fmt.Errorf("attestation format is not apple-appattest")
	}
	stmt, err := cborMap(must(obj, "attStmt"))
	if err != nil {
		return nil, "", fmt.Errorf("attestation statement is missing")
	}
	x5c, ok := stmt["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		return nil, "", fmt.Errorf("attestation certificate chain is incomplete")
	}
	authData, err := cborBytes(obj, "authData")
	if err != nil || len(authData) < 55 {
		return nil, "", fmt.Errorf("authenticator data is incomplete")
	}
	certs := make([]*x509.Certificate, 0, len(x5c)+1)
	for i, item := range x5c {
		der, ok := item.([]byte)
		if !ok {
			return nil, "", fmt.Errorf("certificate %d is not a byte string", i+1)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, "", fmt.Errorf("certificate %d: %w", i+1, err)
		}
		certs = append(certs, cert)
	}
	root := appleRoot()
	certs = append(certs, root)
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, "", fmt.Errorf("certificate %d is not signed by certificate %d", i+1, i+2)
		}
	}

	clientHash := sha256.Sum256([]byte(challenge + "&&" + userID))
	nonceInput := append(append([]byte{}, authData...), clientHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	var ext []byte
	for _, e := range certs[0].Extensions {
		if e.Id.Equal(appleNonceOID) {
			ext = e.Value
			break
		}
	}
	got, err := appleNonce(ext)
	if err != nil || !bytes.Equal(got, nonce[:]) {
		return nil, "", fmt.Errorf("attestation challenge is not bound to %s&&%s", challenge, userID)
	}

	if len(authData) < 37 || !bytes.Equal(authData[33:37], []byte{0, 0, 0, 0}) {
		return nil, "", fmt.Errorf("attestation counter is not zero")
	}
	aaguid := authData[37:53]
	prod := append([]byte("appattest"), make([]byte, 7)...)
	dev := []byte("appattestdevelop")
	env := ""
	switch {
	case bytes.Equal(aaguid, prod):
		env = "production"
	case bytes.Equal(aaguid, dev):
		env = "development"
	default:
		return nil, "", fmt.Errorf("attestation environment is not App Attest")
	}
	credLen := int(authData[53])<<8 | int(authData[54])
	if len(authData) < 55+credLen {
		return nil, "", fmt.Errorf("credential id is truncated")
	}
	credID := authData[55 : 55+credLen]
	keyRaw, err := decodeB64(keyID)
	if err != nil || !bytes.Equal(credID, keyRaw) {
		return nil, "", fmt.Errorf("key id does not match the attested credential")
	}
	rpID := authData[:32]
	appHash := sha256.Sum256([]byte(appID))
	if !bytes.Equal(rpID, appHash[:]) {
		return nil, "", fmt.Errorf("app id is not %s", appID)
	}
	leaf, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("attested key is not ECDSA")
	}
	pointHash := sha256.Sum256(uncompressedPoint(leaf))
	if !bytes.Equal(pointHash[:], credID) {
		return nil, "", fmt.Errorf("credential id does not match the attested public key")
	}
	published, err := parseECPublicKey(pemText)
	if err != nil {
		return nil, "", err
	}
	if !published.Equal(leaf) {
		return nil, "", fmt.Errorf("published public key does not match the attested certificate")
	}
	return leaf, env, nil
}

func verifyAppleAssertion(pub *ecdsa.PublicKey, clientData, assertion, appID string, previous int) (int, error) {
	raw, err := decodeB64(assertion)
	if err != nil {
		return 0, fmt.Errorf("assertion is not base64")
	}
	decoded, err := decodeCBOR(raw)
	if err != nil {
		return 0, fmt.Errorf("assertion: %w", err)
	}
	obj, err := cborMap(decoded)
	if err != nil {
		return 0, err
	}
	authData, err := cborBytes(obj, "authenticatorData")
	if err != nil || len(authData) < 37 {
		return 0, fmt.Errorf("authenticator data is incomplete")
	}
	sig, err := cborBytes(obj, "signature")
	if err != nil || len(sig) == 0 {
		return 0, fmt.Errorf("assertion signature is missing")
	}
	clientHash := sha256.Sum256([]byte(clientData))
	nonce := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signed := sha256.Sum256(nonce[:])
	if !ecdsa.VerifyASN1(pub, signed[:], sig) {
		return 0, fmt.Errorf("signature does not verify")
	}
	appHash := sha256.Sum256([]byte(appID))
	if !bytes.Equal(authData[:32], appHash[:]) {
		return 0, fmt.Errorf("app id is not %s", appID)
	}
	counter := int(authData[33])<<24 | int(authData[34])<<16 | int(authData[35])<<8 | int(authData[36])
	if counter <= previous {
		return 0, fmt.Errorf("counter %d is not newer than %d", counter, previous)
	}
	return counter, nil
}

func appleNonce(ext []byte) ([]byte, error) {
	if len(ext) == 0 {
		return nil, fmt.Errorf("nonce extension is missing")
	}
	off := 0
	seq, ok := derRead(ext, &off)
	if !ok {
		return nil, fmt.Errorf("nonce extension is truncated")
	}
	body := ext
	if seq.number == 16 {
		body = seq.value
	}
	cur := 0
	inner, ok := derRead(body, &cur)
	if !ok {
		return nil, fmt.Errorf("nonce extension has no value")
	}
	if inner.number == 4 && inner.class == 0 {
		return inner.value, nil
	}
	c2 := 0
	oct, ok := derRead(inner.value, &c2)
	if ok && oct.number == 4 && oct.class == 0 {
		return oct.value, nil
	}
	if len(inner.value) == 32 {
		return inner.value, nil
	}
	return nil, fmt.Errorf("nonce extension has no octet string")
}

func uncompressedPoint(pub *ecdsa.PublicKey) []byte {
	size := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*size)
	out[0] = 0x04
	pub.X.FillBytes(out[1 : 1+size])
	pub.Y.FillBytes(out[1+size:])
	return out
}

func must(m map[any]any, key string) any {
	return m[key]
}
