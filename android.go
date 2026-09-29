package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

var androidAttestOID = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11}

type androidBlob struct {
	Fmt     string   `json:"fmt"`
	Package string   `json:"package"`
	Certs   []string `json:"certs"`
	Counter int      `json:"counter"`
	Sig     string   `json:"sig"`
}

type androidFacts struct {
	Public      *ecdsa.PublicKey
	Packages    []string
	Versions    []int
	Digests     []string
	AttestLevel string
	KeyLevel    string
	Boot        string
	Locked      bool
	HaveBoot    bool
}

func decodeB64(s string) ([]byte, error) {
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func decodeAndroidBlob(blob string) (androidBlob, error) {
	raw, err := decodeB64(blob)
	if err != nil {
		raw = []byte(blob)
	}
	var parsed androidBlob
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return androidBlob{}, fmt.Errorf("attestation is not Android JSON")
	}
	if parsed.Fmt != "android-keystore" {
		return androidBlob{}, fmt.Errorf("attestation format is %q", parsed.Fmt)
	}
	return parsed, nil
}

func parseECPublicKey(pemText string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}
	return ec, nil
}

func verifyAndroidAttestation(blob, challenge, userID, keyID, pemText, wantPackage string) (androidFacts, error) {
	parsed, err := decodeAndroidBlob(blob)
	if err != nil {
		return androidFacts{}, err
	}
	if len(parsed.Certs) < 2 {
		return androidFacts{}, fmt.Errorf("attestation certificate chain is incomplete")
	}
	certs := make([]*x509.Certificate, 0, len(parsed.Certs))
	for i, item := range parsed.Certs {
		der, err := decodeB64(item)
		if err != nil {
			return androidFacts{}, fmt.Errorf("certificate %d is not base64", i+1)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return androidFacts{}, fmt.Errorf("certificate %d: %w", i+1, err)
		}
		certs = append(certs, cert)
	}
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return androidFacts{}, fmt.Errorf("certificate %d is not signed by certificate %d", i+1, i+2)
		}
	}
	if !androidRootTrusted(certs[len(certs)-1]) {
		return androidFacts{}, fmt.Errorf("certificate chain does not end at a Google hardware attestation root")
	}

	sum := sha256.Sum256([]byte(challenge + "&&" + userID))
	fields, ok := keyDescription(certs[0].Raw)
	if !ok || len(fields) < 5 || !bytes.Equal(fields[4].value, sum[:]) {
		return androidFacts{}, fmt.Errorf("attestation challenge is not SHA-256 of %s&&%s", challenge, userID)
	}
	attestLevel, okA := derInt(fields[1])
	keyLevel, okK := derInt(fields[3])
	if !okA || !okK {
		return androidFacts{}, fmt.Errorf("attestation security level is missing")
	}
	if attestLevel < 1 || keyLevel < 1 {
		return androidFacts{}, fmt.Errorf("key was created in software (%s / %s), not in a hardware keystore", levelName(attestLevel), levelName(keyLevel))
	}

	leaf, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return androidFacts{}, fmt.Errorf("attested key is not ECDSA")
	}
	idSum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	computedID := base64.StdEncoding.EncodeToString(idSum[:])
	if computedID != keyID {
		return androidFacts{}, fmt.Errorf("key id is %s, attested certificate is %s", keyID, computedID)
	}
	published, err := parseECPublicKey(pemText)
	if err != nil {
		return androidFacts{}, err
	}
	if !published.Equal(leaf) {
		return androidFacts{}, fmt.Errorf("published public key does not match the attested certificate")
	}

	packages, versions, digests, boot, locked, haveBoot := readAuthLists(fields)
	if parsed.Package != "" && parsed.Package != wantPackage {
		return androidFacts{}, fmt.Errorf("attestation names package %s, expected %s", parsed.Package, wantPackage)
	}
	if !containsString(packages, wantPackage) {
		found := "none"
		if len(packages) > 0 {
			found = strings.Join(packages, ", ")
		}
		return androidFacts{}, fmt.Errorf("hardware attestation package is %s, expected %s", found, wantPackage)
	}
	if !haveBoot {
		return androidFacts{}, fmt.Errorf("verified boot state is missing from the hardware attestation")
	}
	if boot != "Verified" || !locked {
		lock := "unlocked"
		if locked {
			lock = "locked"
		}
		return androidFacts{}, fmt.Errorf("device boot state is %s and the bootloader is %s", boot, lock)
	}

	return androidFacts{
		Public:      leaf,
		Packages:    packages,
		Versions:    versions,
		Digests:     digestHex(digests),
		AttestLevel: levelName(attestLevel),
		KeyLevel:    levelName(keyLevel),
		Boot:        boot,
		Locked:      locked,
		HaveBoot:    true,
	}, nil
}

func androidRootTrusted(last *x509.Certificate) bool {
	for _, root := range androidRoots() {
		if bytes.Equal(last.Raw, root.Raw) {
			return true
		}
		if last.CheckSignatureFrom(root) == nil {
			return true
		}
	}
	return false
}

func verifyAndroidAssertion(pub *ecdsa.PublicKey, clientData, assertion string, previous int) (int, error) {
	parsed, err := decodeAndroidBlob(assertion)
	if err != nil {
		return 0, fmt.Errorf("assertion is not an Android keystore assertion")
	}
	if parsed.Counter <= previous {
		return 0, fmt.Errorf("counter %d is not newer than %d", parsed.Counter, previous)
	}
	sig, err := decodeB64(parsed.Sig)
	if err != nil || len(sig) == 0 {
		return 0, fmt.Errorf("assertion signature is missing")
	}
	sum := sha256.Sum256([]byte(clientData))
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return 0, fmt.Errorf("signature does not verify")
	}
	return parsed.Counter, nil
}

func keyDescription(leaf []byte) ([]derNode, bool) {
	search := 0
	for {
		rel := bytes.Index(leaf[search:], androidAttestOID)
		if rel < 0 {
			return nil, false
		}
		pos := search + rel
		off := pos + len(androidAttestOID)
		if off < len(leaf) && leaf[off] == 0x01 {
			if _, ok := derRead(leaf, &off); !ok {
				search = pos + 1
				continue
			}
		}
		ext, ok := derRead(leaf, &off)
		if !ok || ext.number != 4 || ext.class != 0 {
			search = pos + 1
			continue
		}
		inner := 0
		seq, ok := derRead(ext.value, &inner)
		if !ok || seq.number != 16 {
			search = pos + 1
			continue
		}
		var fields []derNode
		cursor := 0
		for cursor < len(seq.value) {
			field, ok := derRead(seq.value, &cursor)
			if !ok {
				break
			}
			fields = append(fields, field)
		}
		if len(fields) >= 5 {
			return fields, true
		}
		search = pos + 1
	}
}

func readAuthLists(fields []derNode) (packages []string, versions []int, digests [][]byte, boot string, locked, haveBoot bool) {
	for _, index := range []int{6, 7} {
		if index >= len(fields) {
			continue
		}
		pkgs, vers, digs, b, lock, ok := packagesFromAuthList(fields[index].value)
		packages = append(packages, pkgs...)
		versions = append(versions, vers...)
		digests = append(digests, digs...)
		if ok {
			boot, locked, haveBoot = b, lock, true
		}
	}
	return packages, versions, digests, boot, locked, haveBoot
}

func packagesFromAuthList(raw []byte) (packages []string, versions []int, digests [][]byte, boot string, locked, haveBoot bool) {
	offset := 0
	for offset < len(raw) {
		item, ok := derRead(raw, &offset)
		if !ok {
			break
		}
		if item.class != 0x80 {
			continue
		}
		switch item.number {
		case 601, 709: // legacy schema and KeyMint ATTESTATION_APPLICATION_ID
			cursor := 0
			oct, ok := derRead(item.value, &cursor)
			appID := item.value
			if ok && oct.number == 4 && oct.class == 0 {
				appID = oct.value
			}
			pkgs, vers, digs := packagesFromAppID(appID)
			packages = append(packages, pkgs...)
			versions = append(versions, vers...)
			digests = append(digests, digs...)
		case 704:
			if b, lock, ok := parseRootOfTrust(item.value); ok {
				boot, locked, haveBoot = b, lock, true
			}
		}
	}
	return packages, versions, digests, boot, locked, haveBoot
}

func packagesFromAppID(der []byte) ([]string, []int, [][]byte) {
	offset := 0
	seq, ok := derRead(der, &offset)
	if !ok {
		return nil, nil, nil
	}
	cursor := 0
	var sets []derNode
	for cursor < len(seq.value) {
		set, ok := derRead(seq.value, &cursor)
		if !ok {
			break
		}
		sets = append(sets, set)
	}
	var packages []string
	var versions []int
	if len(sets) > 0 {
		itemOff := 0
		for itemOff < len(sets[0].value) {
			info, ok := derRead(sets[0].value, &itemOff)
			if !ok {
				break
			}
			nameOff := 0
			name, ok := derRead(info.value, &nameOff)
			if ok && name.number == 4 && name.class == 0 && len(name.value) > 0 {
				packages = append(packages, string(name.value))
				version := 0
				if ver, ok := derRead(info.value, &nameOff); ok {
					if n, ok := derInt(ver); ok {
						version = n
					}
				}
				versions = append(versions, version)
			}
		}
	}
	var digests [][]byte
	if len(sets) > 1 {
		itemOff := 0
		for itemOff < len(sets[1].value) {
			dig, ok := derRead(sets[1].value, &itemOff)
			if !ok {
				break
			}
			if dig.number == 4 && dig.class == 0 && len(dig.value) > 0 {
				digests = append(digests, append([]byte(nil), dig.value...))
			}
		}
	}
	return packages, versions, digests
}

func parseRootOfTrust(raw []byte) (string, bool, bool) {
	cur := 0
	seq, ok := derRead(raw, &cur)
	body := raw
	if ok && seq.number == 16 {
		body = seq.value
	}
	c := 0
	if _, ok := derRead(body, &c); !ok {
		return "", false, false
	}
	lockedNode, ok := derRead(body, &c)
	if !ok {
		return "", false, false
	}
	stateNode, ok := derRead(body, &c)
	if !ok {
		return "", false, false
	}
	locked := len(lockedNode.value) > 0 && lockedNode.value[len(lockedNode.value)-1] != 0
	state, ok := derInt(stateNode)
	if !ok {
		return "", false, false
	}
	names := []string{"Verified", "SelfSigned", "Unverified", "Failed"}
	name := fmt.Sprintf("unknown(%d)", state)
	if state >= 0 && state < len(names) {
		name = names[state]
	}
	return name, locked, true
}

func levelName(n int) string {
	switch n {
	case 0:
		return "Software"
	case 1:
		return "TrustedEnvironment"
	case 2:
		return "StrongBox"
	default:
		return fmt.Sprintf("unknown(%d)", n)
	}
}

func digestHex(digests [][]byte) []string {
	out := make([]string, 0, len(digests))
	seen := map[string]bool{}
	for _, d := range digests {
		h := hex.EncodeToString(d)
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
