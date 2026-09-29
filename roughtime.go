package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func roughtimeTag(name string) uint32 {
	b := make([]byte, 4)
	copy(b, name)
	return binary.LittleEndian.Uint32(b)
}

func parseRoughtime(blob []byte) (map[uint32][]byte, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("packet is too short")
	}
	num := int(binary.LittleEndian.Uint32(blob[:4]))
	if num < 0 || num > 1024 {
		return nil, fmt.Errorf("packet has %d fields", num)
	}
	header := 4
	if num > 0 {
		header += 4*(num-1) + 4*num
	}
	if len(blob) < header {
		return nil, fmt.Errorf("packet header is truncated")
	}
	offsets := []int{0}
	pos := 4
	for i := 0; i < num-1; i++ {
		offsets = append(offsets, int(binary.LittleEndian.Uint32(blob[pos:pos+4])))
		pos += 4
	}
	tags := make([]uint32, num)
	for i := 0; i < num; i++ {
		tags[i] = binary.LittleEndian.Uint32(blob[pos : pos+4])
		pos += 4
	}
	values := blob[header:]
	offsets = append(offsets, len(values))
	out := map[uint32][]byte{}
	for i := 0; i < num; i++ {
		start, end := offsets[i], offsets[i+1]
		if start > end || end > len(values) || start%4 != 0 {
			return nil, fmt.Errorf("packet field bounds are invalid")
		}
		out[tags[i]] = values[start:end]
	}
	return out, nil
}

func roughtimeU32(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[:4]), true
}

func roughtimeU64(b []byte) (uint64, bool) {
	if len(b) < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b[:8]), true
}

func verifyRoughtime(packet, nonce, root []byte) (midp uint64, radi uint32, err error) {
	if len(root) != ed25519.PublicKeySize {
		return 0, 0, fmt.Errorf("time authority public key is not 32 bytes")
	}
	if len(nonce) != sha512.Size {
		return 0, 0, fmt.Errorf("roughtime nonce is not 64 bytes")
	}
	msg, err := parseRoughtime(packet)
	if err != nil {
		return 0, 0, fmt.Errorf("packet: %w", err)
	}
	srep := msg[roughtimeTag("SREP")]
	sig := msg[roughtimeTag("SIG")]
	certBin := msg[roughtimeTag("CERT")]
	indxBin := msg[roughtimeTag("INDX")]
	path := msg[roughtimeTag("PATH")]
	if len(srep) == 0 || len(sig) != ed25519.SignatureSize || len(certBin) == 0 {
		return 0, 0, fmt.Errorf("packet is missing SREP, SIG, or CERT")
	}
	cert, err := parseRoughtime(certBin)
	if err != nil {
		return 0, 0, fmt.Errorf("certificate: %w", err)
	}
	dele := cert[roughtimeTag("DELE")]
	certSig := cert[roughtimeTag("SIG")]
	if len(dele) == 0 || len(certSig) != ed25519.SignatureSize {
		return 0, 0, fmt.Errorf("certificate is missing DELE or SIG")
	}
	certContext := append([]byte("RoughTime v1 delegation signature--\x00"), dele...)
	if !ed25519.Verify(root, certContext, certSig) {
		return 0, 0, fmt.Errorf("delegation signature does not verify")
	}
	deleMsg, err := parseRoughtime(dele)
	if err != nil {
		return 0, 0, fmt.Errorf("delegation: %w", err)
	}
	pubk := deleMsg[roughtimeTag("PUBK")]
	mint, _ := roughtimeU64(deleMsg[roughtimeTag("MINT")])
	maxt, hasMaxt := roughtimeU64(deleMsg[roughtimeTag("MAXT")])
	_, hasMint := roughtimeU64(deleMsg[roughtimeTag("MINT")])
	if len(pubk) != ed25519.PublicKeySize {
		return 0, 0, fmt.Errorf("delegation public key is not 32 bytes")
	}
	srepContext := append([]byte("RoughTime v1 response signature\x00"), srep...)
	if !ed25519.Verify(pubk, srepContext, sig) {
		return 0, 0, fmt.Errorf("response signature does not verify")
	}
	srepMsg, err := parseRoughtime(srep)
	if err != nil {
		return 0, 0, fmt.Errorf("signed response: %w", err)
	}
	midp, ok := roughtimeU64(srepMsg[roughtimeTag("MIDP")])
	if !ok {
		return 0, 0, fmt.Errorf("signed response has no midpoint")
	}
	radi, ok = roughtimeU32(srepMsg[roughtimeTag("RADI")])
	if !ok {
		return 0, 0, fmt.Errorf("signed response has no radius")
	}
	rootHash := srepMsg[roughtimeTag("ROOT")]
	if len(rootHash) != sha512.Size {
		return 0, 0, fmt.Errorf("merkle root is not 64 bytes")
	}
	indx, ok := roughtimeU32(indxBin)
	if !ok {
		return 0, 0, fmt.Errorf("merkle index is missing")
	}
	if !roughtimeMerkle(nonce, indx, path, rootHash) {
		return 0, 0, fmt.Errorf("nonce is not in the merkle tree")
	}
	if hasMint && midp < mint {
		return 0, 0, fmt.Errorf("midpoint is before the delegation window")
	}
	if hasMaxt && midp > maxt {
		return 0, 0, fmt.Errorf("midpoint is after the delegation window")
	}
	return midp, radi, nil
}

func roughtimeMerkle(nonce []byte, index uint32, path, root []byte) bool {
	if len(root) != sha512.Size || len(path)%sha512.Size != 0 {
		return false
	}
	hash := sha512.Sum512(append([]byte{0x00}, nonce...))
	for off := 0; off < len(path); off += sha512.Size {
		sibling := path[off : off+sha512.Size]
		if index&1 == 0 {
			hash = sha512.Sum512(append(append([]byte{0x01}, hash[:]...), sibling...))
		} else {
			hash = sha512.Sum512(append(append([]byte{0x01}, sibling...), hash[:]...))
		}
		index >>= 1
	}
	return hex.EncodeToString(hash[:]) == hex.EncodeToString(root)
}

func fragmentNonce(challenge string, raw []byte) []byte {
	sum := sha512.Sum512(append([]byte(challenge), raw...))
	return sum[:]
}
