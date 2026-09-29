package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	defaultCDN          = "https://cdn.losdias.aengix.com"
	defaultPackage      = "com.aengix.losdias.android"
	defaultAppleID      = "A59M2YXS84.com.aengix.losdias.ios"
	cloudflareRoughtime = "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
)

type options struct {
	cdn         string
	pkg         string
	appID       string
	signingCert string
	json        bool
}

type check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type report struct {
	Broadcast string  `json:"broadcast"`
	Source    string  `json:"source"`
	OK        bool    `json:"ok"`
	Checks    []check `json:"checks"`
}

func (r *report) pass(name, detail string) {
	r.Checks = append(r.Checks, check{Name: name, Status: "PASS", Detail: detail})
}

func (r *report) fail(name, detail string) {
	r.Checks = append(r.Checks, check{Name: name, Status: "FAIL", Detail: detail})
}

func (r *report) warn(name, detail string) {
	r.Checks = append(r.Checks, check{Name: name, Status: "WARN", Detail: detail})
}

func (r *report) note(name, detail string) {
	r.Checks = append(r.Checks, check{Name: name, Status: "NOTE", Detail: detail})
}

func (r *report) finish() {
	r.OK = true
	for _, c := range r.Checks {
		if c.Status == "FAIL" {
			r.OK = false
			return
		}
	}
}

var httpClient = &http.Client{Timeout: 60 * time.Second}

func fetchBytes(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "losdias-verify")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", rawURL, resp.Status)
	}
	return body, nil
}

func verifyBroadcast(text, source, requestedID string, opt options) report {
	rep := report{Source: source}
	events, err := parseValidation(text)
	if err != nil {
		rep.fail("validation", err.Error())
		rep.finish()
		return rep
	}
	enc, ok := findEvent(events, "ENCODER_ATTESTATION")
	gen, genOK := findEvent(events, "STREAM_GENESIS")
	assertions, assertOK := findEvent(events, "ASSERTIONS")
	end, endOK := findEvent(events, "STREAM_END")
	authority, authOK := findEvent(events, "TIME_AUTHORITY")
	if !ok || !genOK || !assertOK || !endOK || !authOK {
		rep.fail("validation", "file is missing encoder, time authority, genesis, assertions, or stream end")
		rep.finish()
		return rep
	}
	for _, ev := range []event{authority, gen, assertions, end} {
		if spec := ev.Fields["SPEC_VERSION"]; spec != "" && spec != "3.0.0" {
			rep.fail("spec", "event "+ev.Type+" is spec "+spec)
			rep.finish()
			return rep
		}
	}

	streamID := gen.Fields["STREAM_ID"]
	rep.Broadcast = streamID
	if requestedID != "" && streamID != requestedID {
		rep.fail("broadcast", "file is for "+streamID+", requested "+requestedID)
	}
	userID := enc.Fields["USER_ID"]
	encoder := enc.Fields["ENCODER"]
	identifier := enc.Fields["ENCODER_IDENTIFIER"]
	genesis := gen.Fields["NONCE"]
	if streamID == "" || userID == "" || genesis == "" {
		rep.fail("validation", "stream id, user id, or genesis is missing")
		rep.finish()
		return rep
	}

	var pub *ecdsa.PublicKey
	switch encoder {
	case "GOOGLE":
		if identifier != opt.pkg {
			rep.fail("encoder", "file names "+identifier+", expected "+opt.pkg)
		}
		var digests []string
		facts, err := verifyAndroidAttestation(
			strings.Join(enc.Data, ""),
			enc.Fields["ENCODER_CHALLENGE"],
			userID,
			enc.Fields["ENCODER_ORIGIN_KEY_ID"],
			enc.Fields["ENCODER_ORIGIN_PUBLIC_KEY"],
			opt.pkg,
		)
		if err != nil {
			rep.fail("attestation", err.Error())
		} else {
			lock := "unlocked"
			if facts.Locked {
				lock = "locked"
			}
			version := ""
			if len(facts.Versions) > 0 {
				version = fmt.Sprintf(" versionCode %d", facts.Versions[0])
			}
			detail := fmt.Sprintf("%s key, attestation %s, boot %s, bootloader %s, package %s%s", facts.KeyLevel, facts.AttestLevel, facts.Boot, lock, opt.pkg, version)
			if len(facts.Digests) > 0 {
				detail += "; signing cert sha256 " + strings.Join(facts.Digests, ", ")
			}
			rep.pass("attestation", detail)
			if err := checkSigningCert(opt.signingCert, facts.Digests); err != nil {
				rep.fail("signing cert", err.Error())
			} else if opt.signingCert != "" {
				rep.pass("signing cert", "matches a digest in the hardware attestation")
			}
			pub = facts.Public
			digests = facts.Digests
		}
		jws := strings.TrimSpace(enc.Fields["PLAY_INTEGRITY_JWS"])
		if jws == "" {
			rep.note("play integrity", "PLAY_RECOGNIZED and MEETS_STRONG_INTEGRITY are not in the validation file, so they cannot be replayed. The hardware certificate is what this file proves.")
		} else {
			startMidp, _ := strconv.ParseUint(gen.Fields["START_MIDP"], 10, 64)
			startRadi, _ := strconv.ParseUint(gen.Fields["START_RADI"], 10, 64)
			detail, err := verifyPlayIntegrityJWS(jws, enc.Fields["ENCODER_CHALLENGE"], userID, opt.pkg, digests, startMidp, startRadi)
			if err != nil {
				rep.fail("play integrity", err.Error())
			} else {
				rep.pass("play integrity", detail)
			}
		}
	case "APPLE":
		if identifier != opt.appID {
			rep.fail("encoder", "file names "+identifier+", expected "+opt.appID)
		}
		key, env, err := verifyAppleAttestation(
			strings.Join(enc.Data, ""),
			enc.Fields["ENCODER_CHALLENGE"],
			userID,
			enc.Fields["ENCODER_ORIGIN_KEY_ID"],
			enc.Fields["ENCODER_ORIGIN_PUBLIC_KEY"],
			opt.appID,
		)
		if err != nil {
			rep.fail("attestation", err.Error())
		} else if env == "development" {
			rep.warn("attestation", "Apple App Attest development, app id "+opt.appID+"; test builds use this environment")
			pub = key
		} else {
			rep.pass("attestation", "Apple App Attest production, app id "+opt.appID)
			pub = key
		}
	default:
		rep.fail("encoder", "encoder is "+encoder)
	}
	if pub == nil {
		if key, err := parseECPublicKey(enc.Fields["ENCODER_ORIGIN_PUBLIC_KEY"]); err == nil {
			pub = key
		}
	}

	if authority.Fields["PUBLIC_KEY"] != cloudflareRoughtime || authority.Fields["AUTHORITY"] != "CLOUDFLARE" || authority.Fields["PROTOCOL"] != "Google-Roughtime" {
		rep.fail("time authority", "file does not pin Cloudflare Google Roughtime")
	} else {
		rep.pass("time authority", "Cloudflare Roughtime "+cloudflareRoughtime)
	}
	root, err := decodeB64(cloudflareRoughtime)
	if err != nil {
		rep.fail("time authority", "pinned public key is not base64")
		rep.finish()
		return rep
	}

	startChallenge := gen.Fields["START_CHALLENGE"]
	genesisRaw, err := decodeB64(genesis)
	if err != nil || len(genesisRaw) != sha256.Size {
		rep.fail("genesis", "genesis nonce is not 32-byte base64")
	} else if startChallenge == "" || gen.Fields["START_ROUGHTIME"] == "" {
		rep.fail("genesis", "start challenge or start roughtime packet is missing")
	} else {
		packet, err := decodeB64(gen.Fields["START_ROUGHTIME"])
		if err != nil {
			rep.fail("start roughtime", "packet is not base64")
		} else {
			midp, radi, err := verifyRoughtime(packet, fragmentNonce(startChallenge, genesisRaw), root)
			if err != nil {
				rep.fail("start roughtime", err.Error())
			} else if strconv.FormatUint(midp, 10) != gen.Fields["START_MIDP"] || strconv.FormatUint(uint64(radi), 10) != gen.Fields["START_RADI"] {
				rep.fail("start roughtime", "packet midpoint or radius does not match the file")
			} else {
				rep.pass("start roughtime", formatRoughtime(midp, radi))
			}
		}
	}

	segs, err := parseSegments(assertions.Data)
	if err != nil {
		rep.fail("segments", err.Error())
		rep.finish()
		return rep
	}
	fallback := 2.0
	if raw := gen.Fields["FRAGMENT_DURATION_SECONDS"]; raw != "" {
		if n, err := strconv.ParseFloat(raw, 64); err == nil && n > 0 {
			fallback = n
		}
	}
	proved := verifySegments(&rep, segs, streamID, userID, genesis, encoder, opt.appID, pub, fallback)

	lastHash := end.Fields["LAST_HASH"]
	endChallenge := end.Fields["END_CHALLENGE"]
	endSeq := end.Fields["SEQ"]
	var last segment
	var haveLast bool
	for _, seg := range segs {
		if !seg.gap {
			last = seg
			haveLast = true
		}
	}
	if !haveLast {
		rep.fail("stream end", "broadcast has no proved segments")
	} else if lastHash != last.hash || endSeq != strconv.Itoa(last.seq) {
		rep.fail("stream end", "last hash or sequence does not match the last proved segment")
	}
	lastRaw, err := decodeB64(lastHash)
	if err != nil || len(lastRaw) != sha256.Size || endChallenge == "" {
		rep.fail("end roughtime", "end challenge or last hash is missing")
	} else {
		packet, err := decodeB64(end.Fields["END_ROUGHTIME"])
		if err != nil {
			rep.fail("end roughtime", "packet is not base64")
		} else {
			midp, radi, err := verifyRoughtime(packet, fragmentNonce(endChallenge, lastRaw), root)
			if err != nil {
				rep.fail("end roughtime", err.Error())
			} else if strconv.FormatUint(midp, 10) != end.Fields["END_MIDP"] || strconv.FormatUint(uint64(radi), 10) != end.Fields["END_RADI"] {
				rep.fail("end roughtime", "packet midpoint or radius does not match the file")
			} else {
				rep.pass("end roughtime", formatRoughtime(midp, radi))
			}
		}
	}
	wantEnd := fmt.Sprintf("%s&&%s&&last=%s&&roughtime=%s&&seq=%s", endChallenge, userID, lastHash, end.Fields["END_ROUGHTIME"], endSeq)
	if end.Fields["DATA_TO_ASSERT"] != wantEnd {
		rep.fail("stream end", "signed close payload does not match the end challenge, last hash, roughtime packet, and sequence")
	}
	if pub == nil {
		rep.fail("close assertion", "no public key is available to verify the close signature")
	} else {
		recorded, _ := strconv.Atoi(end.Fields["ASSERTION_COUNTER"])
		counter, err := verifyAssertion(encoder, pub, end.Fields["DATA_TO_ASSERT"], end.Fields["ASSERTION_STRING"], opt.appID, proved.lastCounter)
		if err != nil {
			rep.fail("close assertion", err.Error())
		} else if recorded != counter && recorded+1 != counter {
			rep.fail("close assertion", fmt.Sprintf("file records counter %d, signature counter is %d", recorded, counter))
		} else {
			rep.pass("close assertion", fmt.Sprintf("counter %d verifies the close payload", counter))
		}
	}

	if proved.complete {
		verifyContinuity(&rep, proved.media, proved.gaps, gen, end)
	}
	rep.finish()
	return rep
}

type provedMedia struct {
	complete    bool
	media       float64
	gaps        int
	lastCounter int
}

func verifySegments(rep *report, segs []segment, streamID, userID, genesis, encoder, appID string, pub *ecdsa.PublicKey, fallback float64) provedMedia {
	if len(segs) == 0 {
		rep.fail("segments", "no segment lines")
		return provedMedia{}
	}
	proved := map[int]segment{}
	gaps := map[int]bool{}
	maxSeq := -1
	var ordered []segment
	for _, seg := range segs {
		if seg.seq > maxSeq {
			maxSeq = seg.seq
		}
		if seg.gap {
			if gaps[seg.seq] || proved[seg.seq].uri != "" {
				rep.fail("segments", fmt.Sprintf("sequence %d is recorded twice", seg.seq))
				return provedMedia{}
			}
			gaps[seg.seq] = true
			continue
		}
		if _, ok := proved[seg.seq]; ok || gaps[seg.seq] {
			rep.fail("segments", fmt.Sprintf("sequence %d is recorded twice", seg.seq))
			return provedMedia{}
		}
		proved[seg.seq] = seg
		ordered = append(ordered, seg)
	}
	for seq := 0; seq <= maxSeq; seq++ {
		if _, ok := proved[seq]; !ok && !gaps[seq] {
			rep.fail("segments", fmt.Sprintf("sequence %d is neither proved nor marked as a gap", seq))
			return provedMedia{}
		}
	}

	var prevHash string
	prevSeq := -1
	var hashes, sigs int
	var counters []int
	previous := 0
	var recordedNote bool
	var media float64
	for _, seg := range ordered {
		base := path.Base(seg.uri)
		if base != fmt.Sprintf("%s_%d.ts", streamID, seg.seq) {
			rep.fail("segments", fmt.Sprintf("segment %d filename is %s", seg.seq, base))
			return provedMedia{}
		}
		u, err := url.Parse(seg.uri)
		if err != nil || u.Scheme != "https" {
			rep.fail("segments", fmt.Sprintf("segment %d URI is not https", seg.seq))
			return provedMedia{}
		}
		if seg.seq == 0 {
			if seg.prev != genesis {
				rep.fail("hash chain", "segment 0 previous hash is not the genesis nonce")
				return provedMedia{}
			}
		} else if prevSeq >= 0 && seg.seq == prevSeq+1 && seg.prev != prevHash {
			rep.fail("hash chain", fmt.Sprintf("segment %d previous hash is not the hash of segment %d", seg.seq, prevSeq))
			return provedMedia{}
		}
		prefix := genesis + "&&" + userID + "&&"
		tail := fmt.Sprintf("&&prev=%s&&seq=%d&&ts_sha256=%s", seg.prev, seg.seq, seg.hash)
		if !strings.HasPrefix(seg.clientData, prefix) || !strings.HasSuffix(seg.clientData, tail) {
			rep.fail("segments", fmt.Sprintf("segment %d signed payload does not bind genesis, user, previous hash, sequence, and chunk hash", seg.seq))
			return provedMedia{}
		}
		body, err := fetchBytes(seg.uri)
		if err != nil {
			rep.fail("segments", fmt.Sprintf("segment %d: %s", seg.seq, err.Error()))
			return provedMedia{}
		}
		sum := sha256.Sum256(body)
		got := base64.StdEncoding.EncodeToString(sum[:])
		if got != seg.hash {
			rep.fail("hash chain", fmt.Sprintf("segment %d bytes hash to %s, file says %s", seg.seq, got, seg.hash))
			return provedMedia{}
		}
		hashes++
		if seconds, ok := mediaSeconds(body); ok {
			media += seconds
		} else {
			media += fallback
		}
		if pub == nil {
			rep.fail("assertions", "no public key is available to verify signatures")
			return provedMedia{}
		}
		counter, err := verifyAssertion(encoder, pub, seg.clientData, seg.assertion, appID, previous)
		if err != nil {
			rep.fail("assertions", fmt.Sprintf("segment %d: %s", seg.seq, err.Error()))
			return provedMedia{}
		}
		if seg.recordedCounter != counter && seg.recordedCounter+1 != counter {
			rep.fail("assertions", fmt.Sprintf("segment %d file records counter %d, signature counter is %d", seg.seq, seg.recordedCounter, counter))
			return provedMedia{}
		}
		if seg.recordedCounter+1 == counter && seg.recordedCounter != counter {
			recordedNote = true
		}
		counters = append(counters, counter)
		previous = counter
		sigs++
		prevHash = seg.hash
		prevSeq = seg.seq
	}
	detail := fmt.Sprintf("%d segment hashes match the published bytes, %d signatures verify", hashes, sigs)
	if len(counters) > 0 {
		detail += fmt.Sprintf(", signed counters %d–%d", counters[0], counters[len(counters)-1])
	}
	if recordedNote {
		detail += "; the file records the counter from before each assertion"
	}
	rep.pass("segments", detail)
	return provedMedia{complete: true, media: media, gaps: len(gaps), lastCounter: previous}
}

func verifyAssertion(encoder string, pub *ecdsa.PublicKey, clientData, assertion, appID string, previous int) (int, error) {
	if encoder == "APPLE" {
		return verifyAppleAssertion(pub, clientData, assertion, appID, previous)
	}
	return verifyAndroidAssertion(pub, clientData, assertion, previous)
}

func verifyContinuity(rep *report, media float64, gaps int, gen, end event) {
	startMidp, err1 := strconv.ParseUint(gen.Fields["START_MIDP"], 10, 64)
	endMidp, err2 := strconv.ParseUint(end.Fields["END_MIDP"], 10, 64)
	startRadi, err3 := strconv.ParseUint(gen.Fields["START_RADI"], 10, 64)
	endRadi, err4 := strconv.ParseUint(end.Fields["END_RADI"], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		rep.fail("continuity", "midpoint or radius is not a number")
		return
	}
	delta := int64(endMidp) - int64(startMidp)
	mediaUS := int64(math.Round(media * 1e6))
	slack := int64(startRadi) + int64(endRadi) + 1_000_000
	pass := gaps == 0 && delta >= mediaUS-slack && delta <= mediaUS+slack
	got := "FAIL"
	if pass {
		got = "PASS"
	}
	mediaText := strconv.FormatFloat(media, 'f', 6, 64)
	windowText := strconv.FormatFloat(float64(delta)/1e6, 'f', 6, 64)
	if end.Fields["CONTINUITY"] != got || end.Fields["GAPS"] != strconv.Itoa(gaps) || !near(end.Fields["MEDIA_SECONDS"], mediaText) || !near(end.Fields["WINDOW_SECONDS"], windowText) {
		rep.fail("continuity", fmt.Sprintf("recomputed %s, media %ss, window %ss, gaps %d; file says %s, media %ss, window %ss, gaps %s", got, mediaText, windowText, gaps, end.Fields["CONTINUITY"], end.Fields["MEDIA_SECONDS"], end.Fields["WINDOW_SECONDS"], end.Fields["GAPS"]))
		return
	}
	rep.pass("continuity", fmt.Sprintf("%s, media %ss inside window %ss, gaps %d", got, mediaText, windowText, gaps))
}

func near(published, got string) bool {
	if published == got {
		return true
	}
	a, err1 := strconv.ParseFloat(published, 64)
	b, err2 := strconv.ParseFloat(got, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	return math.Abs(a-b) < 0.0000005
}

func checkSigningCert(path string, digests []string) error {
	if path == "" {
		return nil
	}
	body, err := fetchOrRead(path)
	if err != nil {
		return err
	}
	var der []byte
	if block, _ := pem.Decode(body); block != nil {
		der = block.Bytes
	} else {
		der = body
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("signing certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	got := hex.EncodeToString(sum[:])
	if !containsString(digests, got) {
		return fmt.Errorf("certificate sha256 %s is not in the attestation", got)
	}
	return nil
}

func formatRoughtime(midp uint64, radi uint32) string {
	when := time.UnixMicro(int64(midp)).UTC().Format(time.RFC3339Nano)
	return fmt.Sprintf("%s ±%s", when, time.Duration(radi)*time.Microsecond)
}

func fetchOrRead(path string) ([]byte, error) {
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		return fetchBytes(path)
	}
	return os.ReadFile(path)
}
