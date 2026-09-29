package main

import (
	"fmt"
	"strconv"
	"strings"
)

type event struct {
	Type   string
	Fields map[string]string
	Data   []string
}

func parseValidation(text string) ([]event, error) {
	var events []event
	var ev *event
	inData := false
	var pem []string
	pemFor := ""

	flushPEM := func() {
		if ev != nil && pemFor != "" && len(pem) > 0 {
			ev.Fields[pemFor] = strings.Join(pem, "\n") + "\n"
		}
		pem = nil
	}
	finish := func() {
		flushPEM()
		if ev != nil {
			ev.Type = ev.Fields["TYPE"]
			events = append(events, *ev)
			ev = nil
		}
		inData = false
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "-----BEGIN ") && !strings.HasSuffix(line, "EVENT-----") {
			pem = []string{line}
			continue
		}
		if pem != nil {
			pem = append(pem, line)
			if strings.HasPrefix(line, "-----END ") {
				flushPEM()
			}
			continue
		}
		switch line {
		case "-----BEGIN EVENT-----":
			finish()
			ev = &event{Fields: map[string]string{}}
			inData = false
			continue
		case "-----END EVENT-----":
			finish()
			continue
		}
		if ev == nil || line == "" {
			continue
		}
		if inData {
			ev.Data = append(ev.Data, line)
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		if key == "DATA" {
			inData = true
			if val != "" {
				ev.Data = append(ev.Data, val)
			}
			continue
		}
		ev.Fields[key] = val
		if val == "" {
			pemFor = key
		}
	}
	finish()
	if len(events) == 0 {
		return nil, fmt.Errorf("validation file has no events")
	}
	return events, nil
}

func findEvent(events []event, typ string) (event, bool) {
	for _, ev := range events {
		if ev.Type == typ {
			return ev, true
		}
	}
	return event{}, false
}

type segment struct {
	gap             bool
	seq             int
	uri             string
	hash            string
	prev            string
	clientData      string
	recordedCounter int
	assertion       string
}

func parseSegments(lines []string) ([]segment, error) {
	var out []segment
	for _, line := range lines {
		parts := strings.SplitN(line, ";;", 7)
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		if parts[0] == "GAP" {
			if len(parts) < 2 {
				return nil, fmt.Errorf("gap line is incomplete")
			}
			seq, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("gap sequence is not a number")
			}
			out = append(out, segment{gap: true, seq: seq})
			continue
		}
		if len(parts) != 7 {
			return nil, fmt.Errorf("assertion line has %d fields", len(parts))
		}
		seq, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("segment sequence %q is not a number", parts[0])
		}
		counter, err := strconv.Atoi(parts[5])
		if err != nil {
			return nil, fmt.Errorf("segment %d counter is not a number", seq)
		}
		out = append(out, segment{
			seq:             seq,
			uri:             parts[1],
			hash:            parts[2],
			prev:            parts[3],
			clientData:      parts[4],
			recordedCounter: counter,
			assertion:       parts[6],
		})
	}
	return out, nil
}
