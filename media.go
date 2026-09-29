package main

func mediaSeconds(packet []byte) (float64, bool) {
	var minPTS, maxPTS int
	var maxPID int
	have := false
	for off := 0; off+188 <= len(packet); off += 188 {
		pkt := packet[off : off+188]
		if pkt[0] != 0x47 {
			continue
		}
		pid := int(pkt[1]&0x1f)<<8 | int(pkt[2])
		if pid != 0x100 && pid != 0x101 {
			continue
		}
		if pkt[1]&0x40 == 0 {
			continue
		}
		adapt := (pkt[3] >> 4) & 0x3
		payload := 4
		if adapt == 2 || adapt == 3 {
			payload = 5 + int(pkt[4])
		}
		if payload+14 > 188 {
			continue
		}
		if pkt[payload] != 0 || pkt[payload+1] != 0 || pkt[payload+2] != 1 {
			continue
		}
		if pkt[payload+7]&0xC0 == 0 {
			continue
		}
		pts := readPTS(pkt[payload+9:])
		if !have || pts < minPTS {
			minPTS = pts
		}
		if !have || pts >= maxPTS {
			maxPTS = pts
			maxPID = pid
		}
		have = true
	}
	if !have {
		return 0, false
	}
	extra := 1920
	if maxPID == 0x100 {
		extra = 3600
	}
	return float64(maxPTS-minPTS+extra) / 90000, true
}

func readPTS(b []byte) int {
	b0, b1, b2, b3, b4 := int(b[0]), int(b[1]), int(b[2]), int(b[3]), int(b[4])
	return ((b0 & 0x0e) << 29) |
		(b1 << 22) |
		((b2 & 0xfe) << 14) |
		(b3 << 7) |
		((b4 & 0xfe) >> 1)
}
