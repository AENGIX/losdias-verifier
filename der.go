package main

type derNode struct {
	class  int
	number int
	value  []byte
}

func derRead(der []byte, offset *int) (derNode, bool) {
	if *offset >= len(der) {
		return derNode{}, false
	}
	tag := int(der[*offset])
	*offset++
	var number int
	if tag&0x1f == 0x1f {
		number = 0
		for {
			if *offset >= len(der) {
				return derNode{}, false
			}
			b := int(der[*offset])
			*offset++
			number = (number << 7) | (b & 0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	} else {
		number = tag & 0x1f
	}
	if *offset >= len(der) {
		return derNode{}, false
	}
	size := int(der[*offset])
	*offset++
	if size&0x80 != 0 {
		count := size & 0x7f
		if count == 0 || *offset+count > len(der) {
			return derNode{}, false
		}
		size = 0
		for i := 0; i < count; i++ {
			size = (size << 8) | int(der[*offset])
			*offset++
		}
	}
	if *offset+size > len(der) {
		return derNode{}, false
	}
	value := der[*offset : *offset+size]
	*offset += size
	return derNode{class: tag & 0xc0, number: number, value: value}, true
}

func derInt(n derNode) (int, bool) {
	if (n.number != 2 && n.number != 10) || len(n.value) == 0 || len(n.value) > 4 {
		return 0, false
	}
	v := 0
	for _, b := range n.value {
		v = (v << 8) | int(b)
	}
	return v, true
}
