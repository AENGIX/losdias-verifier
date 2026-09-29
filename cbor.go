package main

import (
	"encoding/binary"
	"fmt"
)

type cborReader struct {
	b []byte
	i int
}

func decodeCBOR(b []byte) (any, error) {
	r := cborReader{b: b}
	v, err := r.value()
	if err != nil {
		return nil, err
	}
	if r.i != len(r.b) {
		return nil, fmt.Errorf("cbor has %d trailing bytes", len(r.b)-r.i)
	}
	return v, nil
}

func (r *cborReader) value() (any, error) {
	if r.i >= len(r.b) {
		return nil, fmt.Errorf("cbor truncated")
	}
	head := r.b[r.i]
	r.i++
	major := head >> 5
	info := head & 0x1f
	n, err := r.arg(info)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return n, nil
	case 1:
		return int64(-1) ^ int64(n), nil
	case 2:
		return r.take(int(n))
	case 3:
		b, err := r.take(int(n))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case 4:
		arr := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			item, err := r.value()
			if err != nil {
				return nil, err
			}
			arr = append(arr, item)
		}
		return arr, nil
	case 5:
		m := map[any]any{}
		for i := uint64(0); i < n; i++ {
			k, err := r.value()
			if err != nil {
				return nil, err
			}
			v, err := r.value()
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		return m, nil
	case 6:
		return r.value()
	default:
		return nil, fmt.Errorf("unsupported cbor major type %d", major)
	}
}

func (r *cborReader) arg(info byte) (uint64, error) {
	if info < 24 {
		return uint64(info), nil
	}
	switch info {
	case 24:
		b, err := r.take(1)
		if err != nil {
			return 0, err
		}
		return uint64(b[0]), nil
	case 25:
		b, err := r.take(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(b)), nil
	case 26:
		b, err := r.take(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(b)), nil
	case 27:
		b, err := r.take(8)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(b), nil
	default:
		return 0, fmt.Errorf("unsupported cbor length %d", info)
	}
}

func (r *cborReader) take(n int) ([]byte, error) {
	if n < 0 || r.i+n > len(r.b) {
		return nil, fmt.Errorf("cbor truncated")
	}
	out := r.b[r.i : r.i+n]
	r.i += n
	return out, nil
}

func cborMap(v any) (map[any]any, error) {
	m, ok := v.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("cbor value is not a map")
	}
	return m, nil
}

func cborBytes(m map[any]any, key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("cbor map is missing %s", key)
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("cbor %s is not a byte string", key)
	}
	return b, nil
}

func cborText(m map[any]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("cbor map is missing %s", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("cbor %s is not a text string", key)
	}
	return s, nil
}
