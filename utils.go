package srp6ago

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"regexp"
)

var trimRE = regexp.MustCompile(`\s+|\r+\n+`)

func Hex2Bytes(input string) ([]byte, error) {
	return hex.DecodeString(trimRE.ReplaceAllLiteralString(input, ""))
}

func MustHex2Bytes(input string) []byte {
	out, err := Hex2Bytes(input)
	if err != nil {
		panic(fmt.Errorf("failed to decode a hex: %w", err))
	}

	return out
}

func pad(size int, input []byte) []byte {
	if len(input) >= size {
		return input
	}

	diff := size - len(input)
	out := make([]byte, diff+len(input))
	copy(out[diff:], input)

	return out
}

func hash(name string, inputs ...[]byte) []byte {
	h := newHash(name).New()

	for ix := range inputs {
		h.Write(inputs[ix])
	}

	return h.Sum(nil)
}

func newHash(enum string) crypto.Hash {
	switch enum {
	case Sha1:
		return crypto.SHA1
	case Sha256:
		return crypto.SHA256
	case Sha512:
		return crypto.SHA512
	default:
		return 0
	}
}
