package srp6ago

import (
	"crypto/rand"
	"io"
	"math/big"
)

type engine struct {
	N    *big.Int
	g    *big.Int
	hash string
}

func NewEngine(params Params) *engine {
	return &engine{
		N:    new(big.Int).SetBytes(params.N),
		g:    big.NewInt(int64(params.G)),
		hash: params.Hash,
	}
}

func (e *engine) NLen() int {
	return e.N.BitLen() >> 3
}

func (e *engine) k() *big.Int {
	return new(big.Int).SetBytes(e.HASH(e.N.Bytes(), e.PAD(e.g.Bytes())))
}

// PAD
// Conversion between integers and byte-strings assumes the most
// significant bytes are stored first, as per [TLS] and [SRP-RFC].  In
// the following text, if a conversion from integer to byte-string is
// implicit, the most significant byte in the resultant byte-string MUST
// be non-zero.  If a conversion is explicitly specified with the
// operator PAD(), the integer will first be implicitly converted, then
// the resultant byte-string will be left-padded with zeros (if
// necessary) until its length equals the implicitly-converted length of
// N.
//
// In other words RFC5054 specifies that number should be
// left-padded with zeros to be the same length as N.
func (e *engine) PAD(input []byte) []byte {
	return pad(e.NLen(), input)
}

func (e *engine) HASH(inputs ...[]byte) []byte {
	return hash(e.hash, inputs...)
}

func (e *engine) HashedCred(username, password string) []byte {
	credentials := username + ":" + password
	return e.HASH([]byte(credentials))
}

func (e *engine) Random(len int) ([]byte, error) {
	out := make([]byte, len)
	_, err := io.ReadFull(rand.Reader, out)
	return out, err
}

func (e *engine) isModZero(a *big.Int, b *big.Int) bool {
	return new(big.Int).Mod(a, b).Sign() == 0
}
