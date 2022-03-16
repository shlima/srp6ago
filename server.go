package srp6ago

import (
	"crypto/subtle"
	"fmt"
	"math/big"
)

// Server
// @refs RFC-5054 https://datatracker.ietf.org/doc/html/rfc5054
// @refs RFC-2945 https://datatracker.ietf.org/doc/html/rfc2945
//
// N, g: group parameters (prime and generator)
// s: salt
// B, b: server's public and private values
// A, a: client's public and private values
// I: user name (aka "identity")
// P: password
// v: verifier
// k: SRP-6 multiplier (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
// S: pre-master secret
// K = SHA_Interleave(S) shared secret key
//
// m1: client proof H(PAD(A) | PAD(B) | PAD(S))
// m2: server proof H(PAD(A) | M1 | PAD(S))
type Server struct {
	s []byte
	v *big.Int
	e *engine

	b *big.Int
	B *big.Int
	A *big.Int
	u *big.Int

	S  []byte
	m1 []byte
	m2 []byte
}

func NewServer(verifier, seed []byte, params Params) *Server {
	return &Server{
		v: new(big.Int).SetBytes(verifier),
		s: seed,
		e: NewEngine(params),
	}
}

// PublicKey
// The pre-master secret is calculated by the server as follows:
//
// N, g, s, v = <read from password file>
// b = random()
// k = SHA1(N | PAD(g))
// B = k*v + g^b % N
// A = <read from client>
// u = SHA1(PAD(A) | PAD(B))
// <pre-master secret> = (A * v^u) ^ b % N
func (s *Server) PublicKey() ([]byte, error) {
	if s.b == nil { // b might be set from tests
		if salt, err := s.randomSalt(); err != nil {
			return nil, fmt.Errorf("failed to generate a salt: %w", err)
		} else {
			s.b = big.NewInt(0).SetBytes(salt)
		}
	}

	i1 := new(big.Int).Mul(s.e.k(), s.v)
	i2 := new(big.Int).Exp(s.e.g, s.b, s.e.N)
	i1.Add(i1, i2)
	s.B = i1.Mod(i1, s.e.N)

	return s.B.Bytes(), nil
}

// @test
func (s *Server) set_b(input []byte) {
	s.b = new(big.Int).SetBytes(input)
}

func (s *Server) SetClientPublicKey(A []byte) error {
	s.A = new(big.Int).SetBytes(A)
	s.u = new(big.Int).SetBytes(s.e.HASH(s.e.PAD(s.A.Bytes()), s.e.PAD(s.B.Bytes())))

	// The host MUST abort the authentication attempt if A % N is zero.
	if s.e.isModZero(s.A, s.e.N) {
		return ErrAbort
	}

	i1 := new(big.Int).Exp(s.v, s.u, s.e.N)
	i2 := new(big.Int).Mul(i1, s.A)
	s.S = new(big.Int).Exp(i2, s.b, s.e.N).Bytes()

	s.m1 = s.e.HASH(s.e.PAD(s.A.Bytes()), s.e.PAD(s.B.Bytes()), s.e.PAD(s.S))
	s.m2 = s.e.HASH(s.e.PAD(s.A.Bytes()), s.m1, s.e.PAD(s.S))

	return nil
}

func (s *Server) IsProofValid(m1 []byte) bool {
	return subtle.ConstantTimeCompare(m1, s.m1) == 1
}

func (s *Server) SecretKey() []byte {
	return s.S
}

func (s *Server) Proof() []byte {
	return s.m2
}

func (s *Server) randomSalt() ([]byte, error) {
	return s.e.Random(s.e.NLen())
}
