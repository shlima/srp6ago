package srp6ago

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
)

const uint32Size = 4

var byteOrder = binary.LittleEndian

func (s *Server) Marshal() []byte {
	writer := bytes.NewBuffer(nil)

	putBytes(writer, s.e.Marshal())
	putBytes(writer, s.s)
	putBigInt(writer, s.v)
	putBigInt(writer, s.A)
	putBigInt(writer, s.B)
	putBigInt(writer, s.b)
	putBigInt(writer, s.u)
	putBytes(writer, s.S)
	putBytes(writer, s.m1)
	putBytes(writer, s.m2)

	return writer.Bytes()
}

func UnmarshalServer(data []byte) (*Server, error) {
	var err error
	s := new(Server)
	reader := bytes.NewBuffer(data)

	eb, err := getBytes(reader)
	if err != nil {
		return nil, err
	}

	if s.e, err = unmarshalEngine(eb); err != nil {
		return nil, err
	}

	if s.s, err = getBytes(reader); err != nil {
		return nil, err
	}

	if s.v, err = getBigInt(reader); err != nil {
		return nil, err
	}

	if s.A, err = getBigInt(reader); err != nil {
		return nil, err
	}

	if s.B, err = getBigInt(reader); err != nil {
		return nil, err
	}

	if s.b, err = getBigInt(reader); err != nil {
		return nil, err
	}

	if s.u, err = getBigInt(reader); err != nil {
		return nil, err
	}

	if s.S, err = getBytes(reader); err != nil {
		return nil, err
	}

	if s.m1, err = getBytes(reader); err != nil {
		return nil, err
	}

	if s.m2, err = getBytes(reader); err != nil {
		return nil, err
	}

	return s, nil
}

func (e *engine) Marshal() []byte {
	writer := bytes.NewBuffer(nil)

	putBytes(writer, []byte(e.hash))
	putBigInt(writer, e.N)
	putBigInt(writer, e.g)

	return writer.Bytes()
}

func unmarshalEngine(data []byte) (*engine, error) {
	var err error
	e := new(engine)
	reader := bytes.NewBuffer(data)

	if h, err := getBytes(reader); err != nil {
		return nil, err
	} else {
		e.hash = string(h)
	}

	if e.N, err = getBigInt(reader); err != nil {
		return nil, err
	}

	if e.g, err = getBigInt(reader); err != nil {
		return nil, err
	}

	return e, nil
}

func putBytes(writer io.Writer, data []byte) {
	size := binUint32(uint32(len(data)))

	_, _ = writer.Write(size)
	_, _ = writer.Write(data)
}

func putBigInt(writer io.Writer, input *big.Int) {
	if input == nil {
		input = big.NewInt(0)
	}

	data := input.Bytes()
	size := binUint32(uint32(len(data)))

	_, _ = writer.Write(size)
	_, _ = writer.Write(data)
}

func getBytes(reader io.Reader) ([]byte, error) {
	buf := makeUint32()
	if _, err := io.ReadAtLeast(reader, buf, len(buf)); err != nil {
		return nil, err
	}

	size := uint32Bin(buf)
	data := make([]byte, size)

	if _, err := io.ReadAtLeast(reader, data, int(size)); err != nil {
		return nil, err
	}

	return data, nil
}

func getBigInt(reader io.Reader) (*big.Int, error) {
	buf := makeUint32()

	if _, err := io.ReadAtLeast(reader, buf, len(buf)); err != nil {
		return nil, err
	}

	size := uint32Bin(buf)
	data := make([]byte, size)

	if _, err := io.ReadAtLeast(reader, data, int(size)); err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(data), nil
}

func binUint32(input uint32) []byte {
	buff := makeUint32()
	byteOrder.PutUint32(buff, input)
	return buff
}

func makeUint32() []byte {
	return make([]byte, uint32Size)
}

func uint32Bin(input []byte) uint32 {
	return byteOrder.Uint32(input)
}
