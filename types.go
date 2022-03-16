package srp6ago

import "errors"

const (
	Sha1   = "SHA1"
	Sha256 = "SHA256"
	Sha512 = "SHA512"
)

var ErrAbort = errors.New("ERR_ABORT")
