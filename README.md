# srp6ago

[![Test](https://github.com/wault-pw/srp6ago/actions/workflows/test.yml/badge.svg)](https://github.com/wault-pw/srp6a-webcrypto/actions/workflows/test.yml)

This is tiny golang SRP6a implementation
fully complies with the RFC-5054/RFC-2945.

This server is used with [javascript](https://github.com/wault-pw/srp6a-webcrypto) 
SRP6a client implementation.

## Installation

```bash
go get github.com/wault-pw/srp6ago
```

## Usage

All returned values are bytes, so it's up to you how to encode the 
communication between server and client (protobuf or HEX representation 
with JSON).


### Login flow

```go
package main

import (
    "github.com/wault-pw/srp6ago"
)

func main() {
	// verifier and salt come from database
	// after user registration
	verifier, salt := []byte{}, []byte{}
	server := srp6ago.NewServer(verifier, salt, srp6ago.RFC5054b1024Sha1)
	
	// 1) send salt and server public key to the client
	serverPublicKey, _ := server.PublicKey()
	
	// 2) retrieve client's public key and a proof
	clientPublicKey, clientProof := []byte{}, []byte{}
	err := server.SetClientPublicKey(clientPublicKey)
	if err != nil {
        panic("server aborts")
	}
	
	// 3) Validate client proof
	// if OK, user is authenticates
	server.IsProofValid(clientProof)
	
	// 4) Now you have identical session key
	// with client
	server.SecretKey()
	
	// 5) You may send server proof back to the client
	server.Proof()
}
```
You can marshal SRP  server and restore its state between
HTTP requests:

```go
server := srp6ago.NewServer(verifier, salt, srp6ago.RFC5054b1024Sha1)
bin := server.Marshal()
server, _ = srp6ago.UnmarshalServer(bin)
```

## SRP Group Parameters

Preconfigured RFC-5054 SRP Group Parameters:

```go
package main

import (
    "github.com/wault-pw/srp6ago"
)

func main() {
	// RFC-5054 complicated params set:
	srp6ago.RFC5054b1024Sha1
	srp6ago.RFC5054b1536Sha1
	srp6ago.RFC5054b2048Sha1
	srp6ago.RFC5054b3072Sha1
	srp6ago.RFC5054b4096Sha1
	srp6ago.RFC5054b6144Sha1
	srp6ago.RFC5054b8192Sha1

	// RFC-5054 complicated set,
	// with non-standart hash function SHA-256
	srp6ago.RFC5054b8192Sha256
	srp6ago.RFC5054b6144Sha256
	srp6ago.RFC5054b4096Sha256
	srp6ago.RFC5054b1024Sha256
	srp6ago.RFC5054b1536Sha256
	srp6ago.RFC5054b2048Sha256
	srp6ago.RFC5054b3072Sha256	
}
```
