package cmd

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"lukechampine.com/blake3"
)

// Curve25519Genkey generates an X25519 key pair (and Blake3 hash) and prints
// the result.  optionally derives from an existing base64-encoded private key.
func Curve25519Genkey(stdEncoding bool, inputBase64 string) {
	var encoding *base64.Encoding
	if stdEncoding {
		encoding = base64.StdEncoding
	} else {
		encoding = base64.RawURLEncoding
	}

	var privateKey []byte
	if len(inputBase64) > 0 {
		var err error
		privateKey, err = encoding.DecodeString(inputBase64)
		if err != nil || len(privateKey) != 32 {
			fmt.Println("Invalid X25519 private key.")
			return
		}
	}

	privKey, pubKey, hash32, err := genCurve25519(privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("PrivateKey: %v\nPublicKey: %v\nHash32: %v\n",
		encoding.EncodeToString(privKey),
		encoding.EncodeToString(pubKey),
		encoding.EncodeToString(hash32[:]))
}

func genCurve25519(inputPrivateKey []byte) (privateKey, publicKey []byte, hash32 [32]byte, returnErr error) {
	privateKey = inputPrivateKey
	if privateKey == nil {
		privateKey = make([]byte, 32)
		if _, err := rand.Read(privateKey); err != nil {
			returnErr = err
			return
		}
	}

	// Clamp as per https://cr.yp.to/ecdh.html
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		returnErr = err
		return
	}
	publicKey = key.PublicKey().Bytes()
	hash32 = blake3.Sum256(publicKey)
	return
}
