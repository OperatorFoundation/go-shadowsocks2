package darkstar

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/aead/ecdh"
)

func bytesToPublicKey(bytes []byte) crypto.PublicKey{
	PublicKeyX, PublicKeyY := elliptic.UnmarshalCompressed(elliptic.P256(), bytes)
	return ecdh.Point{PublicKeyX, PublicKeyY}
}

func makeNonce() []byte {
	buffer := make([]byte, 32)
	rand.Read(buffer)

	return buffer
}