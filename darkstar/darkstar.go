package darkstar

import (
	"crypto"
	"crypto/elliptic"
	"errors"
	"github.com/aead/ecdh"
)

func bytesToPublicKey(bytes []byte) crypto.PublicKey{
	PublicKeyX, PublicKeyY := elliptic.UnmarshalCompressed(elliptic.P256(), bytes)
	return ecdh.Point{PublicKeyX, PublicKeyY}
}

func publicKeyToBytes(pubKey crypto.PublicKey) ([]byte, error) {
	point, ok := pubKey.(ecdh.Point)
	if !ok {
		return nil, errors.New("could not convert client public key to point")
	}
	return elliptic.MarshalCompressed(elliptic.P256(), point.X, point.Y), nil
}