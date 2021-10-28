package darkstar

import (
	"crypto"
	"crypto/elliptic"
	"errors"
	"github.com/aead/ecdh"
)

func bytesToPublicKey(bytes []byte) crypto.PublicKey{
	publicKeyBuffer := make([]byte, 33)
	copy(publicKeyBuffer[1:], bytes)
	publicKeyBuffer[0] = 3
	PublicKeyX, PublicKeyY := elliptic.UnmarshalCompressed(elliptic.P256(), publicKeyBuffer)
	return ecdh.Point{PublicKeyX, PublicKeyY}
}

func PublicKeyToBytes(pubKey crypto.PublicKey) ([]byte, error) {
	point, ok := pubKey.(ecdh.Point)
	if !ok {
		return nil, errors.New("could not convert client public key to point")
	}
	bytes := elliptic.MarshalCompressed(elliptic.P256(), point.X, point.Y)
	return bytes[1:], nil
}