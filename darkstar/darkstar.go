package darkstar

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/aead/ecdh"
)

func DarkstarFormatBytesToPublicKey(bytes []byte) crypto.PublicKey {
	if len(bytes) != 32 {
		fmt.Printf("Byte array length needs to be 32.  Length is currently %d\n", len(bytes))
	}

	keyBytes := make([]byte, 0)
	keyBytes = append(keyBytes, 2)
	keyBytes = append(keyBytes, bytes...)

	PublicKeyX, PublicKeyY := elliptic.UnmarshalCompressed(elliptic.P256(), keyBytes)
	return ecdh.Point{X: PublicKeyX, Y: PublicKeyY}
}

func KeychainFormatBytesToPublicKey(bytes []byte) crypto.PublicKey {
	if len(bytes) != 66 {
		fmt.Printf("Byte array length needs to be 66.  Length is currently %d\n", len(bytes))
	}

	PublicKeyX, PublicKeyY := elliptic.Unmarshal(elliptic.P256(), bytes[1:])
	return ecdh.Point{X: PublicKeyX, Y: PublicKeyY}
}

// use this for handshake
func PublicKeyToDarkstarFormatBytes(pubKey crypto.PublicKey) ([]byte, error) {
	point, ok := pubKey.(ecdh.Point)
	if !ok {
		return nil, errors.New("could not convert client public key to point")
	}

	bytes := elliptic.MarshalCompressed(elliptic.P256(), point.X, point.Y)
	if bytes == nil {
		return nil, errors.New("MarshalCompressed returned nil")
	}

	return bytes[1:], nil
}

// use this where we read the configs
func PublicKeyToKeychainFormatBytes(pubKey crypto.PublicKey) ([]byte, error) {
	point, ok := pubKey.(ecdh.Point)
	if !ok {
		return nil, errors.New("could not convert client public key to point")
	}

	bytes := elliptic.Marshal(elliptic.P256(), point.X, point.Y)
	if bytes == nil {
		return nil, errors.New("marshal returned nil")
	}

	byteBuffer := make([]byte, 0)
	byteBuffer = append(byteBuffer, 2)
	byteBuffer = append(byteBuffer, bytes...)

	return byteBuffer, nil
}

func generateEvenKeys() (crypto.PrivateKey, crypto.PublicKey, error) {
	keyExchange := ecdh.Generic(elliptic.P256())
	for {
		ephemeralPrivateKey, ephemeralPublicKey, keyError := keyExchange.GenerateKey(rand.Reader)
		if keyError != nil {
			return nil, nil, keyError
		}

		point, ok := ephemeralPublicKey.(ecdh.Point)
		if !ok {
			return nil, nil, errors.New("could not convert client public key to point")
		}

		bytes := elliptic.MarshalCompressed(elliptic.P256(), point.X, point.Y)
		if bytes == nil {
			return nil, nil, errors.New("MarshalCompressed returned nil")
		}

		if bytes[0] == 2  {
			return ephemeralPrivateKey, ephemeralPublicKey, nil
		}
	}
}

func generateKeychainKeys() (crypto.PrivateKey, crypto.PublicKey, error) {
	keyExchange := ecdh.Generic(elliptic.P256())
	
	ephemeralPrivateKey, ephemeralPublicKey, keyError := keyExchange.GenerateKey(rand.Reader)
	if keyError != nil {
		return nil, nil, keyError
	}

	point, ok := ephemeralPublicKey.(ecdh.Point)
	if !ok {
		return nil, nil, errors.New("could not convert client public key to point")
	}

	bytes := elliptic.Marshal(elliptic.P256(), point.X, point.Y)
	if bytes == nil {
		return nil, nil, errors.New("MarshalCompressed returned nil")
	}

	return ephemeralPrivateKey, ephemeralPublicKey, nil
}