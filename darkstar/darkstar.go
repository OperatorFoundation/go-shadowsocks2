package darkstar

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"github.com/aead/ecdh"
	"net"
)

type DarkStar struct {
	serverPersistentPublicKey []byte
	clientEphemeralPublicKey  []byte
	clientEphemeralPrivateKey []byte
	serverIdentifier []byte
}

func (a *DarkStar) KeySize() int {
	return 32
}

func (a *DarkStar) SaltSize() int {
	return 64
}

func (a *DarkStar) Encrypter(salt []byte) (cipher.AEAD, error) {
	sharedKey, keyError := a.generateSharedKey(salt)
	if keyError != nil {
		return nil, keyError
	}
	return a.aesGCM(sharedKey)
}

func (a *DarkStar) Decrypter(salt []byte) (cipher.AEAD, error) {
	sharedKey, keyError := a.generateSharedKey(salt)
	if keyError != nil {
		return nil, keyError
	}
	return a.aesGCM(sharedKey)
}

func (a *DarkStar) aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func (a *DarkStar) generateSharedKey(salt []byte) ([]byte, error) {
	serverEphemeralPublicKeyData := salt[:32]
	serverConfirmationCode := salt[32:]

	clientConfirmationCode, _ := a.generateConfirmationcode(serverEphemeralPublicKeyData)

	if bytes.Equal(serverConfirmationCode, clientConfirmationCode) {
		return nil, errors.New("invalid server confirmation code")
	}

	p256 := ecdh.Generic(elliptic.P256())

	serverEphemeralPublicKeyX, serverEphemeralPublicKeyY := elliptic.UnmarshalCompressed(elliptic.P256(), serverEphemeralPublicKeyData)
	serverEphemeralPublicKeyPoint := ecdh.Point{serverEphemeralPublicKeyX, serverEphemeralPublicKeyY}
	ecdh1 := p256.ComputeSecret(a.clientEphemeralPrivateKey, serverEphemeralPublicKeyPoint)

	serverPersistentPublicKeyX, serverPersistentPublicKeyY := elliptic.UnmarshalCompressed(elliptic.P256(), a.serverPersistentPublicKey)
	serverPersistentPublicKeyPoint := ecdh.Point{serverPersistentPublicKeyX, serverPersistentPublicKeyY}
	ecdh2 := p256.ComputeSecret(a.clientEphemeralPrivateKey, serverPersistentPublicKeyPoint)

	h := sha256.New()
	h.Write(ecdh1)
	h.Write(ecdh2)
	h.Write(a.serverIdentifier)
	h.Write(a.clientEphemeralPublicKey)
	h.Write(serverEphemeralPublicKeyData)
	h.Write([]byte("DarkStar"))

	return h.Sum(nil), nil
}

func (a *DarkStar) generateConfirmationcode(serverEphemeralPublicKey []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(a.serverIdentifier)
	h.Write(serverEphemeralPublicKey)
	h.Write(a.clientEphemeralPublicKey)
	h.Write([]byte("DarkStar"))
	h.Write([]byte("client"))

	return h.Sum(nil), nil
}

func (a *DarkStar) makeServerIdentifier(host string, port int) []byte {
	hostIP := net.ParseIP(host)
	hostBytes := []byte(hostIP.String())
	h := sha256.New()
	if len(hostBytes) == 4 {
		h.Write([]byte{0})
	} else if len(hostBytes) == 16 {
		h.Write([]byte{1})
	} else {
		return nil
	}
	h.Write(hostBytes)
	// h.Write([]byte(port))
	return h.Sum(nil)
}