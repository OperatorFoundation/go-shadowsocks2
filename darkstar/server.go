package darkstar

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/aead/ecdh"
	"net"
)

type DarkStarServer struct {
	serverPersistentPublicKey crypto.PublicKey
	serverPersistentPrivateKey crypto.PrivateKey
	serverEphemeralPublicKey crypto.PublicKey
	serverEphemeralPrivateKey crypto.PrivateKey
	serverIdentifier []byte
}

func NewDarkStarServer(serverPersistentPrivateKey string, host string, port int) *DarkStarServer {
	privateKey, decodeError := hex.DecodeString(serverPersistentPrivateKey)
	if decodeError != nil {
		return nil
	}

	keyExchange := ecdh.Generic(elliptic.P256())
	serverIdentifier := getServerIdentifier(host, port)

	serverEphemeralPrivateKey, serverEphemeralPublicKey, keyError := keyExchange.GenerateKey(rand.Reader)
	if keyError != nil {
		return nil
	}

	return &DarkStarServer{serverPersistentPublicKey: keyExchange.PublicKey(privateKey), serverPersistentPrivateKey: privateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, serverIdentifier: serverIdentifier}
}

func (a *DarkStarServer) KeySize() int {
	return 32
}

func (a *DarkStarServer) SaltSize() int {
	return 64
}

func (a *DarkStarServer) Encrypter(salt []byte) (cipher.AEAD, error) {
	sharedKey, keyError := a.generateSharedKeyClient(salt)
	if keyError != nil {
		return nil, keyError
	}
	return a.aesGCM(sharedKey)
}

func (a *DarkStarServer) Decrypter(salt []byte) (cipher.AEAD, error) {
	sharedKey, keyError := a.generateSharedKeyClient(salt)
	if keyError != nil {
		return nil, keyError
	}
	return a.aesGCM(sharedKey)
}

func (a *DarkStarServer) aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func (a *DarkStarServer) generateSharedKeyClient(salt []byte) ([]byte, error) {
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

func (a *DarkStarServer) getServerIdentifier(host string, port int) []byte {
	hostIP := net.ParseIP(host)
	// we do the below part because host IP in bytes is 16 bytes with padding at the beginning
	hostBytes := []byte(hostIP)[12:16]
	fmt.Println("host bytes:", hostBytes)
	portUint := uint16(port)
	portBuffer := []byte{0,0}
	binary.BigEndian.PutUint16(portBuffer, portUint)
	fmt.Println("port bytes:", portBuffer)
	buffer := make([]byte, 0)
	buffer = append(buffer, hostBytes...)
	buffer = append(buffer, portBuffer...)

	return buffer
}

func (a *DarkStarServer) generateConfirmationcode(serverEphemeralPublicKey []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(a.serverIdentifier)
	h.Write(serverEphemeralPublicKey)
	h.Write(a.clientEphemeralPublicKey)
	h.Write([]byte("DarkStar"))
	h.Write([]byte("client"))

	return h.Sum(nil), nil
}

func (a *DarkStarServer) makeServerIdentifier(host string, port int) []byte {
	hostIP := net.ParseIP(host)
	hostBytes := []byte(hostIP.String())
	portUint := uint16(port)
	portBuffer := []byte{0,0}
	binary.BigEndian.PutUint16(portBuffer, portUint)

	h := sha256.New()
	h.Write(hostBytes)
	h.Write(portBuffer)
	return h.Sum(nil)
}