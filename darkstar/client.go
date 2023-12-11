package darkstar

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/aead/ecdh"
)

const keySize = 32
const confirmationCodeSize = 32

type DarkStarClient struct {
	serverPersistentPublicKey crypto.PublicKey
	serverEphemeralPublicKey  crypto.PublicKey
	serverIdentifier          []byte
	clientEphemeralPrivateKey crypto.PrivateKey
	clientEphemeralPublicKey  crypto.PublicKey
}

func NewDarkStarClient(serverPersistentPublicKey string, host string, port int) *DarkStarClient {
	publicKeyBytes, decodeError := base64.StdEncoding.DecodeString(serverPersistentPublicKey)
	if decodeError != nil {
		return nil
	}

	serverPersistentPublicKeyPoint := KeychainFormatBytesToPublicKey(publicKeyBytes)

	serverIdentifier := getServerIdentifier(host, port)

	clientEphemeralPrivateKey, clientEphemeralPublicKey, keyError := generateEvenKeys()
	if keyError != nil {
		return nil
	}

	return &DarkStarClient{serverPersistentPublicKey: serverPersistentPublicKeyPoint, serverIdentifier: serverIdentifier, clientEphemeralPrivateKey: clientEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey}
}

func (a *DarkStarClient) StreamConn(conn net.Conn) (net.Conn, error) {
	clientEphemeralPublicKeyBytes, keyError := PublicKeyToDarkstarFormatBytes(a.clientEphemeralPublicKey)
	if keyError != nil {
		return nil, keyError
	}
	clientConfirmationCode, confirmationError := a.generateClientConfirmationCode()
	if confirmationError != nil {
		return nil, confirmationError
	}

	keyWriteError := WriteFully(conn, clientEphemeralPublicKeyBytes)
	if keyWriteError != nil {
		return nil, keyWriteError
	}
	confirmationWriteError := WriteFully(conn, clientConfirmationCode)
	if confirmationWriteError != nil {
		return nil, confirmationWriteError
	}

	serverEphemeralPublicKeyBuffer := make([]byte, keySize)
	keyReadError := ReadFully(conn, serverEphemeralPublicKeyBuffer)
	if keyReadError != nil {
		return nil, keyReadError
	}

	a.serverEphemeralPublicKey = DarkstarFormatBytesToPublicKey(serverEphemeralPublicKeyBuffer)

	serverConfirmationCode := make([]byte, confirmationCodeSize)
	confirmationReadError := ReadFully(conn, serverConfirmationCode)
	if confirmationReadError != nil {
		return nil, confirmationReadError
	}

	clientCopyServerConfirmationCode, confirmationCodeError := a.generateServerConfirmationCode()
	if confirmationCodeError != nil {
		return nil, confirmationCodeError
	}
	if !bytes.Equal(serverConfirmationCode, clientCopyServerConfirmationCode) {
		return nil, errors.New("serverConfirmationCode and client copy are not equal")
	}

	sharedKeyClientToServer, sharedKeyClientError := a.createClientToServerSharedKey()
	if sharedKeyClientError != nil {
		return nil, sharedKeyClientError
	}

	sharedKeyServerToClient, sharedKeyServerError := a.createServerToClientSharedKey()
	if sharedKeyServerError != nil {
		return nil, sharedKeyServerError
	}

	encryptCipher, encryptKeyError := a.Encrypter(sharedKeyClientToServer)
	if encryptKeyError != nil {
		return nil, encryptKeyError
	}

	decryptCipher, decryptKeyError := a.Encrypter(sharedKeyServerToClient)
	if decryptKeyError != nil {
		return nil, decryptKeyError
	}

	return NewDarkStarConn(conn, encryptCipher, decryptCipher), nil
}

func (a *DarkStarClient) PacketConn(conn net.PacketConn) net.PacketConn {
	return NewPacketConn(conn, a)
}

func (a *DarkStarClient) KeySize() int {
	return 32
}

func (a *DarkStarClient) SaltSize() int {
	return 64
}

func (a *DarkStarClient) Encrypter(salt []byte) (cipher.AEAD, error) {
	return a.aesGCM(salt)
}

func (a *DarkStarClient) Decrypter(salt []byte) (cipher.AEAD, error) {
	return a.aesGCM(salt)
}

func (a *DarkStarClient) aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func (a *DarkStarClient) createClientToServerSharedKey() ([]byte, error) {
	clientEphemeralPublicKeyBytes, keyError := PublicKeyToDarkstarFormatBytes(a.clientEphemeralPublicKey)
	if keyError != nil {
		return nil, keyError
	}

	p256 := ecdh.Generic(elliptic.P256())

	ecdh1 := p256.ComputeSecret(a.clientEphemeralPrivateKey, a.serverEphemeralPublicKey)
	ecdh2 := p256.ComputeSecret(a.clientEphemeralPrivateKey, a.serverPersistentPublicKey)

	serverEphemeralPublicKeyData, keyToBytesError := PublicKeyToDarkstarFormatBytes(a.serverEphemeralPublicKey)
	if keyToBytesError != nil {
		return nil, keyToBytesError
	}

	h := sha256.New()
	h.Write(ecdh1)
	h.Write(ecdh2)
	h.Write(a.serverIdentifier)
	h.Write(clientEphemeralPublicKeyBytes)
	h.Write(serverEphemeralPublicKeyData)
	h.Write([]byte("DarkStar"))
	h.Write([]byte("server"))

	return h.Sum(nil), nil
}

func (a *DarkStarClient) createServerToClientSharedKey() ([]byte, error) {
	serverEphemeralPublicKeyBytes, keyError := PublicKeyToDarkstarFormatBytes(a.serverEphemeralPublicKey)
	if keyError != nil {
		return nil, keyError
	}

	p256 := ecdh.Generic(elliptic.P256())

	ecdh1 := p256.ComputeSecret(a.clientEphemeralPrivateKey, a.serverEphemeralPublicKey)
	ecdh2 := p256.ComputeSecret(a.clientEphemeralPrivateKey, a.serverPersistentPublicKey)

	clientEphemeralPublicKeyData, keyToBytesError := PublicKeyToDarkstarFormatBytes(a.clientEphemeralPublicKey)
	if keyToBytesError != nil {
		return nil, keyToBytesError
	}

	h := sha256.New()
	h.Write(ecdh1)
	h.Write(ecdh2)
	h.Write(a.serverIdentifier)
	h.Write(clientEphemeralPublicKeyData)
	h.Write(serverEphemeralPublicKeyBytes)
	h.Write([]byte("DarkStar"))
	h.Write([]byte("client"))

	return h.Sum(nil), nil
}

func getServerIdentifier(host string, port int) []byte {
	hostIP := net.ParseIP(host)
	if hostIP == nil || len(hostIP) != 16 {
		fmt.Println("server identifier host failed to parse")
		return nil
	}
	// we do the below part because host IP in bytes is 16 bytes with padding at the beginning
	hostBytes := []byte(hostIP)[12:16]
	portUint := uint16(port)
	portBuffer := []byte{0, 0}
	binary.BigEndian.PutUint16(portBuffer, portUint)
	buffer := make([]byte, 0)
	buffer = append(buffer, hostBytes...)
	buffer = append(buffer, portBuffer...)

	return buffer
}

func (a *DarkStarClient) generateClientConfirmationCode() ([]byte, error) {
	p256 := ecdh.Generic(elliptic.P256())
	ecdhSecret := p256.ComputeSecret(a.clientEphemeralPrivateKey, a.serverPersistentPublicKey)
	serverPersistentPublicKeyData, serverKeyError := PublicKeyToKeychainFormatBytes(a.serverPersistentPublicKey)
	if serverKeyError != nil {
		return nil, serverKeyError
	}

	clientEphemeralPublicKeyData, clientKeyError := PublicKeyToDarkstarFormatBytes(a.clientEphemeralPublicKey)
	if clientKeyError != nil {
		return nil, clientKeyError
	}

	h := sha256.New()
	h.Write(ecdhSecret)
	h.Write(a.serverIdentifier)
	h.Write(serverPersistentPublicKeyData)
	h.Write(clientEphemeralPublicKeyData)
	h.Write([]byte("DarkStar"))
	h.Write([]byte("client"))

	return h.Sum(nil), nil
}

func (a *DarkStarClient) generateServerConfirmationCode() ([]byte, error) {
	p256 := ecdh.Generic(elliptic.P256())
	ecdhSecret := p256.ComputeSecret(a.clientEphemeralPrivateKey, a.serverPersistentPublicKey)
	serverPersistentPublicKeyData, serverKeyError := PublicKeyToKeychainFormatBytes(a.serverPersistentPublicKey)
	if serverKeyError != nil {
		return nil, serverKeyError
	}

	clientEphemeralPublicKeyData, clientKeyError := PublicKeyToDarkstarFormatBytes(a.clientEphemeralPublicKey)
	if clientKeyError != nil {
		return nil, clientKeyError
	}

	h := sha256.New()
	h.Write(ecdhSecret)
	h.Write(a.serverIdentifier)
	h.Write(serverPersistentPublicKeyData)
	h.Write(clientEphemeralPublicKeyData)
	h.Write([]byte("DarkStar"))
	h.Write([]byte("server"))

	return h.Sum(nil), nil
}
