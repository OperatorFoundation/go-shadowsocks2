package darkstar

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"github.com/aead/ecdh"
	"net"
)

type DarkStarServer struct {
	serverPersistentPublicKey  crypto.PublicKey
	serverPersistentPrivateKey crypto.PrivateKey
	serverEphemeralPublicKey   crypto.PublicKey
	serverEphemeralPrivateKey  crypto.PrivateKey
	serverIdentifier           []byte
	clientEphemeralPublicKey   crypto.PublicKey
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

	return &DarkStarServer{
		serverPersistentPublicKey:  keyExchange.PublicKey(privateKey),
		serverPersistentPrivateKey: privateKey,
		serverEphemeralPublicKey:   serverEphemeralPublicKey,
		serverEphemeralPrivateKey:  serverEphemeralPrivateKey,
		serverIdentifier:           serverIdentifier,
	}
}

func (a *DarkStarServer) StreamConn(conn net.Conn) net.Conn {
	clientEphemeralPublicKeyBuffer := make([]byte, keySize)
	_, keyReadError := conn.Read(clientEphemeralPublicKeyBuffer)
	if keyReadError != nil {
		return nil
	}

	a.clientEphemeralPublicKey = bytesToPublicKey(clientEphemeralPublicKeyBuffer)

	clientConfirmationCode := make([]byte, confirmationCodeSize)
	_, confirmationReadError := conn.Read(clientConfirmationCode)
	if confirmationReadError != nil {
		return nil
	}

	serverCopyClientConfirmationCode, confirmationError := a.generateClientConfirmationCode()
	if confirmationError != nil {
		return nil
	}

	if !bytes.Equal(clientConfirmationCode, serverCopyClientConfirmationCode) {
		return nil
	}

	serverEphemeralPublicKeyData, pubKeyToBytesError := PublicKeyToBytes(a.serverEphemeralPublicKey)
	if pubKeyToBytesError != nil {
		return nil
	}

	sharedKeyServer, sharedKeyServerError := a.generateSharedKeyServer()
	if sharedKeyServerError != nil {
		return nil
	}

	sharedKeyClient, sharedKeyClientError := a.generateSharedKeyClient()
	if sharedKeyClientError != nil {
		return nil
	}

	serverConfirmationCode, _ := a.generateServerConfirmationCode(sharedKeyServer, serverEphemeralPublicKeyData)

	_, keyWriteError := conn.Write(serverEphemeralPublicKeyData)
	if keyWriteError != nil {
		return nil
	}

	_, confirmationWriteError := conn.Write(serverConfirmationCode)
	if confirmationWriteError != nil {
		return nil
	}

	encryptCipher, encryptKeyError := a.Encrypter(sharedKeyClient)
	if encryptKeyError != nil {
		return nil
	}

	decryptCipher, decryptKeyError := a.Decrypter(sharedKeyServer)
	if decryptKeyError != nil {
		return nil
	}

	return NewDarkStarConn(conn, encryptCipher, decryptCipher)
}

func (a *DarkStarServer) PacketConn(conn net.PacketConn) net.PacketConn {
	return NewPacketConn(conn, a)
}

func (a *DarkStarServer) KeySize() int {
	return 32
}

func (a *DarkStarServer) SaltSize() int {
	return 96
}

func (a *DarkStarServer) Encrypter(_ []byte) (cipher.AEAD, error) {
	sharedKey, keyError := a.generateSharedKeyServer()
	if keyError != nil {
		return nil, keyError
	}
	return a.aesGCM(sharedKey)
}

func (a *DarkStarServer) Decrypter(_ []byte) (cipher.AEAD, error) {
	sharedKey, keyError := a.generateSharedKeyServer()
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

func (a *DarkStarServer) generateSharedKeyServer() ([]byte, error) {
	serverEphemeralPublicKeyBytes, keyError := PublicKeyToBytes(a.serverEphemeralPublicKey)
	if keyError != nil {
		return nil, keyError
	}

	p256 := ecdh.Generic(elliptic.P256())

	ecdh1 := p256.ComputeSecret(a.serverEphemeralPrivateKey, a.clientEphemeralPublicKey)
	ecdh2 := p256.ComputeSecret(a.serverPersistentPrivateKey, a.clientEphemeralPublicKey)

	clientEphemeralPublicKeyData, keyToBytesError := PublicKeyToBytes(a.clientEphemeralPublicKey)
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
	h.Write([]byte("server"))

	return h.Sum(nil), nil
}

func (a *DarkStarServer) generateSharedKeyClient() ([]byte, error) {

	serverEphemeralPublicKeyBytes, keyError := PublicKeyToBytes(a.serverEphemeralPublicKey)
	if keyError != nil {
		return nil, keyError
	}

	p256 := ecdh.Generic(elliptic.P256())

	ecdh1 := p256.ComputeSecret(a.serverEphemeralPrivateKey, a.clientEphemeralPublicKey)
	ecdh2 := p256.ComputeSecret(a.serverEphemeralPrivateKey, a.clientEphemeralPublicKey)

	clientEphemeralPublicKeyData, keyToBytesError := PublicKeyToBytes(a.clientEphemeralPublicKey)
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

func (a *DarkStarServer) getServerIdentifier(host string, port int) []byte {
	hostIP := net.ParseIP(host)
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

func (a *DarkStarServer) generateServerConfirmationCode(sharedKey []byte, serverEphemeralPublicKeyData []byte) ([]byte, error) {
	clientEphemeralPublicKeyData, clientKeyError := PublicKeyToBytes(a.clientEphemeralPublicKey)
	if clientKeyError != nil {
		return nil, clientKeyError
	}

	h := hmac.New(sha256.New, sharedKey)
	h.Write(a.serverIdentifier)
	h.Write(serverEphemeralPublicKeyData)
	h.Write(clientEphemeralPublicKeyData)
	h.Write([]byte("DarkStar"))
	h.Write([]byte("server"))

	return h.Sum(nil), nil
}

func (a *DarkStarServer) generateClientConfirmationCode() ([]byte, error) {
	p256 := ecdh.Generic(elliptic.P256())
	ecdhSecret := p256.ComputeSecret(a.serverPersistentPrivateKey, a.clientEphemeralPublicKey)
	serverPersistentPublicKeyData, serverKeyError := PublicKeyToBytes(a.serverPersistentPublicKey)
	if serverKeyError != nil {
		return nil, serverKeyError
	}

	clientEphemeralPublicKeyData, clientKeyError := PublicKeyToBytes(a.clientEphemeralPublicKey)
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

func (a *DarkStarServer) makeServerIdentifier(host string, port int) []byte {
	hostIP := net.ParseIP(host)
	hostBytes := []byte(hostIP.String())
	portUint := uint16(port)
	portBuffer := []byte{0, 0}
	binary.BigEndian.PutUint16(portBuffer, portUint)

	h := sha256.New()
	h.Write(hostBytes)
	h.Write(portBuffer)
	return h.Sum(nil)
}
