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
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/aead/ecdh"
	"net"
)

const keySize = 32
const confirmationCodeSize = 32

type DarkStarClient struct {
	serverPersistentPublicKey crypto.PublicKey
	serverIdentifier []byte
	clientEphemeralPrivateKey crypto.PrivateKey
	clientEphemeralPublicKey crypto.PublicKey
	clientNonce []byte
}

func (a *DarkStarClient) StreamConn(conn net.Conn) net.Conn {
	clientEphemeralPublicKeyBytes, keyError := publicKeyToBytes(a.clientEphemeralPublicKey)
	if keyError != nil {
		return nil
	}
	clientConfirmationCode, confirmationError := a.generateClientConfirmationCode()
	if confirmationError != nil {
		return nil
	}

	conn.Write(clientEphemeralPublicKeyBytes)
	conn.Write(clientConfirmationCode)
	conn.Write(a.clientNonce)

	serverEphemeralPublicKeyBuffer := make([]byte, keySize)
	_, keyReadError := conn.Read(serverEphemeralPublicKeyBuffer)
	if keyReadError != nil {
		return nil
	}

	serverConfirmationCode := make([]byte, confirmationCodeSize)
	_, confirmationReadError := conn.Read(serverConfirmationCode)
	if confirmationReadError != nil {
		return nil
	}

	sharedKey, sharedKeyError := a.generateSharedKeyClient(serverEphemeralPublicKeyBuffer)
	if sharedKeyError != nil {
		return nil
	}

	clientCopyServerConfirmationCode, confirmationCodeError := a.generateServerConfirmationCode(sharedKey, serverEphemeralPublicKeyBuffer)
	if confirmationCodeError != nil {
		return nil
	}

	if !bytes.Equal(serverConfirmationCode, clientCopyServerConfirmationCode) {
		return nil
	}

	serverNonce := make([]byte, 32)
	_, nonceReadError := conn.Read(serverNonce)
	if nonceReadError != nil {
		return nil
	}

	encryptCipher, encryptKeyError := a.Encrypter(sharedKey)
	if encryptKeyError != nil {
		return nil
	}

	decryptCipher, decryptKeyError := a.Decrypter(sharedKey)
	if decryptKeyError != nil {
		return nil
	}

	return NewDarkStarConn(conn, encryptCipher, decryptCipher)
}

func (a *DarkStarClient) PacketConn(conn net.PacketConn) net.PacketConn {
	panic("packetconn not available in DarkStar mode")
}

func NewDarkStarClient(serverPersistentPublicKey string, host string, port int) *DarkStarClient{
	publicKeyBytes, decodeError := hex.DecodeString(serverPersistentPublicKey)
	if decodeError != nil {
		return nil
	}

	cert, certError := x509.ParseCertificate(publicKeyBytes)
	if certError != nil {
		return nil
	}
	serverPersistentPublicKeyPoint := cert.PublicKey
	serverIdentifier := getServerIdentifier(host, port)

	keyExchange := ecdh.Generic(elliptic.P256())
	clientEphemeralPrivateKey, clientEphemeralPublicKey, keyError := keyExchange.GenerateKey(rand.Reader)
	if keyError != nil {
		return nil
	}
	nonce := makeNonce()

	return &DarkStarClient{serverPersistentPublicKey: serverPersistentPublicKeyPoint, serverIdentifier: serverIdentifier, clientEphemeralPrivateKey: clientEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, clientNonce: nonce}
}

func (a *DarkStarClient) KeySize() int {
	return 32
}

func (a *DarkStarClient) SaltSize() int {
	return 96
}

func (a *DarkStarClient) Encrypter(salt []byte) (cipher.AEAD, error) {
	sharedKey, keyError := a.generateSharedKeyClient(salt)
	if keyError != nil {
		return nil, keyError
	}
	return a.aesGCM(sharedKey)
}

func (a *DarkStarClient) Decrypter(salt []byte) (cipher.AEAD, error) {
	sharedKey, keyError := a.generateSharedKeyClient(salt)
	if keyError != nil {
		return nil, keyError
	}
	return a.aesGCM(sharedKey)
}

func (a *DarkStarClient) aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func (a *DarkStarClient) generateSharedKeyClient(serverEphemeralPublicKeyData []byte) ([]byte, error) {

	p256 := ecdh.Generic(elliptic.P256())

	serverEphemeralPublicKeyPoint := bytesToPublicKey(serverEphemeralPublicKeyData)
	ecdh1 := p256.ComputeSecret(a.clientEphemeralPrivateKey, serverEphemeralPublicKeyPoint)
	ecdh2 := p256.ComputeSecret(a.clientEphemeralPrivateKey, a.serverPersistentPublicKey)

	clientEphemeralPublicKeyData, keyToBytesError := publicKeyToBytes(a.clientEphemeralPublicKey)
	if keyToBytesError != nil {
		return nil, keyToBytesError
	}

	h := sha256.New()
	h.Write(ecdh1)
	h.Write(ecdh2)
	h.Write(a.serverIdentifier)
	h.Write(clientEphemeralPublicKeyData)
	h.Write(serverEphemeralPublicKeyData)
	h.Write([]byte("DarkStar"))

	return h.Sum(nil), nil
}

func getServerIdentifier(host string, port int) []byte {
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

func (a *DarkStarClient) generateClientConfirmationCode() ([]byte, error) {
	p256 := ecdh.Generic(elliptic.P256())
	ecdh := p256.ComputeSecret(a.clientEphemeralPrivateKey, a.serverPersistentPublicKey)
	serverPersistentPublicKeyData, serverKeyError := publicKeyToBytes(a.serverPersistentPublicKey)
	if serverKeyError != nil {
		return nil, serverKeyError
	}

	clientEphemeralPublicKeyData, clientKeyError := publicKeyToBytes(a.clientEphemeralPublicKey)
	if clientKeyError != nil {
		return nil, clientKeyError
	}

	h := sha256.New()
	h.Write(ecdh)
	h.Write(a.serverIdentifier)
	h.Write(serverPersistentPublicKeyData)
	h.Write(clientEphemeralPublicKeyData)
	h.Write([]byte("DarkStar"))
	h.Write([]byte("client"))

	return h.Sum(nil), nil
}

func (a *DarkStarClient) generateServerConfirmationCode(sharedKey []byte, serverEphemeralPublicKeyData []byte) ([]byte, error) {
	clientEphemeralPublicKeyData, clientKeyError := publicKeyToBytes(a.clientEphemeralPublicKey)
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

