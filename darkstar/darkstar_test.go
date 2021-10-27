package darkstar

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/aead/ecdh"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestKeyGen(t *testing.T) {
	keyExchange := ecdh.Generic(elliptic.P256())
	clientEphemeralPrivateKey, clientEphemeralPublicKeyPoint, keyError := keyExchange.GenerateKey(rand.Reader)
	if keyError != nil {
		t.Fail()
	}

	privateKeyBytes, ok := clientEphemeralPrivateKey.([]byte)
	if !ok {
		t.Fail()
	}

	publicKeyBytes, keyByteError := publicKeyToBytes(clientEphemeralPublicKeyPoint)
	if keyByteError != nil {
		t.Fail()
	}

	privateKeyHex := hex.EncodeToString(privateKeyBytes)
	fmt.Printf("private key bytes: %s\n", privateKeyHex)

	publicKeyHex := hex.EncodeToString(publicKeyBytes)
	fmt.Printf("public key bytes: %s\n", publicKeyHex)
}

func TestDarkStar(t *testing.T) {
	publicKeyHex := "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6"
	privateKeyHex := "dd5e9e88d13e66017eb2087b128c1009539d446208f86173e30409a898ada148"

	addr := "127.0.0.1:1234"

	server := NewDarkStarServer(privateKeyHex, "127.0.0.1", 1234)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fail()
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				t.Fail()
			}

			darkStarConn := server.StreamConn(c)
			darkStarConn.Write([]byte("test"))
			darkStarConn.Close()

		}
	}()

	client := NewDarkStarClient(publicKeyHex, "127.0.0.1", 1234)

	netConn, dialError := net.Dial("tcp", addr)
	if dialError != nil {
		t.Fail()
	}

	darkStarConn := client.StreamConn(netConn)
	testBytes := make([]byte, 4)
	darkStarConn.Read(testBytes)
	testString := string(testBytes)

	if testString != "test" {
		t.Fail()
	}
}

func TestDarkStarClient(t *testing.T) {
	publicKeyHex := "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6"

	addr := "127.0.0.1:1234"

	client := NewDarkStarClient(publicKeyHex, "127.0.0.1", 1234)

	netConn, dialError := net.Dial("tcp", addr)
	if dialError != nil {
		t.Fail()
		return
	}

	darkStarConn := client.StreamConn(netConn)
	testBytes := make([]byte, 4)
	bytesRead, readError := darkStarConn.Read(testBytes)
	if readError != nil {
		assert.Nil(t, readError, "read error: %s", readError)
		return
	}

	assert.Equal(t, 4, bytesRead, "read wrong size of bytes")

	testString := string(testBytes)

	assert.Equal(t, "test", testString, "test string didnt match")
}

func TestDarkStarServer(t *testing.T)  {
	privateKeyHex := "dd5e9e88d13e66017eb2087b128c1009539d446208f86173e30409a898ada148"
	addr := "127.0.0.1:1234"
	server := NewDarkStarServer(privateKeyHex, "127.0.0.1", 1234)
	doneChannel := make(chan bool)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fail()
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				t.Fail()
			}

			darkStarConn := server.StreamConn(c)
			darkStarConn.Write([]byte("test"))
			darkStarConn.Close()
			doneChannel <- true
		}
	}()

	done :=  <- doneChannel
	assert.True(t, done)
}