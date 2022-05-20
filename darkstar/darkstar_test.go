package darkstar

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/aead/ecdh"
	"github.com/stretchr/testify/assert"
)

func TestForShadowSocksTestingMatrix(t *testing.T) {
	// TODO: Use the correct server public key, IP, and port
	serverPublicKey := ""
	serverIPString := ""
	serverPort := 2222
	serverPortString := strconv.Itoa(serverPort)
	serverAddressString := serverIPString + ":" + serverPortString
	darkStarClient := NewDarkStarClient(serverPublicKey, serverIPString, serverPort)
	println("DarkStar client created.")

	netConnection, dialError := net.Dial("tcp", serverAddressString)
	if dialError != nil {
		t.Fail()
		return
	}
	println("Network connection created.")

	darkStarConn, conError := darkStarClient.StreamConn(netConnection)
	if conError != nil {
		t.Fail()
		return
	}
	println("DarkStar connection created.")

	httpRequestString := "GET / HTTP/1.0\r\nConnection: close\r\n\r\n"
	_, writeError := darkStarConn.Write([]byte(httpRequestString))
	if writeError != nil {
		assert.Nil(t, writeError, "write error: %s", writeError)
		return
	}
	println("Wrote some bytes.")

	testBytes := make([]byte, 250)
	bytesRead, readError := darkStarConn.Read(testBytes)
	if readError != nil {
		assert.Nil(t, readError, "read error: %s", readError)
		return
	}
	println("Read some bytes.")

	testString := string(testBytes)
	println("Server sent a response: " + testString)
	println("Server response is " + strconv.Itoa(bytesRead) + " bytes")

	assert.True(t, strings.Contains(testString, "Yeah!"), "The server response was not what we were expecting!")
	//assert.Equal(t, "test", testString, "test string didnt match")
}

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

	publicKeyBytes, keyByteError := PublicKeyToBytes(clientEphemeralPublicKeyPoint)
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

			darkStarConn, connError := server.StreamConn(c)
			if connError != nil {
				t.Fail()
			}
			_, writeError := darkStarConn.Write([]byte("test"))
			if writeError != nil {
				return
			}
			closeError := darkStarConn.Close()
			if closeError != nil {
				return
			}

		}
	}()

	client := NewDarkStarClient(publicKeyHex, "127.0.0.1", 1234)

	netConn, dialError := net.Dial("tcp", addr)
	if dialError != nil {
		t.Fail()
	}

	darkStarConn, connError := client.StreamConn(netConn)
	if connError != nil {
		t.Fail()
		return
	}
	testBytes := make([]byte, 4)
	_, readError := darkStarConn.Read(testBytes)
	if readError != nil {
		return
	}
	testString := string(testBytes)

	if testString != "test" {
		t.Fail()
	}
}

//old code
func TestDarkStarClient(t *testing.T) {
	publicKeyHex := "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6"

	addr := "127.0.0.1:1234"

	darkStarClient := NewDarkStarClient(publicKeyHex, "127.0.0.1", 1234)

	netConnection, dialError := net.Dial("tcp", addr)
	if dialError != nil {
		t.Fail()
		return
	}

	darkStarConn, connError := darkStarClient.StreamConn(netConnection)
	if connError != nil {
		t.Fail()
		return
	}
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

func TestDarkStarServer(t *testing.T) {
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

			darkStarConn, connError := server.StreamConn(c)
			if connError != nil {
				t.Fail()
			}
			_, writeError := darkStarConn.Write([]byte("test"))
			if writeError != nil {
				return
			}
			closeError := darkStarConn.Close()
			if closeError != nil {
				return
			}
			doneChannel <- true
		}
	}()

	done := <-doneChannel
	assert.True(t, done)
}

//new code
func TestDarkStarClientAndServer(t *testing.T) {
	//server
	privateKeyHex := "dd5e9e88d13e66017eb2087b128c1009539d446208f86173e30409a898ada148"
	addr := "127.0.0.1:1234"
	server := NewDarkStarServer(privateKeyHex, "127.0.0.1", 1234)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println(err)
		t.Fail()
		return
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				t.Fail()
				return
			}

			darkStarConn, connError := server.StreamConn(c)
			if connError != nil {
				t.Fail()
			}
			_, writeError := darkStarConn.Write([]byte("test"))
			if writeError != nil {
				return
			}
			testBytes := make([]byte, 4)
			_, readError := darkStarConn.Read(testBytes)
			if readError != nil {
				closeError := darkStarConn.Close()
				if closeError != nil {
					return
				}
				t.Fail()
				return
			}
			closeError := darkStarConn.Close()
			if closeError != nil {
				return
			}
		}
	}()

	//client
	publicKeyHex := "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6"

	client := NewDarkStarClient(publicKeyHex, "127.0.0.1", 1234)

	netConn, dialError := net.Dial("tcp", addr)
	if dialError != nil {
		t.Fail()
		return
	}

	darkStarConn, connError := client.StreamConn(netConn)
	if connError != nil {
		t.Fail()
		return
	}
	testBytes := make([]byte, 4)
	bytesRead, readError := darkStarConn.Read(testBytes)
	if readError != nil {
		assert.Nil(t, readError, "read error: %s", readError)
		return
	}

	assert.Equal(t, 4, bytesRead, "read wrong size of bytes")

	testString := string(testBytes)

	assert.Equal(t, "test", testString, "test string didnt match")

	_, writeError := darkStarConn.Write([]byte("test"))
	if writeError != nil {
		return
	}
}

func TestKeys(t *testing.T) {
	privateKeyHex := "dd5e9e88d13e66017eb2087b128c1009539d446208f86173e30409a898ada148"
	publicKeyHex := "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6"

	publicKeyDecode, _ := hex.DecodeString(publicKeyHex)
	publicKey := bytesToPublicKey(publicKeyDecode)
	privateKey, _ := hex.DecodeString(privateKeyHex)
	keyExchange := ecdh.Generic(elliptic.P256())
	publicKey2 := keyExchange.PublicKey(privateKey)
	publicKey2Bytes, _ := PublicKeyToBytes(publicKey2)
	publicKey2String := hex.EncodeToString(publicKey2Bytes)
	publicKey3, _ := PublicKeyToBytes(publicKey)
	publicKey3Hex := hex.EncodeToString(publicKey3)

	assert.Equal(t, publicKeyHex, publicKey2String)
	assert.Equal(t, publicKey3Hex, publicKeyHex)
}
