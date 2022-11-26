package darkstar

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
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

	privateKeyString := base64.StdEncoding.EncodeToString(privateKeyBytes)
	fmt.Printf("private key bytes: %s\n", privateKeyString)

	publicKeyString := base64.StdEncoding.EncodeToString(publicKeyBytes)
	fmt.Printf("public key bytes: %s\n", publicKeyString)
}

func TestDarkStar(t *testing.T) {
	publicKeyString := "6LukZ8KqZLQ7eOdaTVFkBVqMA8NS1AUxwqG17L/kHnQ="
	privateKeyString := "RaHouPFVOazVSqInoMm8BSO9o/7J493y4cUVofmwXAU="

	addr := "127.0.0.1:1234"

	server := NewDarkStarServer(privateKeyString, "127.0.0.1", 1234)

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

	client := NewDarkStarClient(publicKeyString, "127.0.0.1", 1234)

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
	publicKeyString := "6LukZ8KqZLQ7eOdaTVFkBVqMA8NS1AUxwqG17L/kHnQ="

	addr := "127.0.0.1:1234"

	darkStarClient := NewDarkStarClient(publicKeyString, "127.0.0.1", 1234)

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
	privateKeyString := "RaHouPFVOazVSqInoMm8BSO9o/7J493y4cUVofmwXAU="
	addr := "127.0.0.1:1234"
	server := NewDarkStarServer(privateKeyString, "127.0.0.1", 1234)
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
	privateKeyString := "RaHouPFVOazVSqInoMm8BSO9o/7J493y4cUVofmwXAU="
	addr := "127.0.0.1:1234"
	server := NewDarkStarServer(privateKeyString, "127.0.0.1", 1234)

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
	publicKeyString := "6LukZ8KqZLQ7eOdaTVFkBVqMA8NS1AUxwqG17L/kHnQ="

	client := NewDarkStarClient(publicKeyString, "127.0.0.1", 1234)

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
	privateKeyString := "RaHouPFVOazVSqInoMm8BSO9o/7J493y4cUVofmwXAU="
	publicKeyString := "6LukZ8KqZLQ7eOdaTVFkBVqMA8NS1AUxwqG17L/kHnQ="

	publicKeyDecode, _ := base64.StdEncoding.DecodeString(publicKeyString)
	publicKey := BytesToPublicKey(publicKeyDecode)
	privateKey, _ := base64.StdEncoding.DecodeString(privateKeyString)
	keyExchange := ecdh.Generic(elliptic.P256())
	publicKey2 := keyExchange.PublicKey(privateKey)
	publicKey2Bytes, _ := PublicKeyToBytes(publicKey2)
	publicKey2String := base64.StdEncoding.EncodeToString(publicKey2Bytes)
	publicKey3, _ := PublicKeyToBytes(publicKey)
	publicKey3String := base64.StdEncoding.EncodeToString(publicKey3)

	assert.Equal(t, publicKeyString, publicKey2String)
	assert.Equal(t, publicKey3String, publicKeyString)
}
