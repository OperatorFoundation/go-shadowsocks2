package darkstar

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)


func TestServerIdentifier(t *testing.T) {
	expected := []byte{127, 0, 0, 1, 4, 210}
	host := "127.0.0.1"
	port := 1234

	darkStar := DarkStar{}
	result := darkStar.getServerIdentifier(host, port)

	fmt.Println(result)
	fmt.Println(expected)
	assert.ElementsMatch(t, expected, result)

	//h := sha256.New()
	//h.Write(hostBytes)
	//h.Write(portBuffer)
	//hash := h.Sum(nil)
	//
	//fmt.Println("expected bytes:", expected)
	//fmt.Println("hash bytes:", hash)
	//
	//fmt.Println(hex.EncodeToString(expected))
	//fmt.Println(hex.EncodeToString(hash))
}

func TestPublicKey(t *testing.T) {
	//p256 := ecdh.Generic(elliptic.P256())
	_, publicKeyX, publicKeyY, keyGenError := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if keyGenError != nil {
		t.Fail()
	}

	publicKeyBytes := elliptic.MarshalCompressed(elliptic.P256(), publicKeyX, publicKeyY)

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), publicKeyBytes)
	//publicKeyPoint := ecdh.Point{x, y}
	//point := ecdh.Point{publicKeyX, publicKeyY}

	assert.Equal(t, publicKeyY, y)
	assert.Equal(t, publicKeyX, x)
}


