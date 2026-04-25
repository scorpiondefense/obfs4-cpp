package main

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

func main() {
	// Test vector 1: Simple message
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	var nonce [24]byte
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	plaintext := []byte("Hello, obfs4 world!")

	// Seal: Go's secretbox.Seal appends [tag][ciphertext] after "out"
	sealed := secretbox.Seal(nil, plaintext, &nonce, &key)

	fmt.Println("=== NaCl Secretbox Test Vectors ===")
	fmt.Printf("Key:        %s\n", hex.EncodeToString(key[:]))
	fmt.Printf("Nonce:      %s\n", hex.EncodeToString(nonce[:]))
	fmt.Printf("Plaintext:  %s\n", hex.EncodeToString(plaintext))
	fmt.Printf("Sealed:     %s\n", hex.EncodeToString(sealed))
	fmt.Printf("SealedLen:  %d (plaintext %d + tag 16)\n", len(sealed), len(plaintext))
	fmt.Printf("Tag:        %s\n", hex.EncodeToString(sealed[:16]))
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(sealed[16:]))

	// Test vector 2: Empty message
	empty := []byte{}
	sealed2 := secretbox.Seal(nil, empty, &nonce, &key)
	fmt.Printf("\n--- Empty message ---\n")
	fmt.Printf("Sealed:     %s\n", hex.EncodeToString(sealed2))

	// Test vector 3: Longer message (simulate obfs4 frame payload)
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i * 3)
	}
	sealed3 := secretbox.Seal(nil, payload, &nonce, &key)
	fmt.Printf("\n--- 64-byte payload ---\n")
	fmt.Printf("Plaintext:  %s\n", hex.EncodeToString(payload))
	fmt.Printf("Sealed:     %s\n", hex.EncodeToString(sealed3))

	// Verify we can open what we sealed
	opened, ok := secretbox.Open(nil, sealed, &nonce, &key)
	fmt.Printf("\n--- Round-trip verification ---\n")
	fmt.Printf("Open OK:    %v\n", ok)
	fmt.Printf("Recovered:  %s\n", hex.EncodeToString(opened))
}
