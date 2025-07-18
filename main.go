package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      = "mock-key-id"
)

func main() {
	// var err error
	// seed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}  // any fixed sequence you want
	// detReader := NewDeterministicReader(seed)
	// fmt.Print("Generating RSA key pair... ")
	// privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	// fmt.Println("done")



	const keyFile = "private_key.pem"
    if _, err := os.Stat(keyFile); os.IsNotExist(err) {
        // Key file does not exist, generate new key
        privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
            panic(err)
        }
        // Save it to file
        err = SavePrivateKeyToFile(privateKey, keyFile)
        if err != nil {
            panic(err)
        }
        fmt.Println("Generated and saved new private key.")
    } else {
        // Load existing key from file
        privateKey, err = LoadPrivateKeyFromFile(keyFile)
        if err != nil {
            panic(err)
        }
        fmt.Println("Loaded private key from file.")
    }


	// if err != nil {
	// 	log.Fatalf("Failed to generate key: %v", err)
	// }
	publicKey = &privateKey.PublicKey

	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/jwks", jwksHandler)

	log.Println("Mock IdP running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	claims := jwt.MapClaims{
		"sub":   "1234567890",
		"name":  "John Doe",
		"email": "john@example.com",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(1000 * time.Hour).Unix(),
		"iss":   "http://mock-idp.default.svc.cluster.local",
		"aud":   "my-client-id",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"access_token": signedToken,
		"token_type":   "Bearer",
		"expires_in":   "3600",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   n,
		"e":   e,
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}






type DeterministicReader struct {
	data []byte
	pos  int
}

func NewDeterministicReader(seed []byte) *DeterministicReader {
	return &DeterministicReader{
		data: seed,
		pos:  0,
	}
}

func (r *DeterministicReader) Read(p []byte) (int, error) {
	fmt.Print(p)
	fmt.Print("Length of p: ", len(p))
	n := len(p)
	for i := 0; i < n; i++ {
		p[i] = r.data[r.pos]
		r.pos = (r.pos + 1) % len(r.data)  // cycle through seed repeatedly
	}
	return n, nil
}

// SavePrivateKeyToFile saves RSA private key to a file in PEM format
func SavePrivateKeyToFile(key *rsa.PrivateKey, filename string) error {
    keyBytes := x509.MarshalPKCS1PrivateKey(key)
    pemBlock := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: keyBytes,
    }
    pemData := pem.EncodeToMemory(pemBlock)
    return ioutil.WriteFile(filename, pemData, 0600) // permission 600 to keep it private
}

// LoadPrivateKeyFromFile loads RSA private key from PEM file
func LoadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
    pemData, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(pemData)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, errors.New("failed to decode PEM block containing RSA private key")
    }
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}