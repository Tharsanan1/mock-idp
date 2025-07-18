package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"crypto/rand"
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

// type fixedReader struct {
//     src *rand.Rand
// }

// func (f *fixedReader) Read(p []byte) (n int, err error) {
//     for i := range p {
//         p[i] = byte(f.src.Intn(256))
//     }
//     return len(p), nil
// }


func main() {
	var err error
	// seed := int64(12345678) // fixed seed for reproducibility
    // src := rand.New(rand.NewSource(seed))
    // fixedRandReader := &fixedReader{src}
	// privateKey, err = rsa.GenerateKey(fixedRandReader, 2048)
	// if err != nil {
	// 	log.Fatalf("Failed to generate key: %v", err)
	// }

	// Try load, else generate and save
	privateKey, err := loadPrivateKey("private.pem")
	if err != nil {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		err = savePrivateKey(privateKey, "private.pem")
		if err != nil {
			panic(err)
		}
	}
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
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
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


// Save private key to file in PEM format
func savePrivateKey(key *rsa.PrivateKey, filename string) error {
    keyBytes := x509.MarshalPKCS1PrivateKey(key)
    pemBlock := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: keyBytes,
    }
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    return pem.Encode(file, pemBlock)
}

// Load private key from PEM file
func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
    data, err := os.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(data)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, fmt.Errorf("failed to decode PEM block containing private key")
    }
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}