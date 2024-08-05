package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"net/http"
	"time"
)

func main() {
	// Generating a rsa key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey := &privateKey.PublicKey

	// serializing private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	strpvtkey := base64.StdEncoding.EncodeToString(privateKeyPEM)
	println("\n-=-PRIVATE BASE64-=-\n", fmt.Sprintf("%s", strpvtkey), "\n-=-PRIVATE-=-")

	// serializing public key
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	strpubkey := base64.StdEncoding.EncodeToString(publicKeyPEM)
	println("\n-=-PUBLIC BASE64-=-\n", fmt.Sprintf("%s", strpubkey), "\n-=-PUBLIC-=-\n")

	// Base64 decode
	pvtFromStr, _ := base64.StdEncoding.DecodeString(strpvtkey)
	pubFromStr, _ := base64.StdEncoding.DecodeString(strpubkey)

	// parsing keys from PEM format
	parsedPrivateKey, err := jwk.ParseKey(pvtFromStr, jwk.WithPEM(true))
	if err != nil {
		fmt.Printf("failed to parse JWK: %s\n", err)
		return
	}

	parsedPubkey, err := jwk.ParseKey(pubFromStr, jwk.WithPEM(true))
	if err != nil {
		fmt.Printf("failed to get public key: %s\n", err)
		return
	}

	// setting fields
	parsedPubkey.Set(jwk.KeyIDKey, "key-id")
	parsedPubkey.Set(jwk.AlgorithmKey, jwa.RS256)
	parsedPubkey.Set(jwk.KeyTypeKey, jwa.RSA)

	parsedPrivateKey.Set(jwk.KeyIDKey, "key-id")
	parsedPrivateKey.Set(jwk.AlgorithmKey, jwa.RS256)
	parsedPrivateKey.Set(jwk.KeyTypeKey, jwa.RSA)

	// creating the JWT
	tok, err := jwt.NewBuilder().
		Issuer("jwt-issuer").
		IssuedAt(time.Now()).
		NotBefore(time.Now()).
		Expiration(time.Now().Add(time.Hour*24)).
		Claim("metadata", `{"meta": "data"}`).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	// signing the jwt with the private key
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, parsedPrivateKey))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	// you can copy the string and check the token out at https://jwt.io/ or a similar site
	println(fmt.Sprintf(">>> signed: %s", signed))

	// creating the jwks endpoint to expose the public key
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		asMap, err := parsedPubkey.AsMap(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		indent, err := json.MarshalIndent(asMap, "", "  ")
		if err != nil {
			return
		}
		_, _ = w.Write(indent)
	})

	go func() {
		err = http.ListenAndServe(":8888", mux)
		if err != nil {
			panic(err)
		}
	}()

	// registering the jwks url
	pubCertFetcher := jwk.NewCache(context.Background())
	err = pubCertFetcher.Register("http://localhost:8888/.well-known/jwks.json")
	if err != nil {
		fmt.Printf("failed to register jwks url: %s\n", err)
		return
	}

	// retrieving the public key from the registered (and cached) jwks endpoint
	keySet, err := pubCertFetcher.Get(context.Background(), "http://localhost:8888/.well-known/jwks.json")
	if err != nil {
		fmt.Printf("failed to fetch jwks url: %s\n", err)
		return
	}

	// parsing (verifying and validating) the signed jwt
	token, err := jwt.Parse(signed, jwt.WithKeySet(keySet))
	if err != nil {
		fmt.Printf("failed to parse jwks url: %#s\n", err.Error())
		return
	}

	fmt.Printf("\n>>> token varified against the jwks url: %#v\n", token)
}
