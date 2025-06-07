package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestOidcClient_Validate_ECDSA(t *testing.T) {
	// Step 1: Generate ECDSA key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	kid := "ecdsa-kid-1"

	// Step 2: Create a signed JWT
	claims := jwt.MapClaims{
		"sub": "user456",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid

	signedToken, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	// Step 3: Create matching JWK
	jwk := JWK{
		Kid: kid,
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
	}

	client := &OidcClient{
		Jwks: &[]JWK{jwk},
	}

	// Step 4: Validate the JWT
	claimsOut, err := client.Validate(signedToken)
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	// Step 5: Manual assertions
	gotSub, ok := claimsOut["sub"]
	if !ok {
		t.Fatalf("Expected 'sub' in claims but not found")
	}
	if gotSub != "user456" {
		t.Errorf("Expected sub to be 'user456', got: %v", gotSub)
	}
}

func TestOidcClient_Validate_ECDSA_UnknownKid(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	// JWT uses this kid
	jwtKid := "jwt-kid"
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "user789",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	token.Header["kid"] = jwtKid
	signedToken, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	// JWKS has a different kid
	jwk := JWK{
		Kid: "wrong-kid",
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
	}
	client := &OidcClient{
		Jwks: &[]JWK{jwk},
	}

	_, err = client.Validate(signedToken)
	if err == nil || !strings.Contains(err.Error(), `unable to find key "jwt-kid"`) {
		t.Errorf("expected unknown kid error, got: %v", err)
	}
}

func TestOidcClient_Validate_ECDSA_InvalidSignature(t *testing.T) {
	// Use one key to sign...
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	kid := "ecdsa-key"

	claims := jwt.MapClaims{
		"sub": "user000",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signedToken, _ := token.SignedString(privKey1) // signed with key1

	// JWKS has pubKey2 instead (won’t match)
	jwk := JWK{
		Kid: kid,
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pubKey2.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pubKey2.PublicKey.Y.Bytes()),
	}
	client := &OidcClient{Jwks: &[]JWK{jwk}}

	_, err := client.Validate(signedToken)
	if err == nil || err.Error() == "" {
		t.Errorf("expected signature verification error, got nil")
	}
}

func TestOidcClient_Validate_ECDSA_ExpiredToken(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := &privKey.PublicKey
	kid := "ecdsa-expired"

	claims := jwt.MapClaims{
		"sub": "expired-user",
		"exp": time.Now().Add(-10 * time.Minute).Unix(), // expired
		"iat": time.Now().Add(-20 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signedToken, _ := token.SignedString(privKey)

	jwk := JWK{
		Kid: kid,
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
	}
	client := &OidcClient{Jwks: &[]JWK{jwk}}

	_, err := client.Validate(signedToken)
	if err == nil || err.Error() == "" {
		t.Errorf("expected expiration error, got nil")
	}
}
