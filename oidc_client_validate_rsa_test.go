package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func rsaPublicKeyToJWK(kid string, pubKey *rsa.PublicKey) JWK {
	return JWK{
		Kid: kid,
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}
}

func TestOidcClient_Validate_RSA_UnknownKid(t *testing.T) {
	privKey := generateRSAKey(t)
	pubKey := &privKey.PublicKey

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user001",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	token.Header["kid"] = "unknown-kid"

	signedToken, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// JWKS has a different kid
	jwk := rsaPublicKeyToJWK("correct-kid", pubKey)
	client := &OidcClient{Jwks: &[]JWK{jwk}}

	_, err = client.Validate(signedToken)
	if err == nil || !strings.Contains(err.Error(), `unable to find key "unknown-kid"`) {
		t.Errorf("expected unknown kid error, got: %v", err)
	}
}

func TestOidcClient_Validate_RSA_InvalidSignature(t *testing.T) {
	signingKey := generateRSAKey(t)
	wrongKey := generateRSAKey(t) // public key won't match
	kid := "test-kid"

	claims := jwt.MapClaims{
		"sub": "user002",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedToken, _ := token.SignedString(signingKey)

	jwk := rsaPublicKeyToJWK(kid, &wrongKey.PublicKey)
	client := &OidcClient{Jwks: &[]JWK{jwk}}

	_, err := client.Validate(signedToken)
	if err == nil || !strings.Contains(err.Error(), "JWT parse/verify failed") {
		t.Errorf("expected signature verification error, got: %v", err)
	}
}

func TestOidcClient_Validate_RSA_ExpiredToken(t *testing.T) {
	privKey := generateRSAKey(t)
	pubKey := &privKey.PublicKey
	kid := "expired-kid"

	claims := jwt.MapClaims{
		"sub": "expired-user",
		"exp": time.Now().Add(-10 * time.Minute).Unix(), // expired
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedToken, _ := token.SignedString(privKey)

	jwk := rsaPublicKeyToJWK(kid, pubKey)
	client := &OidcClient{Jwks: &[]JWK{jwk}}

	_, err := client.Validate(signedToken)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("expected expiration error, got: %v", err)
	}
}
