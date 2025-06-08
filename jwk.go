package oidc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

func (j *JWK) rsaPublicKey() (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	e := 0
	for _, b := range eb {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}, nil
}

func (j *JWK) ecdsaPublicKey() (*ecdsa.PublicKey, error) {
	xb, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	var (
		curve     elliptic.Curve
		ecdhCurve ecdh.Curve
	)
	switch j.Crv {
	case "P-256":
		curve = elliptic.P256()
		ecdhCurve = ecdh.P256()
	case "P-384":
		curve = elliptic.P384()
		ecdhCurve = ecdh.P384()
	case "P-521":
		curve = elliptic.P521()
		ecdhCurve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", j.Crv)
	}

	byteLen := (curve.Params().BitSize + 7) >> 3
	if len(xb) != byteLen || len(yb) != byteLen {
		return nil, fmt.Errorf("invalid coordinate length: want %d bytes, got X=%d, Y=%d",
			byteLen, len(xb), len(yb))
	}
	enc := make([]byte, 1+2*byteLen)
	enc[0] = 4
	copy(enc[1:1+byteLen], xb)
	copy(enc[1+byteLen:], yb)

	if _, err := ecdhCurve.NewPublicKey(enc); err != nil {
		return nil, fmt.Errorf("invalid EC public key: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}
