package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type TestKeyPair struct {
	PrivateKey    *rsa.PrivateKey
	PublicKey     *rsa.PublicKey
	PrivateKeyPem []byte
	PublicKeyPem  []byte
}

func NewTestKeyPair(t *testing.T) *TestKeyPair {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)

	if err != nil {
		assert.FailNow(t, "failed to generate rsa keys")
	}

	privatePem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	if privatePem == nil {
		assert.FailNow(t, "can't encode private key")
	}

	x509Bytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	publicPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509Bytes,
	})

	if publicPem == nil {
		assert.FailNow(t, "can't encode public key")
	}

	return &TestKeyPair{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		PrivateKeyPem: privatePem,
		PublicKeyPem:  publicPem,
	}
}

func TestService_NewSignerFromPem(t *testing.T) {
	keys := NewTestKeyPair(t)
	service, err := NewSignerFromPem(keys.PrivateKeyPem)
	assert.NoErrorf(t, err, "should not return any errors")
	assert.Equal(t, keys.PrivateKey, service.PrivateKey, "must be equal")
}

func TestService_NewVerifierFromPem(t *testing.T) {
	keys := NewTestKeyPair(t)
	service, err := NewVerifierFromPem(keys.PublicKeyPem)
	assert.NoErrorf(t, err, "should not return any errors")
	assert.Equal(t, keys.PublicKey, service.PublicKey, "must be equal")
}

func TestService_SignToken(t *testing.T) {
	keys := NewTestKeyPair(t)
	signer, _ := NewSignerFromPem(keys.PrivateKeyPem)
	verifier, _ := NewVerifierFromPem(keys.PublicKeyPem)
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(3 * time.Hour)
	claims := &UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		Username:  "johndoe",
		Email:     "doe@example.com",
		FirstName: "John",
		LastName:  "John",
		AvatarID:  "1cbbb567-6e35-4267-abe5-41cf2208fbe8",
	}
	tokenString, err := signer.SignToken(claims)

	assert.NoError(t, err, "should not return any errors")
	parsedClaims, err := verifier.ParseToken(tokenString)
	assert.NoError(t, err, "should not return any errors")

	assert.Equal(t, claims.Username, parsedClaims.Username)
	assert.Equal(t, claims.FirstName, parsedClaims.FirstName)
	assert.Equal(t, claims.LastName, parsedClaims.LastName)
	assert.Equal(t, claims.Email, parsedClaims.Email)
	assert.Equal(t, claims.AvatarID, parsedClaims.AvatarID)
}

func TestService_ParseToken_ExpiredToken(t *testing.T) {
	keys := NewTestKeyPair(t)
	signer, _ := NewSignerFromPem(keys.PrivateKeyPem)
	verifier, _ := NewVerifierFromPem(keys.PublicKeyPem)
	issuedAt := time.Now().Add(-3 * time.Hour).UTC()
	expiresAt := issuedAt.Add(30 * time.Minute).UTC()

	claims := &UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		Username:  "johndoe",
		Email:     "doe@example.com",
		FirstName: "John",
		LastName:  "John",
		AvatarID:  "1cbbb567-6e35-4267-abe5-41cf2208fbe8",
	}
	tokenString, err := signer.SignToken(claims)

	assert.NoError(t, err, "should not return any errors")
	_, err = verifier.ParseToken(tokenString)

	assert.ErrorIs(t, err, ErrTokenExpired, "should return token expiration error")

}
