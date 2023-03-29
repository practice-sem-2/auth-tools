package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"
	"os"
)

const AuthHeaderKey = "Authorization"
const UserKey = "AuthorizedUser"

var (
	ErrInvalidToken = errors.New("provided token is invalid")
	ErrBadContext   = errors.New("can't retrieve metadata from context")
	ErrNoAuth       = errors.New("token is not provided")
	ErrTokenExpired = errors.New("provided token has expired")
)

type UserClaims struct {
	jwt.RegisteredClaims
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	AvatarID  string `json:"avatar_id"`
}

type VerifierService struct {
	PublicKey *rsa.PublicKey
}

func NewVerifierFromPem(publicKeyRaw []byte) (*VerifierService, error) {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyRaw)
	if err != nil {
		return nil, err
	}

	return &VerifierService{
		PublicKey: publicKey,
	}, nil
}

func NewVerifierFromFile(publicKeyPath string) (*VerifierService, error) {
	publicKeyRaw, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	return NewVerifierFromPem(publicKeyRaw)
}

func (s *VerifierService) GetUser(ctx context.Context) (*UserClaims, error) {
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrBadContext
	}

	auth := meta.Get(AuthHeaderKey)
	if len(auth) == 0 {
		return nil, ErrNoAuth
	}

	user, err := s.ParseToken(auth[0])

	if err != nil {
		return nil, ErrInvalidToken
	}

	return user, nil
}

func (s *VerifierService) ParseToken(token string) (*UserClaims, error) {

	tokenData, err := jwt.ParseWithClaims(token, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidToken
		}
		return s.PublicKey, nil
	})

	claims, ok := tokenData.Claims.(*UserClaims)
	if ok && tokenData != nil && tokenData.Valid {
		return claims, nil
	}

	if errors.Is(err, jwt.ErrTokenExpired) {
		return claims, ErrTokenExpired
	}
	return claims, err
}

type SignerService struct {
	PrivateKey *rsa.PrivateKey
}

func NewSignerFromPem(privateKeyRaw []byte) (*SignerService, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyRaw)

	if err != nil {
		return nil, err
	}

	return &SignerService{
		PrivateKey: privateKey,
	}, nil
}

func NewSignerFromFile(privateKeyPath string) (*SignerService, error) {
	privateKeyRaw, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	return NewSignerFromPem(privateKeyRaw)
}

func MustNewSignerFromFile(privateKeyPath string) *SignerService {
	interceptor, err := NewSignerFromFile(privateKeyPath)
	if err != nil {
		panic(err)
	}
	return interceptor
}

func (s *SignerService) SignToken(claims *UserClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(s.PrivateKey)
	if err != nil {
		return "", err
	}
	return ss, nil
}
