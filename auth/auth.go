package auth

import (
	"encoding/json"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-park-mail-ru/2018_2_LSP_AUTH_GRPC/auth_proto"
	"golang.org/x/net/context"
)

type AuthManager struct {
	token  string
	logger *zap.SugaredLogger
}

func NewAuthManager(token string, logger *zap.SugaredLogger) *AuthManager {
	return &AuthManager{token, logger}
}

func (sm *AuthManager) Check(ctx context.Context, in *auth_proto.Token) (*auth_proto.TokenChecked, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(in.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sm.token), nil
	})

	if err != nil {
		return &auth_proto.TokenChecked{Valid: false}, nil
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Internal server error")
	}

	return &auth_proto.TokenChecked{Valid: true, Claims: []byte(claimsJSON)}, nil
}

func (sm *AuthManager) Generate(ctx context.Context, in *auth_proto.TokenPayload) (*auth_proto.Token, error) {
	tokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id": in.ID,
	})
	token, err := tokenJWT.SignedString([]byte(sm.token))
	if err != nil {
		sm.logger.Errorw("Internal error",
			"err", err,
		)
		return nil, grpc.Errorf(codes.Internal, "Internal server error")
	}
	return &auth_proto.Token{Token: token}, nil
}
