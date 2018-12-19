package auth

import (
	"context"
	"math/rand"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-park-mail-ru/2018_2_LSP_AUTH_GRPC/auth_proto"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func TestHashPassword(t *testing.T) {
	t.Run("empty password", func(t *testing.T) {
		_, err := hashPassword("")
		if err == nil {
			t.Error("Hashig of empty password must return an error")
		}
	})
	t.Run("general password hash", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			password := randStringRunes(rand.Intn(100) + 1)
			hashed, err := hashPassword(password)
			if err != nil {
				t.Error("Error occured during hash check", err)
			}
			if !checkPasswordHash(password, hashed) {
				t.Error("Error during password validation after hashing")
			}
		}
	})
}

func TestGenerate(t *testing.T) {
	logger, err := zap.NewProduction()
	if err != nil {
		t.Error("Can't create logger", err)
		return
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	cnt := context.Background()

	am := NewAuthManager("", sugar)
	claims := jwt.MapClaims{}

	t.Run("general token generating", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			am.token = randStringRunes(rand.Intn(100) + 1)
			token, err := am.Generate(cnt, &auth_proto.TokenPayload{ID: rand.Int63n(1000)})
			_, err = jwt.ParseWithClaims(token.Token, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(am.token), nil
			})
			if err != nil {
				t.Error("Error during verification of generated token", err)
			}
		}
	})
}

func TestCheck(t *testing.T) {
	logger, err := zap.NewProduction()
	if err != nil {
		t.Error("Can't create logger", err)
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	cnt := context.Background()

	am := NewAuthManager("", sugar)

	t.Run("general token validation", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			tokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"id": rand.Int63n(1000),
			})
			token, err := tokenJWT.SignedString([]byte(am.token))
			if err != nil {
				t.Error("Error during token generation", err)
			}

			res, err := am.Check(cnt, &auth_proto.Token{Token: token})
			if err != nil {
				t.Error("Error during token validation", err)
			}
			if !res.Valid {
				t.Error("Valid token is invalid")
			}
		}
	})
}
