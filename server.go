package main

import (
	"fmt"
	"net"
	"os"

	auth "github.com/go-park-mail-ru/2018_2_LSP_AUTH_GRPC/auth"
	"github.com/go-park-mail-ru/2018_2_LSP_AUTH_GRPC/auth_proto"
	"go.uber.org/zap"

	"google.golang.org/grpc"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Println("Can't create logger")
		return
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	server := grpc.NewServer()
	auth_proto.RegisterAuthCheckerServer(server, auth.NewAuthManager(os.Getenv("JWT"), sugar))

	sugar.Infow("Starting server",
		"port", 8080,
	)
	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		sugar.Fatalw("Can't create server",
			"port", 8080,
		)
	}

	server.Serve(lis)
}