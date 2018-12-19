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
		fmt.Println("Can't create logger", err)
		return
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	server := grpc.NewServer()
	auth_proto.RegisterAuthCheckerServer(server, auth.NewAuthManager(os.Getenv("JWT"), sugar))

	sugar.Infow("Starting server",
		"port", 8080,
	)
	lis, err := net.Listen("tcp", ":8080") // nolint: gosec
	if err != nil {
		sugar.Errorw("Can't create server",
			"port", 8080,
		)
		return
	}

	if err := server.Serve(lis); err != nil {
		sugar.Fatalw("Can't start server",
			"error", err,
		)
	}
}
