package auth

import (
	"github.com/mainflux/mainflux/pkg/errors"
	grpcClient "github.com/ultravioletrs/agent/internal/clients/grpc"
	"github.com/ultravioletrs/agent/internal/env"
	"github.com/ultravioletrs/cocos/auth"
	authapi "github.com/ultravioletrs/cocos/auth/api/grpc"
)

const envAuthGrpcPrefix = "AGENT_AUTH_GRPC_"

var errGrpcConfig = errors.New("failed to load grpc configuration")

// Setup loads Auth gRPC configuration from environment variable and creates new Auth gRPC API.
func Setup(envPrefix, jaegerURL, svcName string) (auth.AuthServiceClient, grpcClient.ClientHandler, error) {
	config := grpcClient.Config{}
	if err := env.Parse(&config, env.Options{Prefix: envAuthGrpcPrefix, AltPrefix: envPrefix}); err != nil {
		return nil, nil, errors.Wrap(errGrpcConfig, err)
	}
	c, ch, err := grpcClient.Setup(config, svcName, jaegerURL)
	if err != nil {
		return nil, nil, err
	}

	return authapi.NewClient(c.ClientConn, config.Timeout), ch, nil
}
