package grpc

import (
	"github.com/mainflux/mainflux/pkg/errors"
	agentapi "github.com/ultravioletrs/agent/agent/api/grpc"
	"github.com/ultravioletrs/agent/internal/env"
)

const envAgentGRPCPrefix = "AGENT_GRPC_"

var errGrpcConfig = errors.New("failed to load grpc configuration")

// Setup loads Users gRPC configuration from environment variable and creates new Users gRPC API.
func Setup() (*Client, error) {
	config := Config{}
	if err := env.Parse(&config, env.Options{Prefix: envAgentGRPCPrefix}); err != nil {
		return nil, errors.Wrap(errGrpcConfig, err)
	}

	conn, secure, err := connect(config)
	if err != nil {
		return nil, err
	}
	client := agentapi.NewClient(conn, config.Timeout)

	return setup(conn, secure, client)
}
