package grpc

import (
	"time"

	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/agent/agent"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	errGrpcConnect = errors.New("failed to connect to grpc server")
	errGrpcClose   = errors.New("failed to close grpc connection")
)

type Config struct {
	ClientTLS bool          `env:"CLIENT_TLS"    envDefault:"false"`
	CACerts   string        `env:"CA_CERTS"      envDefault:""`
	URL       string        `env:"URL"           envDefault:""`
	Timeout   time.Duration `env:"TIMEOUT"       envDefault:"1s"`
}

type ClientHandler interface {
	Close() error
	IsSecure() bool
	Secure() string
}

type Client struct {
	*gogrpc.ClientConn
	agent.AgentServiceClient
	secure bool
}

var _ ClientHandler = (*Client)(nil)

// connect creates new gRPC client and connect to gRPC server.
func connect(cfg Config) (*gogrpc.ClientConn, bool, error) {
	var opts []gogrpc.DialOption
	secure := false
	tc := insecure.NewCredentials()

	if cfg.ClientTLS && cfg.CACerts != "" {
		var err error
		tc, err = credentials.NewClientTLSFromFile(cfg.CACerts, "")
		if err != nil {
			return nil, secure, err
		}
		secure = true
	}

	opts = append(opts, gogrpc.WithTransportCredentials(tc), gogrpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()))

	conn, err := gogrpc.Dial(cfg.URL, opts...)
	if err != nil {
		return nil, secure, errors.Wrap(errGrpcConnect, err)
	}

	return conn, secure, nil
}

// setup creates new gRPC client.
func setup(conn *gogrpc.ClientConn, secure bool, agent agent.AgentServiceClient) (*Client, error) {
	return &Client{
		ClientConn:         conn,
		AgentServiceClient: agent,
		secure:             secure,
	}, nil
}

// Close shuts down the gRPC connection.
func (c *Client) Close() error {
	if err := c.ClientConn.Close(); err != nil {
		return errors.Wrap(errGrpcClose, err)
	}

	return nil
}

// IsSecure is utility method for checking if
// the client is running with TLS enabled.
func (c *Client) IsSecure() bool {
	return c.secure
}

// Secure is used for pretty printing TLS info.
func (c *Client) Secure() string {
	if c.secure {
		return "with TLS"
	}
	return "without TLS"
}
