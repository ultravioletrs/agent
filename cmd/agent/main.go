package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/logger"
	opentracing "github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	jconfig "github.com/uber/jaeger-client-go/config"
	agent "github.com/ultravioletrs/agent/agent"
	"github.com/ultravioletrs/agent/agent/api"
	agentgrpc "github.com/ultravioletrs/agent/agent/api/grpc"
	agenthttpapi "github.com/ultravioletrs/agent/agent/api/http"
	authClient "github.com/ultravioletrs/agent/internal/clients/grpc/auth"
	"github.com/ultravioletrs/cocos/auth"
	"google.golang.org/grpc"
)

const (
	defLogLevel   = "error"
	defHTTPPort   = "9031"
	defJaegerURL  = ""
	defServerCert = ""
	defServerKey  = ""
	defSecret     = "secret"
	defGRPCAddr   = "localhost:7002"

	envLogLevel       = "AGENT_LOG_LEVEL"
	envHTTPPort       = "AGENT_HTTP_PORT"
	envServerCert     = "AGENT_SERVER_CERT"
	envServerKey      = "AGENT_SERVER_KEY"
	envSecret         = "AGENT_SECRET"
	envJaegerURL      = "JAEGER_URL"
	envGRPCAddr       = "AGENT_GRPC_ADDR"
	envPrefixAuthGrpc = "AGENT_AUTH_GRPC_"
)

type config struct {
	logLevel   string
	httpPort   string
	serverCert string
	serverKey  string
	secret     string
	jaegerURL  string
	GRPCAddr   string
}

func main() {
	cfg := loadConfig()

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	agentTracer, agentCloser := initJaeger("agent", cfg.jaegerURL, logger)
	defer agentCloser.Close()

	auth, authHandler, err := authClient.Setup(envPrefixAuthGrpc, cfg.jaegerURL, "auth")
	if err != nil {
		logger.Fatal(err.Error())
	}
	defer authHandler.Close()

	logger.Info("Successfully connected to auth grpc server " + authHandler.Secure())

	svc := newService(cfg.secret, auth, logger)
	errs := make(chan error, 2)

	go startgRPCServer(cfg, &svc, logger, errs)
	go startHTTPServer(agenthttpapi.MakeHandler(agentTracer, svc), cfg.httpPort, cfg, logger, errs)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("Agent service terminated: %s", err))
}

func loadConfig() config {
	return config{
		logLevel:   mainflux.Env(envLogLevel, defLogLevel),
		httpPort:   mainflux.Env(envHTTPPort, defHTTPPort),
		serverCert: mainflux.Env(envServerCert, defServerCert),
		serverKey:  mainflux.Env(envServerKey, defServerKey),
		jaegerURL:  mainflux.Env(envJaegerURL, defJaegerURL),
		secret:     mainflux.Env(envSecret, defSecret),
		GRPCAddr:   mainflux.Env(envGRPCAddr, defGRPCAddr),
	}
}

func initJaeger(svcName, url string, logger logger.Logger) (opentracing.Tracer, io.Closer) {
	if url == "" {
		return opentracing.NoopTracer{}, io.NopCloser(nil)
	}

	tracer, closer, err := jconfig.Configuration{
		ServiceName: svcName,
		Sampler: &jconfig.SamplerConfig{
			Type:  "const",
			Param: 1,
		},
		Reporter: &jconfig.ReporterConfig{
			LocalAgentHostPort: url,
			LogSpans:           true,
		},
	}.NewTracer()
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to init Jaeger client: %s", err))
		os.Exit(1)
	}

	return tracer, closer
}

func newService(secret string, auth auth.AuthServiceClient, logger logger.Logger) agent.Service {
	svc := agent.New(secret, auth)

	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "agent",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "agent",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)

	return svc
}

func startHTTPServer(handler http.Handler, port string, cfg config, logger logger.Logger, errs chan error) {
	p := fmt.Sprintf(":%s", port)
	if cfg.serverCert != "" || cfg.serverKey != "" {
		logger.Info(fmt.Sprintf("Agent service started using https on port %s with cert %s key %s",
			port, cfg.serverCert, cfg.serverKey))
		errs <- http.ListenAndServeTLS(p, cfg.serverCert, cfg.serverKey, handler)
		return
	}
	logger.Info(fmt.Sprintf("Agent service started using http on port %s", cfg.httpPort))
	errs <- http.ListenAndServe(p, handler)
}

func startgRPCServer(cfg config, svc *agent.Service, logger logger.Logger, errs chan error) {
	// Create a gRPC server object
	tracer := opentracing.GlobalTracer()
	server := grpc.NewServer()
	// Register the implementation of the service with the server
	agent.RegisterAgentServiceServer(server, agentgrpc.NewServer(tracer, *svc))
	// Listen to a port and serve incoming requests
	listener, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatalf(err.Error())
	}
	logger.Info(fmt.Sprintf("Agent service started using gRPC on address %s", cfg.GRPCAddr))
	errs <- server.Serve(listener)
}
