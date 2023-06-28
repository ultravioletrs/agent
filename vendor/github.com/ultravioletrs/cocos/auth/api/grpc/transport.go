package grpc

import (
	"context"

	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/cocos/auth"
	"github.com/ultravioletrs/cocos/internal/apiutil"
	"go.opentelemetry.io/contrib/instrumentation/github.com/go-kit/kit/otelkit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ auth.AuthServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	authorize    kitgrpc.Handler
	addPolicy    kitgrpc.Handler
	updatePolicy kitgrpc.Handler
	deletePolicy kitgrpc.Handler
	auth.UnimplementedAuthServiceServer
}

// NewServer returns new AuthServiceServer instance.
func NewServer(svc auth.Service) auth.AuthServiceServer {
	return &grpcServer{
		authorize: kitgrpc.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("authorize"))(authorizeEndpoint(svc)),
			decodeAuthorizeRequest,
			encodeAuthorizeResponse,
		),
		addPolicy: kitgrpc.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("add_policy"))(addPolicyEndpoint(svc)),
			decodeAddPolicyRequest,
			encodeAddPolicyResponse,
		),
		updatePolicy: kitgrpc.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("update_policy"))(updatePolicyEndpoint(svc)),
			decodeUpdatePolicyRequest,
			encodeUpdatePolicyResponse,
		),
		deletePolicy: kitgrpc.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("delete_policy"))(deletePolicyEndpoint(svc)),
			decodeDeletePolicyRequest,
			encodeDeletePolicyResponse,
		),
	}
}

func (s *grpcServer) Authorize(ctx context.Context, req *auth.AuthorizeReq) (*auth.AuthorizeRes, error) {
	_, res, err := s.authorize.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*auth.AuthorizeRes), nil
}

func (s *grpcServer) AddPolicy(ctx context.Context, req *auth.AddPolicyReq) (*auth.AddPolicyRes, error) {
	_, res, err := s.addPolicy.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*auth.AddPolicyRes), nil
}

func (s *grpcServer) UpdatePolicy(ctx context.Context, req *auth.UpdatePolicyReq) (*auth.UpdatePolicyRes, error) {
	_, res, err := s.updatePolicy.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*auth.UpdatePolicyRes), nil
}

func (s *grpcServer) DeletePolicy(ctx context.Context, req *auth.DeletePolicyReq) (*auth.DeletePolicyRes, error) {
	_, res, err := s.deletePolicy.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*auth.DeletePolicyRes), nil
}

func decodeAuthorizeRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*auth.AuthorizeReq)
	return authReq{
		user:        req.GetUser(),
		computation: req.GetComputation(),
		role:        req.GetRole(),
		domain:      req.GetDomain(),
	}, nil
}

func encodeAuthorizeResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(authorizeRes)
	return &auth.AuthorizeRes{Authorized: res.authorized}, nil
}

func decodeAddPolicyRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*auth.AddPolicyReq)
	return addPolicyReq{
		token:        req.GetToken(),
		user:         req.GetUser(),
		computation:  req.GetComputation(),
		cloudRole:    req.GetCloudRole(),
		manifestRole: req.GetManifestRole(),
		publicKey:    req.GetPublicKey(),
	}, nil
}

func encodeAddPolicyResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(addPolicyRes)
	return &auth.AddPolicyRes{Added: res.added}, nil
}

func decodeUpdatePolicyRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*auth.UpdatePolicyReq)
	return updatePolicyReq{
		token:        req.GetToken(),
		user:         req.GetUser(),
		computation:  req.GetComputation(),
		cloudRole:    req.GetCloudRole(),
		manifestRole: req.GetManifestRole(),
	}, nil
}

func encodeUpdatePolicyResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(updatePolicyRes)
	return &auth.UpdatePolicyRes{Updated: res.updated}, nil
}

func decodeDeletePolicyRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*auth.DeletePolicyReq)
	return deletePolicyReq{
		token:       req.GetToken(),
		user:        req.GetUser(),
		computation: req.GetComputation(),
	}, nil
}

func encodeDeletePolicyResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(deletePolicyRes)
	return &auth.DeletePolicyRes{Deleted: res.deleted}, nil
}

func encodeError(err error) error {
	switch {
	case errors.Contains(err, nil):
		return nil
	case errors.Contains(err, errors.ErrMalformedEntity),
		errors.Contains(err, apiutil.ErrMissingID),
		errors.Contains(err, apiutil.ErrEmptyList),
		errors.Contains(err, apiutil.ErrNameSize),
		errors.Contains(err, apiutil.ErrMalformedPolicy),
		errors.Contains(err, apiutil.ErrMissingUser),
		errors.Contains(err, apiutil.ErrMissingComputation),
		errors.Contains(err, apiutil.ErrCloudRole),
		errors.Contains(err, apiutil.ErrManifestRole):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Contains(err, errors.ErrAuthentication):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Contains(err, errors.ErrAuthorization):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Contains(err, errors.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Contains(err, errors.ErrConflict):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Contains(err, errors.ErrUnsupportedContentType):
		return status.Error(codes.Unimplemented, err.Error())
	case errors.Contains(err, errors.ErrCreateEntity),
		errors.Contains(err, errors.ErrUpdateEntity),
		errors.Contains(err, errors.ErrViewEntity),
		errors.Contains(err, errors.ErrRemoveEntity):
		return status.Error(codes.Internal, err.Error())
	default:
		return status.Error(codes.Internal, "internal server error")
	}
}
