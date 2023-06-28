package grpc

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/ultravioletrs/cocos/auth"
	"go.opentelemetry.io/contrib/instrumentation/github.com/go-kit/kit/otelkit"
	"google.golang.org/grpc"
)

const svcName = "ultravioletrs.cocos.auth.AuthService"

var _ auth.AuthServiceClient = (*grpcClient)(nil)

type grpcClient struct {
	authorize    endpoint.Endpoint
	addPolicy    endpoint.Endpoint
	updatePolicy endpoint.Endpoint
	deletePolicy endpoint.Endpoint
	timeout      time.Duration
}

// NewClient returns new gRPC client instance.
func NewClient(conn *grpc.ClientConn, timeout time.Duration) auth.AuthServiceClient {
	return &grpcClient{
		authorize: otelkit.EndpointMiddleware(otelkit.WithOperation("authorize"))(kitgrpc.NewClient(
			conn,
			svcName,
			"Authorize",
			encodeAuthorizeRequest,
			decodeAuthorizeResponse,
			auth.AuthorizeRes{},
		).Endpoint()),
		addPolicy: otelkit.EndpointMiddleware(otelkit.WithOperation("add_policy"))(kitgrpc.NewClient(
			conn,
			svcName,
			"AddPolicy",
			encodeAddPolicyRequest,
			decodeAddPolicyResponse,
			auth.AddPolicyRes{},
		).Endpoint()),
		updatePolicy: otelkit.EndpointMiddleware(otelkit.WithOperation("update_policy"))(kitgrpc.NewClient(
			conn,
			svcName,
			"UpdatePolicy",
			encodeUpdatePolicyRequest,
			decodeUpdatePolicyResponse,
			auth.UpdatePolicyRes{},
		).Endpoint()),
		deletePolicy: otelkit.EndpointMiddleware(otelkit.WithOperation("delete_policy"))(kitgrpc.NewClient(
			conn,
			svcName,
			"DeletePolicy",
			encodeDeletePolicyRequest,
			decodeDeletePolicyResponse,
			auth.DeletePolicyRes{},
		).Endpoint()),

		timeout: timeout,
	}
}

func (client grpcClient) Authorize(ctx context.Context, req *auth.AuthorizeReq, _ ...grpc.CallOption) (r *auth.AuthorizeRes, err error) {
	ctx, close := context.WithTimeout(ctx, client.timeout)
	defer close()
	areq := authReq{
		user:        req.GetUser(),
		computation: req.GetComputation(),
		role:        req.GetRole(),
		domain:      req.GetDomain(),
	}
	res, err := client.authorize(ctx, areq)
	if err != nil {
		return &auth.AuthorizeRes{}, err
	}

	ar := res.(authorizeRes)
	return &auth.AuthorizeRes{Authorized: ar.authorized}, nil
}

func encodeAuthorizeRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(authReq)
	return &auth.AuthorizeReq{
		User:        req.user,
		Computation: req.computation,
		Role:        req.role,
		Domain:      req.domain,
	}, nil
}

func decodeAuthorizeResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*auth.AuthorizeRes)
	return authorizeRes{authorized: res.GetAuthorized()}, nil
}

func (client grpcClient) AddPolicy(ctx context.Context, req *auth.AddPolicyReq, opts ...grpc.CallOption) (*auth.AddPolicyRes, error) {
	ctx, close := context.WithTimeout(ctx, client.timeout)
	defer close()
	areq := addPolicyReq{
		token:        req.GetToken(),
		user:         req.GetUser(),
		computation:  req.GetComputation(),
		cloudRole:    req.GetCloudRole(),
		manifestRole: req.GetManifestRole(),
		publicKey:    req.GetPublicKey(),
	}
	res, err := client.addPolicy(ctx, areq)
	if err != nil {
		return &auth.AddPolicyRes{}, err
	}

	apr := res.(addPolicyRes)
	return &auth.AddPolicyRes{Added: apr.added}, nil
}

func encodeAddPolicyRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(addPolicyReq)
	return &auth.AddPolicyReq{
		Token:        req.token,
		User:         req.user,
		Computation:  req.computation,
		CloudRole:    req.cloudRole,
		ManifestRole: req.manifestRole,
		PublicKey:    req.publicKey,
	}, nil
}

func decodeAddPolicyResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*auth.AddPolicyRes)
	return addPolicyRes{added: res.GetAdded()}, nil
}

func (client grpcClient) UpdatePolicy(ctx context.Context, req *auth.UpdatePolicyReq, opts ...grpc.CallOption) (*auth.UpdatePolicyRes, error) {
	ctx, close := context.WithTimeout(ctx, client.timeout)
	defer close()
	ureq := updatePolicyReq{
		token:        req.GetToken(),
		user:         req.GetUser(),
		computation:  req.GetComputation(),
		cloudRole:    req.GetCloudRole(),
		manifestRole: req.GetManifestRole(),
	}
	res, err := client.addPolicy(ctx, ureq)
	if err != nil {
		return &auth.UpdatePolicyRes{}, err
	}

	upr := res.(updatePolicyRes)
	return &auth.UpdatePolicyRes{Updated: upr.updated}, nil
}

func encodeUpdatePolicyRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(updatePolicyReq)
	return &auth.UpdatePolicyReq{
		Token:        req.token,
		User:         req.user,
		Computation:  req.computation,
		CloudRole:    req.cloudRole,
		ManifestRole: req.manifestRole,
	}, nil
}

func decodeUpdatePolicyResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*auth.UpdatePolicyRes)
	return updatePolicyRes{updated: res.GetUpdated()}, nil
}

func (client grpcClient) DeletePolicy(ctx context.Context, req *auth.DeletePolicyReq, opts ...grpc.CallOption) (*auth.DeletePolicyRes, error) {
	ctx, close := context.WithTimeout(ctx, client.timeout)
	defer close()
	dreq := deletePolicyReq{
		token:       req.GetToken(),
		user:        req.GetUser(),
		computation: req.GetComputation(),
	}
	res, err := client.deletePolicy(ctx, dreq)
	if err != nil {
		return &auth.DeletePolicyRes{}, err
	}

	dpr := res.(deletePolicyRes)
	return &auth.DeletePolicyRes{Deleted: dpr.deleted}, err
}

func encodeDeletePolicyRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(deletePolicyReq)
	return &auth.DeletePolicyReq{
		Token:       req.token,
		User:        req.user,
		Computation: req.computation,
	}, nil
}

func decodeDeletePolicyResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*auth.DeletePolicyRes)
	return deletePolicyRes{deleted: res.GetDeleted()}, nil
}
