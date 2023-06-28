package grpc

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/auth"
)

func authorizeEndpoint(svc auth.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(authReq)
		if err := req.validate(); err != nil {
			return authorizeRes{}, err
		}
		aReq := auth.AccessRequest{
			User:        req.user,
			Computation: req.computation,
			Role:        req.role,
			Domain:      req.domain,
		}
		err := svc.Authorize(ctx, aReq)
		if err != nil {
			return authorizeRes{}, err
		}
		return authorizeRes{authorized: true}, nil
	}
}

func addPolicyEndpoint(svc auth.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(addPolicyReq)
		if err := req.validate(); err != nil {
			return addPolicyRes{}, err
		}
		policy := auth.Policy{
			User:         req.user,
			Computation:  req.computation,
			CloudRole:    req.cloudRole,
			ManifestRole: req.manifestRole,
			PublicKey:    req.publicKey,
		}
		err := svc.AddPolicy(ctx, req.token, policy)
		if err != nil {
			return addPolicyRes{}, err
		}
		return addPolicyRes{added: true}, nil
	}
}

func updatePolicyEndpoint(svc auth.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updatePolicyReq)
		if err := req.validate(); err != nil {
			return updatePolicyRes{}, err
		}
		policy := auth.Policy{
			User:         req.user,
			Computation:  req.computation,
			CloudRole:    req.cloudRole,
			ManifestRole: req.manifestRole,
		}
		err := svc.UpdatePolicy(ctx, req.token, policy)
		if err != nil {
			return updatePolicyRes{}, err
		}
		return updatePolicyRes{updated: true}, nil
	}
}

func deletePolicyEndpoint(svc auth.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(deletePolicyReq)
		if err := req.validate(); err != nil {
			return deletePolicyRes{}, err
		}

		policy := auth.Policy{
			User:        req.user,
			Computation: req.computation,
		}
		err := svc.DeletePolicy(ctx, req.token, policy)
		if err != nil {
			return deletePolicyRes{}, err
		}
		return deletePolicyRes{deleted: true}, nil
	}
}
