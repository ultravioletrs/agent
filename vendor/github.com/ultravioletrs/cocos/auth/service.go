package auth

import (
	"context"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/pkg/errors"
	users "github.com/mainflux/mainflux/users/policies"
)

const (
	compsObjectKey  = "client"
	addPolicyAction = "g_add"
	entityType      = "client"
	CloudDomain     = "cloud"
	ManifestDomain  = "manifest"
)

// ErrInvalidDomainType indicates that the domain type is invalid.
var ErrInvalidDomainType = errors.New("invalid domain type")

type service struct {
	auth       Repository
	users      users.AuthServiceClient
	idProvider mainflux.IDProvider
}

// NewService returns a new Policies service implementation.
func NewService(repo Repository, users users.AuthServiceClient, idp mainflux.IDProvider) Service {
	return service{
		auth:       repo,
		users:      users,
		idProvider: idp,
	}
}

func (svc service) Authorize(ctx context.Context, ar AccessRequest) error {
	switch ar.Domain {
	case CloudDomain:
		if _, err := svc.auth.EvaluateCloudAccess(ctx, ar); err != nil {
			return err
		}
	case ManifestDomain:
		if _, err := svc.auth.EvaluateManifestAccess(ctx, ar); err != nil {
			return err
		}
	default:
		return ErrInvalidDomainType
	}

	return nil
}

// AddPolicy adds a policy is added if:
//
//  1. The user identified by the token is admin.
//  2. The user identified by the token is the owner of the computation.
func (svc service) AddPolicy(ctx context.Context, token string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}

	id, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}

	if err := svc.checkPolicy(ctx, id, p); err != nil {
		return err
	}

	p.Owner = id
	p.CreatedAt = time.Now()

	// incase the policy exists, update it.
	p.UpdatedAt = time.Now()
	p.UpdatedBy = id

	if _, err := svc.auth.Save(ctx, p); err != nil {
		return err
	}

	return nil
}

func (svc service) UpdatePolicy(ctx context.Context, token string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}

	id, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}

	if err := svc.checkPolicy(ctx, id, p); err != nil {
		return err
	}

	p.UpdatedAt = time.Now()
	p.UpdatedBy = id

	// Update Cloud Role.
	if len(p.CloudRole) != 0 && len(p.ManifestRole) == 0 {
		return svc.auth.UpdateCloud(ctx, p)
	}

	// Update Manifest Role.
	if len(p.ManifestRole) != 0 && len(p.CloudRole) == 0 {
		return svc.auth.UpdateManifest(ctx, p)
	}

	return nil
}

func (svc service) ListPolicies(ctx context.Context, token string, pm Page) (PolicyPage, error) {
	id, err := svc.identify(ctx, token)
	if err != nil {
		return PolicyPage{}, err
	}

	// If the user is admin, return all policies
	if err := svc.checkAdmin(ctx, id); err == nil {
		return svc.auth.RetrieveAll(ctx, pm)
	}

	// If the user is not admin, return only the policies that they created
	pm.Owner = id

	return svc.auth.RetrieveAll(ctx, pm)
}

func (svc service) DeletePolicy(ctx context.Context, token string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}

	id, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if err := svc.checkPolicy(ctx, id, p); err != nil {
		return err
	}

	return svc.auth.Delete(ctx, p)
}

// identify returns the client ID associated with the provided token.
func (svc service) identify(ctx context.Context, token string) (string, error) {
	req := &users.Token{Value: token}
	res, err := svc.users.Identify(ctx, req)
	if err != nil {
		return "", errors.Wrap(errors.ErrAuthorization, err)
	}

	return res.GetId(), nil
}

func (svc service) checkAdmin(ctx context.Context, id string) error {
	// for checking admin rights policy object, action and entity type are not important
	req := &users.AuthorizeReq{
		Sub:        id,
		Obj:        compsObjectKey,
		Act:        addPolicyAction,
		EntityType: entityType,
	}
	res, err := svc.users.Authorize(ctx, req)
	if err != nil {
		return errors.Wrap(errors.ErrAuthorization, err)
	}
	if !res.GetAuthorized() {
		return errors.ErrAuthorization
	}

	return nil
}

// checkPolicy checks if the user identified by the token is admin or the owner of the computation.
func (svc service) checkPolicy(ctx context.Context, id string, p Policy) error {
	if err := svc.checkAdmin(ctx, id); err == nil {
		return nil
	}

	ar := AccessRequest{User: p.User, Computation: p.Computation, Domain: CloudDomain}
	if _, err := svc.auth.EvaluateCloudAccess(ctx, ar); err == nil {
		return nil
	}

	return errors.ErrAuthorization
}
