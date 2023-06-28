package auth

import (
	"context"
	"time"

	"github.com/ultravioletrs/cocos/internal/apiutil"
)

var (
	// CloudRoles contains all the possible cloud roles.
	//
	// 1. The view role is used to view a computation.
	//
	// 2. The edit role is used to change all the fields except adding new providers and consumers to policies.
	//
	// 3. The run role is used to generate manifest and start computation.
	//
	// There are two other fields not covered which is owner and admin.
	// The owner has all the rights and admin is the same as owner.
	CloudRoles = []string{"view", "edit", "run"}

	// ManifestRoles contains all the possible manifest roles.
	// The manifest role is used to generate manifest.
	//
	// 1. The dataset_provider role is used to provide dataset.
	//
	// 2. The algorithm_provider role is used to provide algorithm.
	//
	// 3. The result_consumer role is used to consume result.
	//
	// The manifest role can be empty.
	ManifestRoles = []string{"dataset_provider", "algorithm_provider", "result_consumer"}
)

// Policy represents an argument struct for making a policy related function calls.
type Policy struct {
	Owner        string    `json:"owner"`
	User         string    `json:"user"`
	Computation  string    `json:"computation"`
	CloudRole    []string  `json:"cloud_role"`
	ManifestRole []string  `json:"manifest_role,omitempty"`
	PublicKey    string    `json:"public_key"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
	UpdatedBy    string    `json:"updated_by,omitempty"`
}

// AccessRequest represents an access control request for Authorization.
type AccessRequest struct {
	User        string `json:"user"`
	Computation string `json:"computation"`
	Role        string `json:"role"`   // can either a cloud role or a manifest role
	Domain      string `json:"domain"` // can either be cloud or manifest
}

// PolicyPage contains a page of policies.
type PolicyPage struct {
	Page
	Policies []Policy
}

// Repository specifies a policy persistence API.
type Repository interface {
	// Save creates a policy for the given Policy User and Computation combination.
	// It returns an error and an empty policy if the policy already exists or the operation failed
	// otherwise it returns nil and the policy.
	Save(ctx context.Context, p Policy) (Policy, error)

	// EvaluateCloudAccess is used to evaluate if user has access to a computation in the cloud domain.
	// It returns an error and an empty policy if the user does not have access
	// otherwise it returns nil and the policy.
	EvaluateCloudAccess(ctx context.Context, ar AccessRequest) (Policy, error)

	// EvaluateManifestAccess is used to evaluate if user has access to a computation in the manifest domain.
	// It returns an error and an empty policy if the user does not have access
	// otherwise it returns nil and the policy.
	EvaluateManifestAccess(ctx context.Context, ar AccessRequest) (Policy, error)

	// UpdateCloud updates the policy cloud roles for the given Policy User and Computation combination.
	// It overwrites the existing policy cloud role with the new policy cloud role.
	// It returns an error if the policy does not exist or the operation failed
	// otherwise it returns nil.
	UpdateCloud(ctx context.Context, p Policy) error

	// UpdateManifest updates the policy manifest roles for the given Policy User and Computation combination.
	// It overwrites the existing policy manifest role with the new policy manifest role.
	// It returns an error if the policy does not exist or the operation failed
	// otherwise it returns nil.
	UpdateManifest(ctx context.Context, p Policy) error

	// RetrieveAll retrieves policies based on the given policy structure.
	// It returns an error with an empty policy page if the operation failed
	// otherwise it returns nil and the policy page.
	RetrieveAll(ctx context.Context, pm Page) (PolicyPage, error)

	// Delete deletes the policy for the given Policy User and Computation combination.
	// It returns an error if the policy does not exist or the operation failed
	// otherwise it returns nil.
	Delete(ctx context.Context, p Policy) error
}

// Service specifies a policy service API.
type Service interface {
	// Authorize is used to authorize a user to access a computation.
	// It returns an error if the user does not have access
	// otherwise it returns nil.
	Authorize(ctx context.Context, ar AccessRequest) error

	// AddPolicy is used to add a policy.
	// It returns an error if the policy already exists or the operation failed
	// otherwise it returns nil.
	AddPolicy(ctx context.Context, token string, p Policy) error

	// UpdatePolicy is used to update a policy.
	// It returns an error if the policy does not exist or the operation failed
	// otherwise it returns nil.
	UpdatePolicy(ctx context.Context, token string, p Policy) error

	// ListPolicies is used to list policies.
	// It returns an error with an empty policy page if the operation failed
	// otherwise it returns nil and the policy page.
	ListPolicies(ctx context.Context, token string, pm Page) (PolicyPage, error)

	// DeletePolicy is used to delte a policy.
	// It returns an error if the policy does not exist or the operation failed
	// otherwise it returns nil.
	DeletePolicy(ctx context.Context, token string, p Policy) error
}

func (p Policy) Validate() error {
	if p.User == "" {
		return apiutil.ErrMissingUser
	}
	if p.Computation == "" {
		return apiutil.ErrMissingComputation
	}

	for _, role := range p.CloudRole {
		if !contains(CloudRoles, role) {
			return apiutil.ErrCloudRole
		}
	}
	for _, role := range p.ManifestRole {
		if !contains(ManifestRoles, role) {
			return apiutil.ErrManifestRole
		}
	}
	return nil
}

func contains(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}
