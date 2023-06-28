package grpc

import "github.com/ultravioletrs/cocos/internal/apiutil"

type addPolicyReq struct {
	token        string
	user         string
	computation  string
	cloudRole    []string
	manifestRole []string
	publicKey    string
}

func (req addPolicyReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.user == "" {
		return apiutil.ErrMissingUser
	}
	if req.computation == "" {
		return apiutil.ErrMissingComputation
	}
	if len(req.cloudRole) == 0 {
		return apiutil.ErrCloudRole
	}

	return nil
}

type updatePolicyReq struct {
	token        string
	user         string
	computation  string
	cloudRole    []string
	manifestRole []string
}

func (req updatePolicyReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.user == "" {
		return apiutil.ErrMissingUser
	}
	if req.computation == "" {
		return apiutil.ErrMissingComputation
	}
	if len(req.cloudRole) == 0 || len(req.manifestRole) == 0 {
		return apiutil.ErrEmptyList
	}

	return nil
}

type deletePolicyReq struct {
	token       string
	user        string
	computation string
}

func (req deletePolicyReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.user == "" {
		return apiutil.ErrMissingUser
	}
	if req.computation == "" {
		return apiutil.ErrMissingComputation
	}

	return nil
}

type authReq struct {
	user        string
	computation string
	role        string
	domain      string
}

func (req authReq) validate() error {
	if req.user == "" {
		return apiutil.ErrMissingUser
	}
	if req.computation == "" {
		return apiutil.ErrMissingComputation
	}
	if req.role == "" {
		return apiutil.ErrCloudRole
	}

	return nil
}
