// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"

	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/cocos/auth"
)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")
)

type Metadata map[string]interface{}

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// Ping compares a given string with secret
	Ping(string) (string, error)
	Run(ctx context.Context, cmp Computation) (string, error)
	Algo(ctx context.Context, algorithm []byte) (string, error)
	Data(ctx context.Context, dataset string) (string, error)
	Result(ctx context.Context) ([]byte, error)
}

type agentService struct {
	secret string
	auth   auth.AuthServiceClient
}

const (
	dRole          = "dataset_provider"
	aRole          = "algorithm_provider"
	rRole          = "result_consumer"
	manifestDomain = "manifest"
)

var _ Service = (*agentService)(nil)

// New instantiates the agent service implementation.
func New(secret string, auth auth.AuthServiceClient) Service {
	return &agentService{
		secret: secret,
		auth:   auth,
	}
}

func (ks *agentService) Ping(secret string) (string, error) {
	if ks.secret != secret {
		return "", ErrUnauthorizedAccess
	}
	return "Hello World :)", nil
}

func (ks *agentService) Run(ctx context.Context, cmp Computation) (string, error) {
	cmpJSON, err := json.Marshal(cmp)
	if err != nil {
		return "", err
	}

	return string(cmpJSON), nil // return the JSON string as the function's string return value
}

func (as *agentService) Algo(ctx context.Context, algorithm []byte) (string, error) {
	// Since we don't have a userID and computationID, we pass empty strings
	// for those parameters. We also ignore the error returned by the authorize
	// method since it will fail anyway.
	_ = as.authorize(ctx, "", "", aRole)

	// Implement the logic for the Algo method based on your requirements
	// Use the provided ctx and algorithm parameters as needed

	// Perform some processing on the algorithm byte array
	// For example, generate a unique ID for the algorithm
	algorithmID := "algo123"

	// Return the algorithm ID or an error
	return algorithmID, nil
}

func (as *agentService) Data(ctx context.Context, dataset string) (string, error) {
	// Since we don't have a userID and computationID, we pass empty strings
	// for those parameters. We also ignore the error returned by the authorize
	// method since it will fail anyway.
	_ = as.authorize(ctx, "", "", dRole)

	// Implement the logic for the Data method based on your requirements
	// Use the provided ctx and dataset parameters as needed

	// Perform some processing on the dataset string
	// For example, generate a unique ID for the dataset
	datasetID := "dataset456"

	// Return the dataset ID or an error
	return datasetID, nil
}

func (as *agentService) Result(ctx context.Context) ([]byte, error) {
	// Since we don't have a userID and computationID, we pass empty strings
	// for those parameters. We also ignore the error returned by the authorize
	// method since it will fail anyway.
	_ = as.authorize(ctx, "", "", rRole)

	// Implement the logic for the Result method based on your requirements
	// Use the provided ctx parameter as needed

	// Perform some processing to retrieve the computation result file
	// For example, read the file from storage or generate a dummy result

	result := []byte("This is the computation result file.")

	// Return the result file or an error
	return result, nil
}

func (as *agentService) authorize(ctx context.Context, user, computation, role string) error {
	req := &auth.AuthorizeReq{
		User:        user,
		Computation: computation,
		Role:        role,
		Domain:      manifestDomain,
	}
	res, err := as.auth.Authorize(ctx, req)
	if err != nil {
		return errors.Wrap(errors.ErrAuthorization, err)
	}
	if !res.GetAuthorized() {
		return errors.ErrAuthorization
	}
	return nil
}
