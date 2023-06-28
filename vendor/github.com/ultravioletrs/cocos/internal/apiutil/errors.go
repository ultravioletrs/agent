package apiutil

import "github.com/mainflux/mainflux/pkg/errors"

// Errors defined in this file are used by the LoggingErrorEncoder decorator
// to distinguish and log API request validation errors and avoid that service
// errors are logged twice.
var (
	// ErrBearerToken indicates missing or invalid bearer user token.
	ErrBearerToken = errors.New("missing or invalid bearer user token")

	// ErrMissingID indicates missing entity ID.
	ErrMissingID = errors.New("missing entity id")

	// ErrNameSize indicates that name size exceeds the max.
	ErrNameSize = errors.New("invalid name size")

	// ErrLimitSize indicates that an invalid limit.
	ErrLimitSize = errors.New("invalid limit size")

	// ErrOffsetSize indicates an invalid offset.
	ErrOffsetSize = errors.New("invalid offset size")

	// ErrInvalidOrder indicates an invalid list order.
	ErrInvalidOrder = errors.New("invalid list order provided")

	// ErrInvalidDirection indicates an invalid list direction.
	ErrInvalidDirection = errors.New("invalid list direction provided")

	// ErrEmptyList indicates that entity data is empty.
	ErrEmptyList = errors.New("empty list provided")

	// ErrMalformedPolicy indicates that policies are malformed.
	ErrMalformedPolicy = errors.New("falmormed policy")

	// ErrRunComputation indicates error in running the computation.
	ErrRunComputation = errors.New("failed to run computation")

	// ErrMissingUser indicates that the user is missing.
	ErrMissingUser = errors.New("missing user")

	// ErrMissingComputation indicates that the computation is missing.
	ErrMissingComputation = errors.New("missing computation")

	// ErrCloudRole indicates missing or invalid cloud role.
	ErrCloudRole = errors.New("missing or invalid cloud role")

	// ErrManifestRole indicates missing or invalid manifest role.
	ErrManifestRole = errors.New("missing or invalid manifest role")
)
