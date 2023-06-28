package grpc

type addPolicyRes struct {
	added bool
}

type updatePolicyRes struct {
	updated bool
}

type deletePolicyRes struct {
	deleted bool
}

type authorizeRes struct {
	authorized bool
}
