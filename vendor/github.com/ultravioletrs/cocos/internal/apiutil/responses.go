package apiutil

// ErrorRes represents the HTTP error response body.
type ErrorRes struct {
	Err string `json:"error"`
}
