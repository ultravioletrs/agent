package auth

// Page contains page metadata that helps navigation.
type Page struct {
	Total        uint64 `json:"total,omitempty"`
	Offset       uint64 `json:"offset,omitempty"`
	Limit        uint64 `json:"limit,omitempty"`
	Owner        string `json:"owner,omitempty"`
	User         string `json:"user,omitempty"`
	Computation  string `json:"computation,omitempty"`
	CloudRole    string `json:"cloud_role,omitempty"`
	ManifestRole string `json:"manifest_role,omitempty"`
}
