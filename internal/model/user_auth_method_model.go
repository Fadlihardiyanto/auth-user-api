package model

type UserAuthMethodResponse struct {
	ID                   string `json:"id,omitempty"`
	UserID               string `json:"user_id,omitempty"`
	AuthMethod           string `json:"auth_method,omitempty"`
	AuthMethodIdentifier string `json:"auth_method_identifier,omitempty"`
	CreatedAt            string `json:"created_at,omitempty"`
	UpdatedAt            string `json:"updated_at,omitempty"`
}

type CreateUserAuthMethodRequest struct {
	UserID         string `json:"user_id" validate:"required,max=100"`
	AuthMethod     string `json:"auth_method" validate:"required,max=100"`
	AuthIdentifier string `json:"auth_identifier" validate:"required,max=100"`
}
