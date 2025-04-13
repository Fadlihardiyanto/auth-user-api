package model

import (
	"time"

	"gorm.io/datatypes"
)

type UserResponse struct {
	ID             string    `json:"id,omitempty"`
	Email          string    `json:"email,omitempty"`
	AccessToken    string    `json:"access_token,omitempty"`
	AccessExpiry   time.Time `json:"access_expiry,omitzero"`
	RefreshTokenID string    `json:"refresh_token_id,omitempty"`
	Role           string    `json:"role,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitzero"`
	UpdatedAt      time.Time `json:"updated_at,omitzero"`
}

type VerifyUserRequest struct {
	ID    string `json:"id" validate:"required,max=100"`
	Token string `json:"token" validate:"required"`
}

type VerifyUserResponse struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type RegisterUserRequest struct {
	ID                   string `json:"id" validate:"required,max=100"`
	Password             string `json:"password" validate:"required,gt=6,containsany=ABCDEFGHIJKLMNOPQRSTUVWXYZ,containsany=abcdefghijklmnopqrstuvwxyz,containsany=0123456789"`
	PasswordConfirmation string `json:"password_confirmation" validate:"required,eqfield=Password"`
	Email                string `json:"email" validate:"required,email"`
}

type RegisterOauthUserRequest struct {
	ID    string `json:"id" validate:"required,max=100"`
	Email string `json:"email" validate:"required,email"`
}

type RegisterUserResponse struct {
	ID      string `json:"id,omitempty"`
	Email   string `json:"email,omitempty"`
	Role    string `json:"role,omitempty"`
	Message string `json:"message,omitempty"`
}

type UpdateUserRequest struct {
	ID    string  `json:"-" validate:"required,max=100"`
	Email string  `json:"email,omitempty" validate:"email"`
	Phone *string `json:"phone,omitempty" validate:"max=20"`
}

type LoginUserRequest struct {
	Email      string         `json:"email" validate:"required,email"`
	Password   string         `json:"password" validate:"required,max=100"`
	IpAddress  string         `json:"ip_address" validate:"required,max=100"`
	DeviceInfo datatypes.JSON `json:"device_info" validate:"required"`
}

type LoginOauthUserRequest struct {
	Email          string         `json:"email" validate:"required,email"`
	AuthMethod     string         `json:"auth_method" validate:"required,max=100"`
	AuthIdentifier string         `json:"auth_identifier" validate:"required,max=100"`
	IpAddress      string         `json:"ip_address" validate:"required,max=100"`
	DeviceInfo     datatypes.JSON `json:"device_info" validate:"required"`
}

type LogoutUserRequest struct {
	ID string `json:"id" validate:"required,max=100"`
}

type LogoutAllUserRequest struct {
	UserID string `json:"user_id" validate:"required,max=100"`
}

type GetUserRequest struct {
	ID string `json:"id" validate:"required,max=100"`
}

type SearchUserRequest struct {
	UserId   string `json:"user_id" validate:"max=100"`
	Email    string `json:"email" validate:"max=200"`
	Verified string `json:"verified" validate:"max=100"`
	Role     string `json:"role" validate:"max=100"`
	Page     int    `json:"page" validate:"min=1"`
	Size     int    `json:"size" validate:"min=1,max=100"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	ID                   string `json:"id" validate:"required,max=100"`
	Password             string `json:"password" validate:"required,gt=6,containsany=ABCDEFGHIJKLMNOPQRSTUVWXYZ,containsany=abcdefghijklmnopqrstuvwxyz,containsany=0123456789"`
	PasswordConfirmation string `json:"password_confirmation" validate:"required,eqfield=Password"`
	Token                string `json:"token" validate:"required"`
}

type ChangeRoleRequest struct {
	ID   string `json:"id" validate:"required,max=100"`
	Role string `json:"role" validate:"required,max=100,oneof=customer admin"`
}

type DeleteUserRequest struct {
	ID string `json:"id" validate:"required,max=100"`
}
