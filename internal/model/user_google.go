package model

import "gorm.io/datatypes"

type GoogleUser struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
	Picture  string `json:"picture"`
}

type GoogleLoginRequest struct {
	Code       string         `json:"code" validate:"required"`
	IpAddress  string         `json:"ip_address" validate:"required,max=100"`
	DeviceInfo datatypes.JSON `json:"device_info" validate:"required"`
}
