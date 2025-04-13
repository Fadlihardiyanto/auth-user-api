package model

import "gorm.io/datatypes"

type GithubUser struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
	Name      string `json:"name"`
	Email     string `json:"email"` // bisa null dari GitHub
}

type GithubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type GithubLoginRequest struct {
	Code       string         `json:"code" validate:"required"`
	IpAddress  string         `json:"ip_address" validate:"required,max=100"`
	DeviceInfo datatypes.JSON `json:"device_info" validate:"required"`
}
