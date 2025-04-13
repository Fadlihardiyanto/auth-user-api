package model

import "gorm.io/datatypes"

type UserLoginHistoryResponse struct {
	ID         string         `json:"id,omitempty"`
	UserID     string         `json:"user_id,omitempty"`
	LoginTime  string         `json:"login_time,omitempty"`
	IpAddress  string         `json:"ip_address,omitempty"`
	DiviceInfo datatypes.JSON `json:"device_info,omitempty"`
	CreatedAt  string         `json:"created_at,omitempty"`
	UpdatedAt  string         `json:"updated_at,omitempty"`
}

type SearchUserLoginHistoryRequest struct {
	UserId         string `json:"user_id" validate:"max=100"`
	IpAddress      string `json:"ip_address" validate:"max=100"`
	Os             string `json:"os" validate:"max=100"`
	Device         string `json:"device" validate:"max=100"`
	Browser        string `json:"browser" validate:"max=100"`
	UserAgent      string `json:"user_agent" validate:"max=100"`
	LoginTimeStart string `json:"login_time_start" validate:"max=100"`
	LoginTimeEnd   string `json:"login_time_end" validate:"max=100"`
	Page           int    `json:"page" validate:"gte=1"`
	Size           int    `json:"size" validate:"gte=1"`
}
