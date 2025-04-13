package model

import "time"

type ProfileEvent struct {
	ID             string    `json:"id,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	FullName       string    `json:"full_name,omitempty"`
	DisplayName    string    `json:"display_name,omitempty"`
	ProfilePicture string    `json:"profile_picture,omitempty"`
	Phone          string    `json:"phone,omitempty"`
	Language       string    `json:"language,omitempty"`
	Currency       string    `json:"currency,omitempty"`
	BirthYear      string    `json:"birth_year,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

func (p *ProfileEvent) GetId() string {
	return p.ID
}
