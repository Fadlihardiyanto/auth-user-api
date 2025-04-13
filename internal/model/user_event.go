package model

import "time"

type UserEvent struct {
	ID        string    `json:"id,omitempty"`
	Token     string    `json:"token,omitempty"`
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

func (u *UserEvent) GetId() string {
	return u.ID
}
