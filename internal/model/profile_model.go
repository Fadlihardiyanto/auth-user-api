package model

import (
	"time"

	"github.com/go-playground/validator/v10"
)

type ProfileResponse struct {
	ID             string    `json:"id"`
	FullName       string    `json:"full_name"`
	DisplayName    string    `json:"display_name"`
	ProfilePicture string    `json:"profile_picture"`
	Phone          string    `json:"phone"`
	Language       string    `json:"language"`
	Currency       string    `json:"currency"`
	BirthYear      string    `json:"birth_year"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type SearchProfileRequest struct {
	UserID      string `json:"-" validate:"required"`
	FullName    string `json:"full_name" validate:"max=100"`
	DisplayName string `json:"display_name" validate:"max=100"`
	Phone       string `json:"phone" validate:"max=20"`
	Language    string `json:"language" validate:"max=10"`
	Currency    string `json:"currency" validate:"max=10"`
	BirthYear   string `json:"birth_year"`
	Page        int    `json:"page" validate:"min=1"`
	Size        int    `json:"size" validate:"min=1,max=100"`
}

type CreateProfileRequest struct {
	UserID      string `json:"-" validate:"required"`
	FullName    string `json:"full_name" validate:"required,max=100"`
	DisplayName string `json:"display_name" validate:"required,max=100"`
	Phone       string `json:"phone" validate:"max=20"`
	Language    string `json:"language" validate:"max=10"`
	Currency    string `json:"currency" validate:"max=10"`
	BirthYear   string `json:"birth_year" validate:"date_format"`
}

func DateFormat(fl validator.FieldLevel) bool {
	_, err := time.Parse("2006-01-02", fl.Field().String())
	return err == nil
}

type UpdateProfileRequest struct {
	UserID      string `json:"-" validate:"required"`
	ID          string `json:"-" validate:"required"`
	FullName    string `json:"full_name" validate:"max=100"`
	DisplayName string `json:"display_name" validate:"max=100"`
	Phone       string `json:"phone" validate:"max=20"`
	Language    string `json:"language" validate:"max=10"`
	Currency    string `json:"currency" validate:"max=10"`
	BirthYear   string `json:"birth_year" validate:"date_format"`
}

type GetProfileRequest struct {
	UserID string `json:"user_id" validate:"required"`
	ID     string `json:"id" validate:"required"`
}

type DeleteProfileRequest struct {
	UserID string `json:"user_id" validate:"required"`
	ID     string `json:"id" validate:"required"`
}
