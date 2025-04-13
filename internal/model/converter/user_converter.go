package converter

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"
	"time"
)

func UserToResponse(user *entity.User) *model.UserResponse {
	return &model.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

func UserToLoginResponse(user *entity.User, accessToken string, refreshTokenID string, accessExpiry time.Time) *model.UserResponse {
	return &model.UserResponse{
		AccessToken:    accessToken,
		AccessExpiry:   accessExpiry,
		RefreshTokenID: refreshTokenID,
		Role:           user.Role,
		CreatedAt:      user.CreatedAt,
		UpdatedAt:      user.UpdatedAt,
	}
}

func UserToEvent(user *entity.User) *model.UserEvent {
	return &model.UserEvent{
		ID:        user.ID,
		Email:     user.Email,
		Token:     user.Token, // Token diambil dari parameter, bukan dari entity
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}
