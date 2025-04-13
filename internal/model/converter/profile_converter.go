package converter

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"
)

func ProfileToResponse(profile *entity.Profile) *model.ProfileResponse {
	return &model.ProfileResponse{
		ID:             profile.ID,
		FullName:       profile.FullName,
		DisplayName:    profile.DisplayName,
		Phone:          profile.Phone,
		ProfilePicture: profile.ProfilePicture,
		Language:       profile.Language,
		Currency:       profile.Currency,
		BirthYear:      profile.BirthYear,
		CreatedAt:      profile.CreatedAt,
		UpdatedAt:      profile.UpdatedAt,
	}
}

func ProfileToEvent(profile *entity.Profile) *model.ProfileEvent {
	return &model.ProfileEvent{
		ID:             profile.ID,
		UserID:         profile.UserID,
		FullName:       profile.FullName,
		DisplayName:    profile.DisplayName,
		Phone:          profile.Phone,
		ProfilePicture: profile.ProfilePicture,
		Language:       profile.Language,
		Currency:       profile.Currency,
		BirthYear:      profile.BirthYear,
		CreatedAt:      profile.CreatedAt,
		UpdatedAt:      profile.UpdatedAt,
	}
}
