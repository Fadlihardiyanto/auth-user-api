package converter

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"
)

func UserAuthMethodToResponse(userAuthMethod *entity.UserAuthMethod) *model.UserAuthMethodResponse {
	return &model.UserAuthMethodResponse{
		ID:                   userAuthMethod.ID,
		UserID:               userAuthMethod.UserID,
		AuthMethod:           userAuthMethod.AuthMethod,
		AuthMethodIdentifier: userAuthMethod.AuthIdentifier,
		CreatedAt:            userAuthMethod.CreatedAt.Format("2006-01-02 15:04:05"),
		UpdatedAt:            userAuthMethod.UpdatedAt.Format("2006-01-02 15:04:05"),
	}
}
