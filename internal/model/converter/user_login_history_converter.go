package converter

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"
)

func UserLoginHistoryToResponse(userLoginHistory *entity.UserLoginHistory) *model.UserLoginHistoryResponse {
	return &model.UserLoginHistoryResponse{
		ID:         userLoginHistory.ID,
		UserID:     userLoginHistory.UserID,
		LoginTime:  userLoginHistory.LoginTime.Format("2006-01-02 15:04:05"),
		IpAddress:  userLoginHistory.IpAddress,
		DiviceInfo: userLoginHistory.DiviceInfo,
	}
}
