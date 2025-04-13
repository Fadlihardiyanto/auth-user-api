package repository

import (
	"auth-user-api/internal/entity"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserAuthMethodRepository struct {
	Repository[entity.UserAuthMethod]
	Log *logrus.Logger
}

func NewUserAuthMethodRepository(log *logrus.Logger) *UserAuthMethodRepository {
	return &UserAuthMethodRepository{
		Log: log,
	}
}

func (r *UserAuthMethodRepository) FindByUserIDAndMethodAndIdentifier(db *gorm.DB, userAuthMethod *entity.UserAuthMethod, userID string, authMethod string, authIdentifier string) error {
	return db.Where("user_id = ? AND auth_method = ? AND auth_identifier = ?", userID, authMethod, authIdentifier).First(userAuthMethod).Error
}

func (r *UserAuthMethodRepository) CountByUserIDAndMethodAndIdentifier(db *gorm.DB, userID string, authMethod string, authIdentifier string) (int64, error) {
	var count int64
	err := db.Model(&entity.UserAuthMethod{}).Where("user_id = ? AND auth_method = ? AND auth_identifier = ?", userID, authMethod, authIdentifier).Count(&count).Error
	if err != nil {
		return 0, err
	}
	return count, nil
}
