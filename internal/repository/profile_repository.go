package repository

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type ProfileRepository struct {
	Repository[entity.Profile]
	Log *logrus.Logger
}

func NewProfileRepository(log *logrus.Logger) *ProfileRepository {
	return &ProfileRepository{
		Log: log,
	}
}

func (r *ProfileRepository) FindByIDAndUserID(db *gorm.DB, profile *entity.Profile, id string, userID string) error {
	return db.Where("id = ? AND user_id = ?", id, userID).First(profile).Error
}

func (r *ProfileRepository) FindByUserID(db *gorm.DB, profile *entity.Profile, userID string) error {
	return db.Where("user_id = ?", userID).First(profile).Error
}

func (r *ProfileRepository) CountByUserID(db *gorm.DB, userID string) (int64, error) {
	var count int64
	err := db.Model(&entity.Profile{}).Where("user_id = ?", userID).Count(&count).Error
	return count, err
}

func (r *ProfileRepository) Search(db *gorm.DB, request *model.SearchProfileRequest) ([]entity.Profile, int64, error) {
	var contacts []entity.Profile
	if err := db.Scopes(r.FilterProfile(request)).Offset((request.Page - 1) * request.Size).Limit(request.Size).Find(&contacts).Error; err != nil {
		return nil, 0, err
	}

	var total int64 = 0
	if err := db.Model(&entity.Profile{}).Scopes(r.FilterProfile(request)).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	return contacts, total, nil
}

func (r *ProfileRepository) FilterProfile(request *model.SearchProfileRequest) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if request.UserID != "" {
			db = db.Where("user_id = ?", request.UserID)
		}
		if request.FullName != "" {
			db = db.Where("full_name LIKE ?", "%"+request.FullName+"%")
		}
		if request.DisplayName != "" {
			db = db.Where("display_name LIKE ?", "%"+request.DisplayName+"%")
		}
		if request.Language != "" {
			db = db.Where("language = ?", request.Language)
		}
		if request.Currency != "" {
			db = db.Where("currency = ?", request.Currency)
		}
		if request.BirthYear != "" {
			db = db.Where("birth_year = ?", request.BirthYear)
		}
		return db
	}
}
