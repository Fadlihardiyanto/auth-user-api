package repository

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserLoginHistoryRepository struct {
	Repository[entity.UserLoginHistory]
	Log *logrus.Logger
}

func NewUserLoginHistoryRepository(log *logrus.Logger) *UserLoginHistoryRepository {
	return &UserLoginHistoryRepository{
		Log: log,
	}
}

func (r *UserLoginHistoryRepository) FindByUserId(db *gorm.DB, userLoginHistory *entity.UserLoginHistory, userId int) error {
	return db.Where("user_id = ?", userId).First(userLoginHistory).Error
}

func (r *UserLoginHistoryRepository) Search(db *gorm.DB, request *model.SearchUserLoginHistoryRequest) ([]entity.UserLoginHistory, int64, error) {
	var history []entity.UserLoginHistory
	if err := db.Scopes(r.FilterUser(request)).Find(&history).Error; err != nil {
		return nil, 0, err
	}

	var total int64 = 0

	if err := db.Model(&entity.UserLoginHistory{}).Scopes(r.FilterUser(request)).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	return history, total, nil

}

func (r *UserLoginHistoryRepository) FilterUser(request *model.SearchUserLoginHistoryRequest) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if request.UserId != "" {
			db = db.Where("user_id = ?", request.UserId)
		}
		if request.IpAddress != "" {
			db = db.Where("ip_address ILIKE ?", "%"+request.IpAddress+"%")
		}
		if request.Os != "" {
			logrus.Infof("os: %s", request.Os)
			db = db.Where("device_info ->>'os' ILIKE ?", "%"+request.Os+"%")
		}
		if request.Device != "" {
			db = db.Where("device_info ->>'device' ILIKE ?", "%"+request.Device+"%")
		}
		if request.Browser != "" {
			db = db.Where("device_info ->>'browser' ILIKE ?", "%"+request.Browser+"%")
		}
		if request.UserAgent != "" {
			db = db.Where("device_info ->>'user_agent' ILIKE ?", "%"+request.UserAgent+"%")
		}
		if request.LoginTimeStart != "" && request.LoginTimeEnd != "" {
			logrus.Infof("login time: %s", request.LoginTimeStart)
			db = db.Where("login_time BETWEEN ? AND ?", request.LoginTimeStart, request.LoginTimeEnd)
		}
		return db
	}
}
