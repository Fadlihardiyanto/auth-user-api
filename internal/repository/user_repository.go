package repository

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserRepository struct {
	Repository[entity.User]
	Log *logrus.Logger
}

func NewUserRepository(log *logrus.Logger) *UserRepository {
	return &UserRepository{
		Log: log,
	}
}

func (r *UserRepository) FindByToken(db *gorm.DB, user *entity.User, token string) error {
	return db.Where("token = ? AND is_deleted = ?", token, false).Take(user).Error
}

func (r *UserRepository) FindByEmail(db *gorm.DB, user *entity.User, email string) error {
	return db.Where("email = ? AND is_deleted = ?", email, false).First(user).Error
}

func (r *UserRepository) FindByEmailVerified(db *gorm.DB, user *entity.User, email string) error {
	return db.Where("email = ? AND email_verified_at IS NOT NULL AND is_deleted = ?", email, false).First(user).Error
}

func (r *UserRepository) FindByEmailOrUsername(db *gorm.DB, user *entity.User, email string, username string) error {
	return db.Where("email = ? OR username = ? AND email_verified_at IS NOT NULL AND is_deleted = ?", email, username, false).First(user).Error
}

func (r *UserRepository) CountByEmail(db *gorm.DB, email string) (int64, error) {
	var count int64
	err := db.Model(&entity.User{}).Where("email = ? AND is_deleted = ?", email, false).Count(&count).Error
	return count, err
}

func (r *UserRepository) FindEmailVerifiedAt(db *gorm.DB, id string) (int64, error) {
	var count int64
	err := db.Model(&entity.User{}).Where("id = ? AND email_verified_at IS NOT NULL AND is_deleted = ?", id, false).Count(&count).Error
	return count, err
}

func (r *UserRepository) UpdateEmailVerifiedAt(db *gorm.DB, user *entity.User, id string, token string) error {
	return db.Model(user).Where("id = ? AND email_token = ? AND email_verified_at IS NULL AND is_deleted = ?", id, token, false).Update("email_verified_at", gorm.Expr("NOW()")).Error
}

func (r *UserRepository) Search(db *gorm.DB, request *model.SearchUserRequest) ([]entity.User, int64, error) {
	var users []entity.User
	if err := db.Scopes(r.FilterUser(request)).Find(&users).Error; err != nil {
		return nil, 0, err
	}

	var total int64 = 0

	if err := db.Model(&entity.User{}).Scopes(r.FilterUser(request)).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil

}

func (r *UserRepository) FilterUser(request *model.SearchUserRequest) func(tx *gorm.DB) *gorm.DB {
	return func(tx *gorm.DB) *gorm.DB {
		if request.UserId != "" {
			tx = tx.Where("id = ? AND is_deleted = ?", request.UserId, false)
		}
		if request.Email != "" {
			tx = tx.Where("email LIKE ? AND is_deleted = ?", "%"+request.Email+"%", false)
		}
		if request.Role != "" {
			tx = tx.Where("role = ? AND is_deleted = ?", request.Role, false)
		}
		if request.Verified == "true" {
			tx = tx.Where("email_verified_at IS NOT NULL AND is_deleted = ?", false)
		}
		if request.Verified == "false" {
			tx = tx.Where("email_verified_at IS NULL AND is_deleted = ?", false)
		}
		return tx
	}
}

func (r *UserRepository) UpdatePasswordResetToken(db *gorm.DB, user *entity.User, id string, token string) error {
	return db.Model(user).Where("id = ? AND is_deleted = ?", id, false).Update("password_reset_token", token).Error
}

func (r *UserRepository) ResetPassword(db *gorm.DB, user *entity.User, id string, token string, password string) error {
	return db.Model(user).Where("id = ? AND password_reset_token = ? AND is_deleted = ?", id, token, false).Update("password", password).Error
}
