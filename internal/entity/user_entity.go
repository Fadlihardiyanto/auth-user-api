package entity

import "time"

type User struct {
	ID                 string     `gorm:"column:id;primaryKey"`
	Email              string     `gorm:"column:email"`
	EmailToken         string     `gorm:"column:email_token"`
	EmailVerifiedAt    *time.Time `gorm:"column:email_verified_at"`
	Password           string     `gorm:"column:password"`
	PasswordResetToken *string    `gorm:"column:password_reset_token"`
	Role               string     `gorm:"column:role;default:customer"`
	IsDeleted          bool       `gorm:"column:is_deleted;default:false"`
	CreatedAt          time.Time  `gorm:"column:created_at"`
	UpdatedAt          time.Time  `gorm:"column:updated_at"`
	Token              string     `gorm:"-"` // Token diambil dari parameter, bukan dari entity
}
