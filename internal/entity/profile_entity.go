package entity

import "time"

type Profile struct {
	ID             string    `gorm:"column:id;primaryKey"`
	UserID         string    `gorm:"user_id"`
	FullName       string    `gorm:"full_name"`
	DisplayName    string    `gorm:"display_name"`
	ProfilePicture string    `gorm:"profile_picture"`
	Phone          string    `gorm:"phone"`
	Language       string    `gorm:"language"`
	Currency       string    `gorm:"currency"`
	BirthYear      string    `gorm:"birth_year"`
	CreatedAt      time.Time `gorm:"created_at"`
	UpdatedAt      time.Time `gorm:"updated_at"`
	User           User      `gorm:"foreignKey:UserID;references:ID"`
}
