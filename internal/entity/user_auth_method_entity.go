package entity

import "time"

type UserAuthMethod struct {
	ID             string    `gorm:"column:id;primaryKey"`
	UserID         string    `gorm:"column:user_id"`
	AuthMethod     string    `gorm:"column:auth_method"`
	AuthIdentifier string    `gorm:"column:auth_identifier"`
	CreatedAt      time.Time `gorm:"column:created_at"`
	UpdatedAt      time.Time `gorm:"column:updated_at"`
	User           User      `gorm:"foreignKey:UserID;references:ID"`
}
