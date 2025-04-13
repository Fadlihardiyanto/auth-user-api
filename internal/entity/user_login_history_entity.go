package entity

import (
	"time"

	"gorm.io/datatypes"
)

type UserLoginHistory struct {
	ID         string         `gorm:"column:id;primaryKey"`
	UserID     string         `gorm:"column:user_id"`
	LoginTime  time.Time      `gorm:"column:login_time"`
	IpAddress  string         `gorm:"column:ip_address"`
	DiviceInfo datatypes.JSON `gorm:"column:device_info"`
	CreatedAt  time.Time      `gorm:"column:created_at"`
	UpdatedAt  time.Time      `gorm:"column:updated_at"`
	User       User           `gorm:"foreignKey:UserID;references:ID"`
}
