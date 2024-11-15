package models

import (
	"time"
)

type PlatformType string

const (
	YouTube   PlatformType = "YOUTUBE"
	TikTok    PlatformType = "TIKTOK"
	Instagram PlatformType = "INSTAGRAM"
)

type PlatformCredentials struct {
	BaseModel
	UserID         string       `gorm:"not null"`
	PlatformType   PlatformType `gorm:"type:varchar(20);not null"`
	AccessToken    string       `gorm:"not null"`
	RefreshToken   string       `gorm:"not null"`
	TokenExpiresAt time.Time    `gorm:"not null"`
	IsActive       bool         `gorm:"not null"`
}
