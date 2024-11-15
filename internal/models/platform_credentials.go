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
	UserID         string
	PlatformType   PlatformType
	AccessToken    string
	RefreshToken   string
	TokenExpiresAt time.Time
	IsActive       bool
}
