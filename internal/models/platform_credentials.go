package models

import (
	"time"

	"gorm.io/gorm"
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

	YouTubeChannelDetails []YouTubeChannelDetails `gorm:"foreignKey:CredentialsID"`
}

func (pc *PlatformCredentials) AfterFind(tx *gorm.DB) (err error) {
	if pc.PlatformType == YouTube {
		// Check if the association is loaded by looking at the length
		var count int64
		tx.Model(&YouTubeChannelDetails{}).Where("credentials_id = ?", pc.ID).Count(&count)

		if count > 0 && len(pc.YouTubeChannelDetails) == 0 {
			return tx.Model(pc).Association("YouTubeChannelDetails").Find(&pc.YouTubeChannelDetails)
		}
	}
	return nil
}
