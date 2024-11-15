package models

import (
	"time"

	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/utils"
	"gorm.io/gorm"
)

type BaseModel struct {
	ID        string `gorm:"primaryKey;type:varchar(32)"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (base *BaseModel) BeforeCreate(tx *gorm.DB) (err error) {
	if base.ID == "" {
		base.ID = utils.GenerateId()
	}
	return
}
