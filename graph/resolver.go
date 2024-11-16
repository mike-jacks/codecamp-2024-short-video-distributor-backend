package graph

import (
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/service"
	"gorm.io/gorm"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	db             *gorm.DB
	YoutubeService *service.YouTubeService
	TikTokService  *service.TikTokService
}

func NewResolver(db *gorm.DB) *Resolver {
	if db == nil {
		panic("db cannot be nil")
	}

	youtubeService := service.NewYouTubeService(db)
	if youtubeService == nil {
		panic("failed to create youtube service")
	}

	tiktokService := service.NewTikTokService(db)
	if tiktokService == nil {
		panic("failed to create tiktok service")
	}

	return &Resolver{
		db:             db,
		YoutubeService: youtubeService,
		TikTokService:  tiktokService,
	}
}
