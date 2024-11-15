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
	youtubeService *service.YouTubeService
}

func NewResolver(db *gorm.DB) *Resolver {
	return &Resolver{
		db:             db,
		youtubeService: service.NewYouTubeService(db),
	}
}
