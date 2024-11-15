package service

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/graph/model"
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/internal/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/youtube/v3"
	"gorm.io/gorm"
)

type YouTubeService struct {
	db     *gorm.DB
	config *oauth2.Config
}

func NewYouTubeService(db *gorm.DB) *YouTubeService {
	clientID := os.Getenv("YOUTUBE_CLIENT_ID")
	clientSecret := os.Getenv("YOUTUBE_CLIENT_SECRET")
	redirectURI := os.Getenv("YOUTUBE_REDIRECT_URI")
	// Add debug logging
	log.Printf("YouTube Config - ClientID: %v, RedirectURI: %s",
		clientID, redirectURI)

	if clientID == "" || clientSecret == "" || redirectURI == "" {
		log.Fatal("Missing required YouTube OAuth credentials")
	}

	config := &oauth2.Config{
		ClientID:     os.Getenv("YOUTUBE_CLIENT_ID"),
		ClientSecret: os.Getenv("YOUTUBE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("YOUTUBE_REDIRECT_URI"),
		Scopes: []string{
			youtube.YoutubeUploadScope,
			youtube.YoutubeScope,
		},
		Endpoint: google.Endpoint,
	}

	return &YouTubeService{db: db, config: config}
}

func (s *YouTubeService) GetAuthURL() string {
	return s.config.AuthCodeURL("state", oauth2.AccessTypeOffline)
}

func (s *YouTubeService) ExchangeAndSaveToken(ctx context.Context, code string, userID string) (*model.PlatformCredentials, error) {
	// Exchange authorization code for tokens
	token, err := s.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	// Verify the token by making a test API call
	client := s.config.Client(ctx, token)
	youtubeService, err := youtube.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create YouTube service: %w", err)
	}

	_, err = youtubeService.Channels.List([]string{"snippet"}).Mine(true).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	// Deactivate any existing credentials
	if err := s.db.Model(&models.PlatformCredentials{}).
		Where("user_id = ? AND platform_type = ? AND is_active = ?", userID, models.YouTube, true).
		Update("is_active", false).Error; err != nil {
		return nil, fmt.Errorf("failed to deactivate existing credentials: %w", err)
	}

	// Save new credentials
	creds := &models.PlatformCredentials{
		UserID:         userID,
		PlatformType:   models.YouTube,
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
		TokenExpiresAt: token.Expiry,
		IsActive:       true,
	}

	if err := s.db.Create(creds).Error; err != nil {
		return nil, fmt.Errorf("failed to save new credentials: %w", err)
	}

	return &model.PlatformCredentials{
		ID:             creds.ID,
		UserID:         creds.UserID,
		PlatformType:   model.PlatformType(creds.PlatformType),
		AccessToken:    creds.AccessToken,
		RefreshToken:   creds.RefreshToken,
		TokenExpiresAt: creds.TokenExpiresAt,
		IsActive:       creds.IsActive,
	}, nil
}

func (s *YouTubeService) GetActiveCredentials(ctx context.Context, userID string) (*model.PlatformCredentials, error) {
	var creds models.PlatformCredentials

	err := s.db.Where("user_id = ? AND platform_type = ? AND is_active = ?",
		userID, models.YouTube, true).First(&creds).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// Return nil and no error when no credentials are found
			return nil, nil
		}
		return nil, fmt.Errorf("error fetching credentials: %w", err)
	}

	return &model.PlatformCredentials{
		ID:             creds.ID,
		UserID:         creds.UserID,
		PlatformType:   model.PlatformType(creds.PlatformType),
		AccessToken:    creds.AccessToken,
		RefreshToken:   creds.RefreshToken,
		TokenExpiresAt: creds.TokenExpiresAt,
		IsActive:       creds.IsActive,
	}, nil
}
