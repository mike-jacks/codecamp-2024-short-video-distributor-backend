package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/graph/model"
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/internal/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/youtube/v3"
	"gorm.io/gorm"
)

type AuthSession struct {
	Token     string
	UserID    string
	CreatedAt time.Time
	Used      bool
}

type YouTubeService struct {
	db           *gorm.DB
	config       *oauth2.Config
	authSessions map[string]*AuthSession
	sessionMux   sync.RWMutex
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

	return &YouTubeService{
		db:           db,
		config:       config,
		authSessions: make(map[string]*AuthSession),
		sessionMux:   sync.RWMutex{},
	}
}

func (s *YouTubeService) GetAuthURL(userID string) (string, error) {
	// Generate a random session token
	sessionToken := make([]byte, 32)
	if _, err := rand.Read(sessionToken); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	token := hex.EncodeToString(sessionToken)

	// Store the session
	s.sessionMux.Lock()
	s.authSessions[token] = &AuthSession{
		Token:     token,
		UserID:    userID,
		CreatedAt: time.Now(),
		Used:      false,
	}
	s.sessionMux.Unlock()

	go s.cleanupOldSessions()

	return s.config.AuthCodeURL(token, oauth2.AccessTypeOffline, oauth2.ApprovalForce), nil
}

func (s *YouTubeService) cleanupOldSessions() {
	s.sessionMux.Lock()
	defer s.sessionMux.Unlock()

	for token, session := range s.authSessions {
		if time.Since(session.CreatedAt) > 15*time.Minute || session.Used {
			delete(s.authSessions, token)
		}
	}
}

func (s *YouTubeService) ValidateAndGetUserID(state string) (string, error) {
	s.sessionMux.Lock()
	defer s.sessionMux.Unlock()

	session, exists := s.authSessions[state]
	if !exists {
		return "", fmt.Errorf("invalid or expired session")
	}

	if session.Used {
		return "", fmt.Errorf("session already used")
	}

	if time.Since(session.CreatedAt) > 15*time.Minute {
		delete(s.authSessions, state)
		return "", fmt.Errorf("invalid or expired session")
	}

	// Mark the session as used
	session.Used = true
	userID := session.UserID

	// Clean up the used session
	delete(s.authSessions, state)

	return userID, nil
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

	// Verify the token by making a test API call
	channelResponse, err := youtubeService.Channels.List([]string{"snippet"}).Mine(true).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	if len(channelResponse.Items) == 0 {
		return nil, fmt.Errorf("no channels found for this account")
	}

	channel := channelResponse.Items[0]

	// Save new credentials
	creds := &models.PlatformCredentials{
		UserID:         userID,
		PlatformType:   models.YouTube,
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
		TokenExpiresAt: token.Expiry,
		IsActive:       true,
	}

	// Start transaction
	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", tx.Error)
	}

	if err := tx.Create(creds).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to save new credentials: %w", err)
	}

	// Save channel details
	channelDetails := &models.YouTubeChannelDetails{
		CredentialsID: creds.ID,
		ChannelID:     channel.Id,
		ChannelTitle:  channel.Snippet.Title,
	}

	if err := tx.Create(channelDetails).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to save channel details: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
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

func (s *YouTubeService) GetActiveCredentials(ctx context.Context, userID string) ([]*model.PlatformCredentials, error) {
	var creds []models.PlatformCredentials

	err := s.db.Where("user_id = ? AND platform_type = ? AND is_active = ?",
		userID, models.YouTube, true).Find(&creds).Error

	if err != nil {
		return nil, fmt.Errorf("error fetching credentials: %w", err)
	}

	result := make([]*model.PlatformCredentials, len(creds))
	for i, cred := range creds {
		result[i] = &model.PlatformCredentials{
			ID:             cred.ID,
			UserID:         cred.UserID,
			PlatformType:   model.PlatformType(cred.PlatformType),
			AccessToken:    cred.AccessToken,
			RefreshToken:   cred.RefreshToken,
			TokenExpiresAt: cred.TokenExpiresAt,
			IsActive:       cred.IsActive,
		}
	}

	return result, nil
}

func (s *YouTubeService) UploadVideo(ctx context.Context, userID string, channelId string, title string, description string, file graphql.Upload, privacyStatus *string) (*model.Video, error) {
	if privacyStatus == nil {
		// Default to private if no privacy status is provided
		private := "private"
		privacyStatus = &private
	}
	youtubeService, err := s.getYoutubeClient(ctx, userID, channelId)
	if err != nil {
		return nil, fmt.Errorf("failed to get YouTube client: %w", err)
	}

	// Create the video object
	video := &youtube.Video{
		Snippet: &youtube.VideoSnippet{
			Title:       title,
			Description: description,
			ChannelId:   channelId,
		},
		Status: &youtube.VideoStatus{
			PrivacyStatus:           *privacyStatus,
			SelfDeclaredMadeForKids: false,
		},
	}

	call := youtubeService.Videos.Insert([]string{"snippet", "status"}, video)
	call.Media(file.File)

	response, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to upload video: %w", err)
	}

	return &model.Video{
		ID:           response.Id,
		Title:        response.Snippet.Title,
		Description:  response.Snippet.Description,
		URL:          fmt.Sprintf("https://www.youtube.com/watch?v=%s", response.Id),
		Status:       response.Status.PrivacyStatus,
		ChannelID:    response.Snippet.ChannelId,
		ChannelTitle: response.Snippet.ChannelTitle,
	}, nil
}

func (s *YouTubeService) GetChannels(ctx context.Context, userID string) ([]*model.YoutubeChannel, error) {
	var channels []*models.YouTubeChannelDetails

	err := s.db.Joins("JOIN platform_credentials ON youtube_channel_details.credentials_id = platform_credentials.id").
		Where("platform_credentials.user_id = ? AND platform_credentials.is_active = ?",
			userID, true).
		Find(&channels).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get channels: %w", err)
	}

	result := make([]*model.YoutubeChannel, len(channels))
	for i, channel := range channels {
		result[i] = &model.YoutubeChannel{
			ID:    channel.ChannelID,
			Title: channel.ChannelTitle,
		}
	}

	return result, nil
}

func (s *YouTubeService) getYoutubeClient(ctx context.Context, userID string, channelId string) (*youtube.Service, error) {
	// Get active credentials for the user and channel
	var channelDetails models.YouTubeChannelDetails
	err := s.db.Preload("PlatformCredentials").
		Where("youtube_channel_details.channel_id = ? AND platform_credentials.user_id = ? AND platform_credentials.is_active = ?",
			channelId, userID, true).
		First(&channelDetails).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("no active credentials found for channel %s", channelId)
		}
		return nil, fmt.Errorf("failed to get active credentials: %w", err)
	}

	// CreateOAuth2 token from stored credentials
	token := &oauth2.Token{
		AccessToken:  channelDetails.PlatformCredentials.AccessToken,
		RefreshToken: channelDetails.PlatformCredentials.RefreshToken,
		Expiry:       channelDetails.PlatformCredentials.TokenExpiresAt,
	}

	// Create YouTube client
	client := s.config.Client(ctx, token)
	youtubeService, err := youtube.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create YouTube service: %w", err)
	}
	return youtubeService, nil
}
