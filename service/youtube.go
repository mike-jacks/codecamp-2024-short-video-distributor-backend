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

func (s *YouTubeService) UploadVideo(ctx context.Context, userID string, channelId string, title string, description string, file graphql.Upload, privacyStatus *string) (*model.Video, error) {
	if privacyStatus == nil {
		// Default to private if no privacy status is provided
		private := "private"
		privacyStatus = &private
	}
	youtubeService, err := s.getYoutubeClient(ctx, userID)
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
	youtubeService, err := s.getYoutubeClient(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get YouTube client: %w", err)
	}

	// Get the user's channels
	channelResponse, err := youtubeService.Channels.List([]string{"snippet"}).Mine(true).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get channels: %w", err)
	}

	// Convert the response to the model
	channels := make([]*model.YoutubeChannel, len(channelResponse.Items))
	for i, channel := range channelResponse.Items {
		channels[i] = &model.YoutubeChannel{
			ID:    channel.Id,
			Title: channel.Snippet.Title,
		}
	}

	return channels, nil
}

func (s *YouTubeService) getYoutubeClient(ctx context.Context, userID string) (*youtube.Service, error) {
	// Get active credentials for the user
	creds, err := s.GetActiveCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active credentials: %w", err)
	}
	if creds == nil {
		return nil, fmt.Errorf("no active credentials found")
	}

	// CreateOAuth2 token from stored credentials
	token := &oauth2.Token{
		AccessToken:  creds.AccessToken,
		RefreshToken: creds.RefreshToken,
		Expiry:       creds.TokenExpiresAt,
	}

	// Create YouTube client
	client := s.config.Client(ctx, token)
	youtubeService, err := youtube.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create YouTube service: %w", err)
	}
	return youtubeService, nil
}
