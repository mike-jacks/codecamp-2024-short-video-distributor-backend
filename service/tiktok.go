package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/graph/model"
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/internal/models"
	"gorm.io/gorm"
)

type TikTokUserInfo struct {
	Nickname string `json:"display_name"`
	Avatar   string `json:"avatar_url"`
	OpenID   string `json:"open_id"`
}

type TikTokService struct {
	db           *gorm.DB
	clientID     string
	clientSecret string
	redirectURI  string
	authURI      string
	authSessions map[string]*AuthSession
	sessionMux   sync.RWMutex
	codeVerifier string
}

func NewTikTokService(db *gorm.DB) *TikTokService {
	clientID := os.Getenv("TIKTOK_CLIENT_ID")
	clientSecret := os.Getenv("TIKTOK_CLIENT_SECRET")
	redirectURI := os.Getenv("TIKTOK_REDIRECT_URI")

	if clientID == "" || clientSecret == "" || redirectURI == "" {
		log.Fatal("TIKTOK_CLIENT_ID, TIKTOK_CLIENT_SECRET, and TIKTOK_REDIRECT_URI must be set")
	}

	return &TikTokService{
		db:           db,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		authURI:      "https://www.tiktok.com/v2/auth/authorize/",
		authSessions: make(map[string]*AuthSession),
		sessionMux:   sync.RWMutex{},
	}
}

func (s *TikTokService) getUserInfo(accessToken string, openID string) (*TikTokUserInfo, error) {
	userInfoURL := "https://open.tiktokapis.com/v2/user/info/"

	// Create request
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the correct Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Add query parameters including openID
	q := req.URL.Query()
	q.Add("open_id", openID) // Add openID as query parameter
	q.Add("fields", "open_id,display_name,avatar_url")
	req.URL.RawQuery = q.Encode()

	// Add debug logging
	log.Printf("User info request headers: %v", req.Header)
	log.Printf("User info URL: %s", req.URL.String())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	// Debug response
	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("User info response: %s", string(respBody))
	resp.Body = io.NopCloser(bytes.NewBuffer(respBody))

	var response struct {
		Data  TikTokUserInfo `json:"data"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}

	// Check for API errors
	if response.Error.Code != "" {
		return nil, fmt.Errorf("TikTok API error: %s - %s", response.Error.Code, response.Error.Message)
	}

	return &response.Data, nil
}

func (s *TikTokService) GetAuthURL(userID string) (string, error) {
	// Generate PKCE values
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", fmt.Errorf("failed to generate PKCE values: %w", err)
	}

	// Store the verifier in the session
	s.codeVerifier = verifier

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

	params := url.Values{}
	params.Set("client_key", s.clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", s.redirectURI)
	params.Set("scope", "user.info.basic,video.publish,video.upload")
	params.Set("state", token)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	authURL := s.authURI + "?" + params.Encode()

	return authURL, nil
}

func (s *TikTokService) ExchangeAndSaveToken(ctx context.Context, code string, userID string) (*model.PlatformCredentials, error) {
	// Exchange code for access token
	tokenURL := "https://open.tiktokapis.com/v2/oauth/token/"

	data := url.Values{}
	data.Add("client_key", s.clientID)
	data.Add("client_secret", s.clientSecret)
	data.Add("code", code)
	data.Add("grant_type", "authorization_code")
	data.Add("redirect_uri", s.redirectURI)
	data.Add("code_verifier", s.codeVerifier)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(s.clientID+":"+s.clientSecret))))

	// Add debug logging
	log.Printf("Token exchange request headers: %v", req.Header)
	log.Printf("Token exchange request body: %s", data.Encode())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	// Add debug logging for response
	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("Token exchange response: %s", string(respBody))
	resp.Body = io.NopCloser(bytes.NewBuffer(respBody))

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		OpenID       string `json:"open_id"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		Error        struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Get user info
	userInfo, err := s.getUserInfo(tokenResponse.AccessToken, tokenResponse.OpenID)
	if err != nil {
		return nil, err
	}

	// Save credentials
	creds := &models.PlatformCredentials{
		UserID:         userID,
		PlatformType:   models.TikTok,
		AccessToken:    tokenResponse.AccessToken,
		RefreshToken:   tokenResponse.RefreshToken,
		TokenExpiresAt: time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
		IsActive:       true,
		AccountID:      tokenResponse.OpenID,
		AccountTitle:   userInfo.Nickname, // Using the display name from user info
	}

	if err := s.db.Create(creds).Error; err != nil {
		return nil, fmt.Errorf("failed to save credentials: %w", err)
	}

	return &model.PlatformCredentials{
		ID:             creds.ID,
		UserID:         creds.UserID,
		PlatformType:   model.PlatformType(creds.PlatformType),
		AccessToken:    creds.AccessToken,
		RefreshToken:   creds.RefreshToken,
		TokenExpiresAt: creds.TokenExpiresAt,
		IsActive:       creds.IsActive,
		AccountID:      creds.AccountID,
		AccountTitle:   creds.AccountTitle,
	}, nil
}

func (s *TikTokService) UploadVideo(ctx context.Context, userID string, accountID string, title string, description string, file graphql.Upload, privacyStatus *string, accessToken string, refreshToken string, tokenExpiresAt time.Time) (*model.VideoDistribution, error) {
	// First, upload the video file
	uploadURL := "https://open.tiktokapis.com/v2/video/upload/"

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add video file
	part, err := writer.CreateFormFile("video", file.Filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	_, err = io.Copy(part, file.File)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file: %w", err)
	}

	// Add other fields
	writer.WriteField("access_token", accessToken)
	writer.WriteField("open_id", accountID)
	writer.WriteField("title", title)
	writer.WriteField("description", description)

	writer.Close()

	// Make request
	req, err := http.NewRequest("POST", uploadURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to upload video: %w", err)
	}
	defer resp.Body.Close()

	var uploadResponse struct {
		Data struct {
			VideoID string `json:"video_id"`
			Share   struct {
				ShareID  string `json:"share_id"`
				ShareURL string `json:"share_url"`
			} `json:"share"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&uploadResponse); err != nil {
		return nil, fmt.Errorf("failed to decode upload response: %w", err)
	}

	return &model.VideoDistribution{
		ID:           uploadResponse.Data.VideoID,
		Title:        title,
		Description:  description,
		URL:          uploadResponse.Data.Share.ShareURL,
		Status:       "completed",
		AccountID:    accountID,
		AccountTitle: "", // TikTok doesn't return this in upload response
	}, nil
}

func (s *TikTokService) ValidateAndGetUserID(token string) (string, error) {
	s.sessionMux.Lock()
	defer s.sessionMux.Unlock()

	session, exists := s.authSessions[token]
	if !exists {
		return "", fmt.Errorf("session not found")
	}

	// Check if session is expired (30 minutes)
	if time.Since(session.CreatedAt) > 30*time.Minute {
		delete(s.authSessions, token)
		return "", fmt.Errorf("session expired")
	}

	// Check if session was already used
	if session.Used {
		delete(s.authSessions, token)
		return "", fmt.Errorf("session already used")
	}

	// Mark session as used
	session.Used = true

	// Clean up old sessions periodically
	go s.cleanupOldSessions()

	return session.UserID, nil
}

// cleanupOldSessions removes expired sessions
func (s *TikTokService) cleanupOldSessions() {
	s.sessionMux.Lock()
	defer s.sessionMux.Unlock()

	now := time.Now()
	for token, session := range s.authSessions {
		if now.Sub(session.CreatedAt) > 30*time.Minute || session.Used {
			delete(s.authSessions, token)
		}
	}
}

func generatePKCE() (verifier, challenge string, err error) {
	// Generate random bytes for verifier
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}

	// Create code verifier
	verifier = hex.EncodeToString(bytes)

	// Create code challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.URLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}
