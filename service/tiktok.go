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
	Data struct {
		User struct {
			DisplayName string `json:"display_name"`
			AvatarURL   string `json:"avatar_url"`
		} `json:"user"`
	} `json:"data"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		LogID   string `json:"log_id"`
	} `json:"error"`
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
	q.Add("fields", "display_name,avatar_url")
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

	var response TikTokUserInfo

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}
	fmt.Println("\n\nresponse: ", response)

	// Check for API errors
	if response.Error.Code != "ok" {
		return nil, fmt.Errorf("TikTok API error: %s - %s", response.Error.Code, response.Error.Message)
	}

	return &response, nil
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
		log.Printf("Failed to decode token response: %v", err)
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	log.Printf("Decoded token response: %+v", tokenResponse)

	// Get user info
	userInfo, err := s.getUserInfo(tokenResponse.AccessToken, tokenResponse.OpenID)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		return nil, err
	}

	log.Printf("User info received: %+v", userInfo)

	// Create credentials
	creds := &models.PlatformCredentials{
		UserID:         userID,
		PlatformType:   models.TikTok,
		AccessToken:    tokenResponse.AccessToken,
		RefreshToken:   tokenResponse.RefreshToken,
		TokenExpiresAt: time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
		IsActive:       true,
		AccountID:      tokenResponse.OpenID,
		AccountTitle:   userInfo.Data.User.DisplayName,
	}

	if err := s.db.Create(creds).Error; err != nil {
		log.Printf("Failed to save credentials: %v", err)
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
	// Step 1: Initialize upload
	initURL := "https://open.tiktokapis.com/v2/post/publish/video/init/"

	// Get file size for the initialization request
	fileBytes, err := io.ReadAll(file.File)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	fileSize := len(fileBytes)

	// Reset file reader for later use
	file.File = bytes.NewReader(fileBytes)

	// Create initialization payload
	type PostInfo struct {
		Title               string `json:"title"`
		PrivacyLevel        string `json:"privacy_level"`
		DisableDuet         bool   `json:"disable_duet"`
		DisableComment      bool   `json:"disable_comment"`
		DisableStitch       bool   `json:"disable_stitch"`
		VideoCoverTimestamp int64  `json:"video_cover_timestamp_ms"`
	}

	type SourceInfo struct {
		Source          string `json:"source"`
		VideoSize       int    `json:"video_size"`
		ChunkSize       int    `json:"chunk_size"`
		TotalChunkCount int    `json:"total_chunk_count"`
	}

	type InitPayload struct {
		PostInfo   PostInfo   `json:"post_info"`
		SourceInfo SourceInfo `json:"source_info"`
	}

	// Create the payload
	payload := InitPayload{
		PostInfo: PostInfo{
			Title:               title,
			PrivacyLevel:        "SELF_ONLY",
			DisableDuet:         false,
			DisableComment:      false,
			DisableStitch:       false,
			VideoCoverTimestamp: 1000,
		},
		SourceInfo: SourceInfo{
			Source:          "FILE_UPLOAD",
			VideoSize:       fileSize,
			ChunkSize:       fileSize,
			TotalChunkCount: 1,
		},
	}

	// Add privacy level handling if provided
	if privacyStatus != nil {
		switch *privacyStatus {
		case "PUBLIC":
			payload.PostInfo.PrivacyLevel = "PUBLIC_TO_EVERYONE"
		case "PRIVATE":
			payload.PostInfo.PrivacyLevel = "SELF_ONLY"
		case "FOLLOWERS":
			payload.PostInfo.PrivacyLevel = "MUTUAL_FOLLOW_FRIENDS"
		}
	}

	// Debug logging before marshaling
	log.Printf("Init Payload Structure:")
	log.Printf("Post Info:")
	log.Printf("- Title: %s", payload.PostInfo.Title)
	log.Printf("- Privacy Level: %s", payload.PostInfo.PrivacyLevel)
	log.Printf("Source Info:")
	log.Printf("- Video Size: %d", payload.SourceInfo.VideoSize)
	log.Printf("- Chunk Size: %d", payload.SourceInfo.ChunkSize)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal payload: %v", err)
		return nil, fmt.Errorf("failed to marshal init payload: %w", err)
	}

	// Debug the actual JSON being sent
	log.Printf("Init payload JSON: %s", string(payloadBytes))

	// Create initialization request
	initReq, err := http.NewRequest("POST", initURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create init request: %w", err)
	}

	initReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	initReq.Header.Set("Content-Type", "application/json; charset=UTF-8")

	// Add query parameters
	q := initReq.URL.Query()
	q.Add("open_id", accountID)
	initReq.URL.RawQuery = q.Encode()

	// Debug the final request
	log.Printf("Init Request Details:")
	log.Printf("- URL: %s", initReq.URL.String())
	log.Printf("- Headers: %v", initReq.Header)
	log.Printf("- Body: %s", string(payloadBytes))

	// Make initialization request
	client := &http.Client{}
	initResp, err := client.Do(initReq)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize upload: %w", err)
	}
	defer initResp.Body.Close()

	var initResponse struct {
		Data struct {
			UploadURL string `json:"upload_url"`
			VideoID   string `json:"video_id"`
		} `json:"data"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(initResp.Body).Decode(&initResponse); err != nil {
		return nil, fmt.Errorf("failed to decode init response: %w", err)
	}

	if initResponse.Error.Code != "" && initResponse.Error.Code != "ok" {
		return nil, fmt.Errorf("TikTok API init error: %s - %s", initResponse.Error.Code, initResponse.Error.Message)
	}

	// Add detailed debug logging for init response
	log.Printf("Init Response Details:")
	log.Printf("- Upload URL: %s", initResponse.Data.UploadURL)
	log.Printf("- Video ID: %s", initResponse.Data.VideoID)
	log.Printf("- Error Code: %s", initResponse.Error.Code)

	fmt.Println("\n\ninitResponse: ", initResponse)

	// Step 2: Upload video to the provided URL
	log.Printf("Starting Step 2 - Video Upload")
	log.Printf("File size: %d bytes", fileSize)
	log.Printf("First 100 bytes of file content: %v", fileBytes[:min(100, len(fileBytes))])

	// Debug init response data
	log.Printf("Init Response Data - Upload URL: %s", initResponse.Data.UploadURL)
	log.Printf("Init Response Data - Video ID: %s", initResponse.Data.VideoID)

	uploadReq, err := http.NewRequest("PUT", initResponse.Data.UploadURL, bytes.NewReader(fileBytes))
	if err != nil {
		log.Printf("Failed to create upload request: %v", err)
		return nil, fmt.Errorf("failed to create upload request: %w", err)
	}

	// Set and log headers
	uploadReq.Header.Set("Content-Type", "video/mov")
	uploadReq.Header.Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", fileSize-1, fileSize))
	uploadReq.Header.Set("Content-Length", fmt.Sprintf("%d", fileSize))

	log.Printf("Upload Request Details:")
	log.Printf("- Method: %s", uploadReq.Method)
	log.Printf("- URL: %s", uploadReq.URL.String())
	log.Printf("- Headers: %v", uploadReq.Header)
	log.Printf("- Content Length: %d", uploadReq.ContentLength)

	// Make request
	client = &http.Client{
		Timeout: 5 * time.Minute, // Increased timeout for large files
	}

	log.Printf("Sending upload request...")
	uploadResp, err := client.Do(uploadReq)
	if err != nil {
		log.Printf("Upload request failed: %v", err)
		return nil, fmt.Errorf("failed to upload video: %w", err)
	}
	defer uploadResp.Body.Close()

	// Read and log response
	respBody, _ := io.ReadAll(uploadResp.Body)
	log.Printf("Upload Response Details:")
	log.Printf("- Status Code: %d", uploadResp.StatusCode)
	log.Printf("- Status: %s", uploadResp.Status)
	log.Printf("- Headers: %v", uploadResp.Header)
	log.Printf("- Body: %s", string(respBody))

	if uploadResp.StatusCode != http.StatusOK && uploadResp.StatusCode != http.StatusCreated {
		log.Printf("Upload failed with non-success status code")
		return nil, fmt.Errorf("upload failed with status %d: %s", uploadResp.StatusCode, string(respBody))
	}

	log.Printf("Upload appears successful, proceeding to status check...")

	// Step 3: Check upload status
	statusURL := "https://open.tiktokapis.com/v2/post/publish/status/fetch/"

	log.Printf("Video ID from init response: %s", initResponse.Data.VideoID)

	statusPayload := struct {
		PublishID string `json:"publish_id"`
	}{
		PublishID: initResponse.Data.VideoID,
	}

	statusBytes, err := json.Marshal(statusPayload)
	if err != nil {
		log.Printf("Failed to marshal status payload: %v", err)
		return nil, fmt.Errorf("failed to marshal status payload: %w", err)
	}

	// Add query parameter for open_id
	statusReq, err := http.NewRequest("POST", statusURL, bytes.NewBuffer(statusBytes))
	if err != nil {
		log.Printf("Failed to create status request: %v", err)
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}

	statusReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	statusReq.Header.Set("Content-Type", "application/json; charset=UTF-8")

	// Add open_id to query parameters
	q = statusReq.URL.Query()
	q.Add("open_id", accountID)
	statusReq.URL.RawQuery = q.Encode()

	log.Printf("Sending status check request...")
	statusResp, err := client.Do(statusReq)
	if err != nil {
		log.Printf("Status request failed: %v", err)
		return nil, fmt.Errorf("failed to check status: %w", err)
	}
	defer statusResp.Body.Close()

	// Read and log status response
	statusRespBody, err := io.ReadAll(statusResp.Body)
	if err != nil {
		log.Printf("Failed to read status response body: %v", err)
		return nil, fmt.Errorf("failed to read status response: %w", err)
	}

	log.Printf("Status Response Details:")
	log.Printf("- Status Code: %d", statusResp.StatusCode)
	log.Printf("- Status: %s", statusResp.Status)
	log.Printf("- Headers: %v", statusResp.Header)
	log.Printf("- Body: %s", string(statusRespBody))

	var statusResponse struct {
		Data struct {
			Status   string `json:"status"`
			VideoID  string `json:"video_id"`
			ShareURL string `json:"share_url"`
		} `json:"data"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	// Create new reader for JSON decoding
	if err := json.NewDecoder(bytes.NewReader(statusRespBody)).Decode(&statusResponse); err != nil {
		log.Printf("Failed to decode status response: %v", err)
		return nil, fmt.Errorf("failed to decode status response: %w", err)
	}

	log.Printf("Decoded status response: %+v", statusResponse)

	return &model.VideoDistribution{
		ID:           statusResponse.Data.VideoID,
		Title:        title,
		Description:  description,
		URL:          statusResponse.Data.ShareURL,
		Status:       statusResponse.Data.Status,
		AccountID:    accountID,
		AccountTitle: "",
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
