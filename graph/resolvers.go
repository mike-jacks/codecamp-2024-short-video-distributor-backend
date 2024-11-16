package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.56

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/99designs/gqlgen/graphql"
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/graph/model"
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/internal/models"
)

// Empty is the resolver for the _empty field.
func (r *mutationResolver) Empty(ctx context.Context) (*string, error) {
	panic(fmt.Errorf("not implemented: Empty - _empty"))
}

// GenerateAuthURL is the resolver for the generateAuthURL field.
func (r *mutationResolver) GenerateAuthURL(ctx context.Context, platformType model.PlatformType, userID string) (string, error) {
	switch platformType {
	case model.PlatformTypeYoutube:
		return r.YoutubeService.GetAuthURL(userID)
	case model.PlatformTypeTiktok:
		return "", fmt.Errorf("TikTok not implemented yet")
	case model.PlatformTypeInstagram:
		return "", fmt.Errorf("instagram not implemented yet")
	default:
		return "", fmt.Errorf("unsupported platform type: %s", platformType)
	}
}

// Authorize is the resolver for the authorize field.
func (r *mutationResolver) Authorize(ctx context.Context, platformType model.PlatformType, code string, userID string) (bool, error) {
	switch platformType {
	case model.PlatformTypeYoutube:
		_, err := r.YoutubeService.ExchangeAndSaveToken(ctx, code, userID)
		return err == nil, nil
	case model.PlatformTypeTiktok:
		_, err := r.TikTokService.ExchangeAndSaveToken(ctx, code, userID)
		return err == nil, nil
	case model.PlatformTypeInstagram:
		return false, fmt.Errorf("instagram not implemented yet")
	default:
		return false, fmt.Errorf("unsupported platform type: %s", platformType)
	}
}

// RevokeAuth is the resolver for the revokeAuth field.
func (r *mutationResolver) RevokeAuth(ctx context.Context, platformType model.PlatformType, userID string) (bool, error) {
	switch platformType {
	case model.PlatformTypeYoutube:
		// return r.youtubeService.RevokeToken(ctx, userID)
		return false, fmt.Errorf("YouTube not implemented yet")
	case model.PlatformTypeTiktok:
		return false, fmt.Errorf("TikTok not implemented yet")
	case model.PlatformTypeInstagram:
		return false, fmt.Errorf("instagram not implemented yet")
	default:
		return false, fmt.Errorf("unsupported platform type: %s", platformType)
	}
}

// UploadVideos is the resolver for the uploadVideos field.
func (r *mutationResolver) UploadVideo(ctx context.Context, title string, description string, file graphql.Upload, uploadVideoInput []*model.UploadVideoInput) ([]*model.VideoDistribution, error) {
	// Add a size check before reading the file (e.g., 2GB limit)
	if file.Size > 2*1024*1024*1024 {
		return nil, fmt.Errorf("file size exceeds maximum allowed size of 2GB")
	}
	result := make([]*model.VideoDistribution, len(uploadVideoInput))
	var err error

	// Read the entire file into memory
	fileBytes, err := io.ReadAll(file.File)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	for i, input := range uploadVideoInput {
		// Create a new reader for each upload
		fileReader := bytes.NewReader(fileBytes)
		uploadFile := graphql.Upload{
			File:     fileReader,
			Filename: file.Filename,
			Size:     file.Size,
		}

		switch input.PlatformType {
		case model.PlatformTypeYoutube:
			result[i], err = r.YoutubeService.UploadVideo(ctx, input.UserID, input.AccountID, title, description, uploadFile, input.PrivacyStatus, input.AccessToken, input.RefreshToken, input.TokenExpiresAt)
			if err != nil {
				return nil, err
			}

			tx := r.db.Begin()
			defer func() {
				if r := recover(); r != nil {
					tx.Rollback()
				}
			}()

			if err := tx.Create(&models.VideoDistribution{
				Title:        result[i].Title,
				Description:  result[i].Description,
				URL:          result[i].URL,
				Status:       models.DistributionStatus(result[i].Status),
				AccountID:    result[i].AccountID,
				AccountTitle: result[i].AccountTitle,
			}).Error; err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("failed to save video distribution: %w", err)
			}

			if err := tx.Commit().Error; err != nil {
				return nil, fmt.Errorf("failed to commit transaction: %w", err)
			}
		case model.PlatformTypeTiktok:
			result[i], err = r.TikTokService.UploadVideo(ctx, input.UserID, input.AccountID, title, description, uploadFile, input.PrivacyStatus, input.AccessToken, input.RefreshToken, input.TokenExpiresAt)
			if err != nil {
				return nil, err
			}

			tx := r.db.Begin()
			defer func() {
				if r := recover(); r != nil {
					tx.Rollback()
				}
			}()

			if err := tx.Create(&models.VideoDistribution{
				Title:        result[i].Title,
				Description:  result[i].Description,
				URL:          result[i].URL,
				Status:       models.DistributionStatus(result[i].Status),
				AccountID:    result[i].AccountID,
				AccountTitle: result[i].AccountTitle,
			}).Error; err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("failed to save video distribution: %w", err)
			}

			if err := tx.Commit().Error; err != nil {
				return nil, fmt.Errorf("failed to commit transaction: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported platform type: %s", input.PlatformType)
		}
	}
	return result, nil
}

// Empty is the resolver for the _empty field.
func (r *queryResolver) Empty(ctx context.Context) (*string, error) {
	panic(fmt.Errorf("not implemented: Empty - _empty"))
}

// GetAuthURL is the resolver for the getAuthURL field.
func (r *queryResolver) GetAuthURL(ctx context.Context, platformType model.PlatformType, userID string) (string, error) {
	switch platformType {
	case model.PlatformTypeYoutube:
		return r.YoutubeService.GetAuthURL(userID)
	case model.PlatformTypeTiktok:
		return r.TikTokService.GetAuthURL(userID)
	case model.PlatformTypeInstagram:
		return "", fmt.Errorf("instagram not implemented yet")
	default:
		return "", fmt.Errorf("unsupported platform type: %s", platformType)
	}
}

// GetPlatformCredentials is the resolver for the getPlatformCredentials field.
func (r *queryResolver) GetPlatformCredentials(ctx context.Context, userID string) ([]*model.PlatformCredentials, error) {
	var creds []*models.PlatformCredentials
	err := r.db.Where("user_id = ?", userID).Find(&creds).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get platform credentials: %w", err)
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
			AccountID:      cred.AccountID,
			AccountTitle:   cred.AccountTitle,
		}
	}
	return result, nil
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
