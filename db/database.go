package db

import (
	"context"

	"gorm.io/gorm"
)

type Database interface {
	Connect() error
	Close() error
	GetDriver() string
	Ping(ctx context.Context) error
	DB() *gorm.DB
}
