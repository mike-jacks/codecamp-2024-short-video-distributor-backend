package db

import (
	"context"
)

type Database interface {
	Connect() error
	Close() error

	GetDriver() string
	Ping(ctx context.Context) error
}
