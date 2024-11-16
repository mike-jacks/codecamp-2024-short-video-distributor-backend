package db

import (
	"context"
	"fmt"

	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Postgres struct {
	db     *gorm.DB
	config *PostgresConfig
}

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

func NewPostges(config *PostgresConfig) Database {
	return &Postgres{
		config: config,
	}
}

func (p *Postgres) Connect() error {
	dsn := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=%s",
		p.config.User,
		p.config.Password,
		p.config.Host,
		p.config.Port,
		p.config.DBName,
		p.config.SSLMode,
	)

	fmt.Println("Connecting to database with DSN:", dsn)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	p.db = db
	fmt.Println("Connected to database")

	// Auto migrate models
	if err := p.db.AutoMigrate(
		&models.VideoDistribution{},
		&models.PlatformCredentials{},
	); err != nil {
		return fmt.Errorf("failed to migrate models: %w", err)
	}

	return nil
}

func (p *Postgres) Close() error {
	sqlDB, err := p.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}
	fmt.Println("Closing database connection")
	return sqlDB.Close()
}

func (p *Postgres) GetDriver() string {
	return "postgres"
}

func (p *Postgres) Ping(ctx context.Context) error {
	sqlDB, err := p.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}
	return sqlDB.PingContext(ctx)
}

func (p *Postgres) DB() *gorm.DB {
	return p.db
}
