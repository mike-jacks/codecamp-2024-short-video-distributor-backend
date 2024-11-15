package db

import "fmt"

type DBType string

const (
	PostgresType DBType = "postgres"
)

func NewDatabase(dbType DBType, config interface{}) (Database, error) {
	switch dbType {
	case PostgresType:
		pgConfig, ok := config.(*PostgresConfig)
		if !ok {
			return nil, fmt.Errorf("invalid config type for postgres")
		}
		return NewPostges(pgConfig), nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
}
