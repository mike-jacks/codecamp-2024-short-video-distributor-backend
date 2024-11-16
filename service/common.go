package service

import "time"

type AuthSession struct {
	Token     string
	UserID    string
	CreatedAt time.Time
	Used      bool
}
