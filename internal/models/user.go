package models

type User struct {
	BaseModel
	Name          string `gorm:"not null"`
	Email         string `gorm:"not null;unique"`
	EmailVerified bool   `gorm:"not null"`
	Image         string `gorm:"image"`
}
