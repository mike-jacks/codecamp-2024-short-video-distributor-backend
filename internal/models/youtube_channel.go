package models

type YouTubeChannelDetails struct {
	BaseModel
	CredentialsID string `gorm:"not null;type:varchar(32)"`
	ChannelID     string `gorm:"not null"`
	ChannelTitle  string `gorm:"not null"`

	// Foreign key to PlatformCredentials
	PlatformCredentials PlatformCredentials `gorm:"foreignKey:CredentialsID;references:ID"`
}
