package models

type DistributionStatus string

const (
	Uploaded   DistributionStatus = "uploaded"
	Processing DistributionStatus = "processing"
	Completed  DistributionStatus = "completed"
	Failed     DistributionStatus = "failed"
	Rejected   DistributionStatus = "rejected"
	Deleted    DistributionStatus = "deleted"
)

type VideoDistribution struct {
	BaseModel
	Title        string             `gorm:"not null"`
	Description  string             `gorm:"not null"`
	URL          string             `gorm:"not null"`
	Status       DistributionStatus `gorm:"type:varchar(20);not null"`
	AccountID    string             `gorm:"not null"`
	AccountTitle string             `gorm:"not null"`
}
