package models

type DistributionStatus string

const (
	Pending   DistributionStatus = "PENDING"
	Uploading DistributionStatus = "UPLOADING"
	Completed DistributionStatus = "COMPLETED"
	Failed    DistributionStatus = "FAILED"
)

type VideoDistribution struct {
	BaseModel
	UserID     string
	Title      string
	PlatformID string
	VideoID    string
	Status     DistributionStatus
}
