package messaging

import (
	"auth-user-api/internal/model"
	"encoding/json"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
)

type ProfileConsumer struct {
	Log *logrus.Logger
}

func NewProfileConsumer(log *logrus.Logger) *ProfileConsumer {
	return &ProfileConsumer{
		Log: log,
	}
}

func (c *ProfileConsumer) Consume(message *kafka.Message) error {
	ProfileEvent := new(model.ProfileEvent)
	if err := json.Unmarshal(message.Value, ProfileEvent); err != nil {
		c.Log.WithError(err).Error("failed to unmarshal message")
		return err
	}

	// TODO process event
	c.Log.Infof("Received topic profile with event: %v from partition %d", ProfileEvent, message.TopicPartition.Partition)

	return nil
}
