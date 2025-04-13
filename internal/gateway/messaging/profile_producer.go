package messaging

import (
	"auth-user-api/internal/model"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
)

type ProfileProducer struct {
	Producer[*model.ProfileEvent]
}

func NewProfileProducer(producer *kafka.Producer, log *logrus.Logger) *ProfileProducer {
	return &ProfileProducer{
		Producer: Producer[*model.ProfileEvent]{
			Producer: producer,
			Topic:    "profiles",
			Log:      log,
		},
	}
}
