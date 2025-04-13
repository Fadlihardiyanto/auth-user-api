package messaging

import (
	"auth-user-api/internal/model"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
)

type NotificationProducer struct {
	Producer[*model.NotificationEvent]
}

func NewNotificationProducer(producer *kafka.Producer, log *logrus.Logger) *NotificationProducer {
	return &NotificationProducer{
		Producer: Producer[*model.NotificationEvent]{
			Producer: producer,
			Topic:    "notification-event",
			Log:      log,
		},
	}
}
