package messaging

import (
	"encoding/json"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"auth-user-api/internal/model"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
)

type EmailSender struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	Log          *logrus.Logger
}

func NewEmailSender(host, port, username, password, from string, log *logrus.Logger) *EmailSender {
	return &EmailSender{
		SMTPHost:     host,
		SMTPPort:     port,
		SMTPUsername: username,
		SMTPPassword: password,
		FromEmail:    from,
		Log:          log,
	}
}

func (e *EmailSender) SendEmail(to []string, subject, body string) error {
	emailBody := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s",
		e.FromEmail, strings.Join(to, ","), subject, body)

	auth := smtp.PlainAuth("", e.SMTPUsername, e.SMTPPassword, e.SMTPHost)
	smtpAddr := fmt.Sprintf("%s:%s", e.SMTPHost, e.SMTPPort)

	var err error
	for i := 0; i < 3; i++ { // Max retry 3 kali
		err = smtp.SendMail(smtpAddr, auth, e.SMTPUsername, to, []byte(emailBody))
		if err == nil {
			e.Log.Infof("Email sent successfully to %s", strings.Join(to, ","))
			return nil
		}
		e.Log.Errorf("Failed to send email (attempt %d): %v", i+1, err)
		time.Sleep(time.Duration(i*2) * time.Second) // Exponential backoff
	}

	e.Log.Errorf("Failed to send email after retries: %v", err)
	return err
}

type NotificationConsumer struct {
	Log         *logrus.Logger
	EmailSender *EmailSender
}

func NewUserNotificationConsumer(log *logrus.Logger, emailSender *EmailSender) *NotificationConsumer {
	return &NotificationConsumer{
		Log:         log,
		EmailSender: emailSender,
	}
}

func (c *NotificationConsumer) Consume(message *kafka.Message) error {

	event := new(model.NotificationEvent)

	if err := json.Unmarshal(message.Value, event); err != nil {
		c.Log.WithError(err).Error("Error unmarshalling NotificationEvent")
		return err
	}

	// TODO process event
	c.Log.Infof("Received topic notification with event: %v from partition %d", event, message.TopicPartition.Partition)

	subject := "Notification"
	body := "Hello, this is your notification."

	log.Println("event type", event.Type)
	if event.Type == "registration" {
		subject = "Welcome to Our Platform!"
		body = fmt.Sprintf("Hello %s, please verify your email using this link: %s", event.Name, event.Data["verification_link"])
	} else if event.Type == "order" {
		subject = "Order Confirmation"
		body = fmt.Sprintf("Thank you %s, your order #%s has been received.", event.Name, event.Data["order_id"])
	} else if event.Type == "reset_password" {
		subject = "Reset Password"
		body = fmt.Sprintf("Hello %s, please reset your password using this link: %s", event.Name, event.Data["reset_link"])
	}

	return c.EmailSender.SendEmail([]string{event.Email}, subject, body)
}
