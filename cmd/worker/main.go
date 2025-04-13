package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-user-api/internal/config"
	"auth-user-api/internal/delivery/messaging"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	viperConfig := config.NewViper()
	logger := config.NewLogger(viperConfig)
	logger.Info("Starting worker service")

	ctx, cancel := context.WithCancel(context.Background())

	go RunUserConsumer(logger, viperConfig, ctx)
	go RunUserNotificationConsumer(logger, viperConfig, ctx)

	terminateSignals := make(chan os.Signal, 1)
	signal.Notify(terminateSignals, syscall.SIGINT, syscall.SIGTERM)

	stop := false
	for !stop {
		s := <-terminateSignals
		logger.Info("Got one of stop signals, shutting down worker gracefully, SIGNAL NAME :", s)
		cancel()
		stop = true
	}

	time.Sleep(5 * time.Second) // wait for all consumers to finish processing
}

func RunUserConsumer(logger *logrus.Logger, viperConfig *viper.Viper, ctx context.Context) {
	logger.Info("setup user consumer")
	userConsumer := config.NewKafkaConsumer(viperConfig, logger)
	userHandler := messaging.NewUserConsumer(logger)
	messaging.ConsumeTopic(ctx, userConsumer, "users", logger, userHandler.Consume)
}

func RunUserNotificationConsumer(logger *logrus.Logger, viperConfig *viper.Viper, ctx context.Context) {
	logger.Info("Setting up user notification consumer")

	// Load SMTP config
	emailSender := messaging.NewEmailSender(
		viperConfig.GetString("SMTP_HOST"),
		viperConfig.GetString("SMTP_PORT"),
		viperConfig.GetString("SMTP_USERNAME"),
		viperConfig.GetString("SMTP_PASSWORD"),
		viperConfig.GetString("SMTP_FROM"),
		logger,
	)

	userConsumer := config.NewKafkaConsumer(viperConfig, logger)
	userNotificationHandler := messaging.NewUserNotificationConsumer(logger, emailSender)
	messaging.ConsumeTopic(ctx, userConsumer, "notification-event", logger, userNotificationHandler.Consume)
}
