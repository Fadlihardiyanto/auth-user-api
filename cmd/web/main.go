package main

import (
	"fmt"

	"auth-user-api/internal/config"
)

func main() {
	viperConfig := config.NewViper()
	log := config.NewLogger(viperConfig)
	db := config.NewDatabase(viperConfig, log)
	validate := config.NewValidator(viperConfig)
	app := config.NewFiber(viperConfig)
	producer := config.NewKafkaProducer(viperConfig, log)
	redis := config.NewRedisClient(viperConfig, log)
	jwtConfig := config.NewJWTConfig(viperConfig)

	config.Bootstrap(&config.BootstrapConfig{
		DB:        db,
		App:       app,
		Log:       log,
		Validate:  validate,
		Config:    viperConfig,
		Producer:  producer,
		Redis:     redis,
		JWTConfig: jwtConfig,
	})

	webPort := viperConfig.GetInt("WEB_PORT")
	url := viperConfig.GetString("WEB_HOST")
	log.Infof("Starting server at %s:%d", url, webPort)
	err := app.Listen(fmt.Sprintf(":%d", webPort))
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
