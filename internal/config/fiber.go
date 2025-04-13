package config

import (
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
)

func NewFiber(config *viper.Viper) *fiber.App {
	return fiber.New(fiber.Config{
		AppName:                 config.GetString("APP_NAME"),
		ErrorHandler:            NewErrorHandler(),
		Prefork:                 config.GetBool("WEB_PREFORK"),
		EnableTrustedProxyCheck: true,
		TrustedProxies:          []string{"*", "127.0.0.1"},
	})
}

func NewErrorHandler() fiber.ErrorHandler {
	return func(ctx *fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
		}
		return ctx.Status(code).JSON(fiber.Map{
			"errors": err.Error(),
		})
	}
}
