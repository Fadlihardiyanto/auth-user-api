package middleware

import (
	"auth-user-api/internal/model"
	"auth-user-api/internal/usecase"

	"slices"

	"github.com/gofiber/fiber/v2"
)

func NewAuth(tokenUseCase *usecase.TokenUseCase, userUseCase *usecase.UserUseCase) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// extract jwt token from cookie
		token := ctx.Cookies("jwt")
		if token == "" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Unauthorized",
			})
		}

		// validate jwt token
		auth, err := tokenUseCase.ValidateToken(token)
		if err != nil {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Unauthorized",
			})
		}

		ctx.Locals("auth", auth)

		return ctx.Next()
	}
}

func RoleMiddleware(roles ...string) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		auth := GetUser(ctx)

		if slices.Contains(roles, auth.Role) {
			return ctx.Next()
		}

		return ctx.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Forbidden",
		})
	}
}

func GetUser(ctx *fiber.Ctx) *model.Auth {
	return ctx.Locals("auth").(*model.Auth)
}
