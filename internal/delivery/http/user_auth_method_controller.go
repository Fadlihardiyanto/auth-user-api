package http

import (
	common "auth-user-api/internal/common/error"
	"auth-user-api/internal/delivery/http/middleware"
	"auth-user-api/internal/model"
	"auth-user-api/internal/usecase"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type UserAuthMethodController struct {
	UseCase *usecase.UserAuthMethodUseCase
	Log     *logrus.Logger
}

func NewUserAuthMethodController(useCase *usecase.UserAuthMethodUseCase, logger *logrus.Logger) *UserAuthMethodController {
	return &UserAuthMethodController{
		UseCase: useCase,
		Log:     logger,
	}
}

func (c *UserAuthMethodController) Create(ctx *fiber.Ctx) error {
	auth := middleware.GetUser(ctx)

	request := new(model.CreateUserAuthMethodRequest)

	request.UserID = auth.ID
	if err := ctx.BodyParser(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	response, err := c.UseCase.Create(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to create user auth method : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.JSON(model.WebResponse[*model.UserAuthMethodResponse]{Data: response})
}
