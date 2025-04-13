package http

import (
	common "auth-user-api/internal/common/error"
	"auth-user-api/internal/delivery/http/middleware"
	"auth-user-api/internal/model"
	"auth-user-api/internal/usecase"
	"math"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type ProfileController struct {
	UseCase *usecase.ProfileUseCase
	Log     *logrus.Logger
}

func NewProfileController(useCase *usecase.ProfileUseCase, logger *logrus.Logger) *ProfileController {
	return &ProfileController{
		UseCase: useCase,
		Log:     logger,
	}
}

func (c *ProfileController) Create(ctx *fiber.Ctx) error {
	auth := middleware.GetUser(ctx)

	request := new(model.CreateProfileRequest)

	request.UserID = auth.ID
	if err := ctx.BodyParser(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	response, err := c.UseCase.Create(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to create profile : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.JSON(model.WebResponse[*model.ProfileResponse]{Data: response})
}

func (c *ProfileController) List(ctx *fiber.Ctx) error {
	auth := middleware.GetUser(ctx)

	request := &model.SearchProfileRequest{
		UserID:      auth.ID,
		FullName:    ctx.Query("full_name"),
		DisplayName: ctx.Query("display_name"),
		Phone:       ctx.Query("phone"),
		Language:    ctx.Query("language"),
		Currency:    ctx.Query("currency"),
		BirthYear:   ctx.Query("birth_year"),
		Page:        ctx.QueryInt("page", 1),
		Size:        ctx.QueryInt("size", 10),
	}

	responses, total, err := c.UseCase.Search(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to search profile : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	paging := &model.PageMetadata{
		Page:      request.Page,
		Size:      request.Size,
		TotalItem: total,
		TotalPage: int64(math.Ceil(float64(total) / float64(request.Size))),
	}

	return ctx.JSON(model.WebResponse[[]model.ProfileResponse]{
		Data:   responses,
		Paging: paging,
	})

}

func (c *ProfileController) Get(ctx *fiber.Ctx) error {
	auth := middleware.GetUser(ctx)

	request := &model.GetProfileRequest{
		UserID: auth.ID,
		ID:     ctx.Params("id"),
	}

	response, err := c.UseCase.Get(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to get profile : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.JSON(model.WebResponse[*model.ProfileResponse]{Data: response})
}

func (c *ProfileController) Update(ctx *fiber.Ctx) error {
	auth := middleware.GetUser(ctx)

	request := &model.UpdateProfileRequest{
		UserID: auth.ID,
		ID:     ctx.Params("id"),
	}
	if err := ctx.BodyParser(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	response, err := c.UseCase.Update(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to update profile : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.JSON(model.WebResponse[*model.ProfileResponse]{Data: response})
}

func (c *ProfileController) Delete(ctx *fiber.Ctx) error {
	auth := middleware.GetUser(ctx)

	request := &model.DeleteProfileRequest{
		UserID: auth.ID,
		ID:     ctx.Params("id"),
	}

	err := c.UseCase.Delete(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to delete profile : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.SendStatus(fiber.StatusNoContent)
}
