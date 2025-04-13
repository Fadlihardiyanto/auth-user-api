package http

import (
	"math"

	common "auth-user-api/internal/common/error"
	"auth-user-api/internal/model"
	"auth-user-api/internal/usecase"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type UserController struct {
	Log     *logrus.Logger
	UseCase *usecase.UserUseCase
}

func NewUserController(useCase *usecase.UserUseCase, logger *logrus.Logger) *UserController {
	return &UserController{
		Log:     logger,
		UseCase: useCase,
	}
}

func (c *UserController) List(ctx *fiber.Ctx) error {

	request := &model.SearchUserRequest{
		UserId:   ctx.Query("user_id", ""),
		Email:    ctx.Query("email", ""),
		Role:     ctx.Query("role", ""),
		Verified: ctx.Query("verified", ""),
		Page:     ctx.QueryInt("page", 1),
		Size:     ctx.QueryInt("size", 10),
	}

	response, total, err := c.UseCase.Search(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	paging := &model.PageMetadata{
		Page:      request.Page,
		Size:      request.Size,
		TotalItem: total,
		TotalPage: int64(math.Ceil(float64(total) / float64(request.Size))),
	}

	return ctx.JSON(model.WebResponse[[]model.UserResponse]{
		Data:   response,
		Paging: paging,
	})
}

func (c *UserController) FindById(ctx *fiber.Ctx) error {
	request := &model.GetUserRequest{
		ID: ctx.Params("id"),
	}

	response, err := c.UseCase.FindByID(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.JSON(model.WebResponse[*model.UserResponse]{Data: response})
}

func (c *UserController) Update(ctx *fiber.Ctx) error {
	request := new(model.UpdateUserRequest)
	if err := ctx.BodyParser(request); err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	request.ID = ctx.Params("id")

	response, err := c.UseCase.Update(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.JSON(model.WebResponse[*model.UserResponse]{Data: response})
}

func (c *UserController) ChangeRole(ctx *fiber.Ctx) error {
	request := new(model.ChangeRoleRequest)
	if err := ctx.BodyParser(request); err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	request.ID = ctx.Params("id")

	response, err := c.UseCase.ChangeRole(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	if response {
		hasil := "Role berhasil diubah"
		return ctx.JSON(model.WebResponse[string]{Data: hasil})
	}

	hasil := "Role gagal diubah"
	return ctx.JSON(model.WebResponse[string]{Data: hasil})
}

func (c *UserController) Delete(ctx *fiber.Ctx) error {
	request := &model.DeleteUserRequest{
		ID: ctx.Params("id"),
	}

	response, err := c.UseCase.SoftDelete(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	if response {
		hasil := "Data berhasil dihapus"
		return ctx.JSON(model.WebResponse[string]{Data: hasil})
	}

	hasil := "Data gagal dihapus"
	return ctx.JSON(model.WebResponse[string]{Data: hasil})
}
