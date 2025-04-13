package http

import (
	common "auth-user-api/internal/common/error"
	"auth-user-api/internal/model"
	"auth-user-api/internal/usecase"
	"math"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type UserLoginHistoryController struct {
	Log         *logrus.Logger
	UserUseCase *usecase.UserLoginHistoryUsecase
}

func NewUserLoginHistoryController(useCase *usecase.UserLoginHistoryUsecase, logger *logrus.Logger) *UserLoginHistoryController {
	return &UserLoginHistoryController{
		Log:         logger,
		UserUseCase: useCase,
	}
}

func (c *UserLoginHistoryController) List(ctx *fiber.Ctx) error {
	request := &model.SearchUserLoginHistoryRequest{
		UserId:         ctx.Query("user_id", ""),
		IpAddress:      ctx.Query("ip_address", ""),
		Os:             ctx.Query("os", ""),
		Device:         ctx.Query("device", ""),
		Browser:        ctx.Query("browser", ""),
		LoginTimeStart: ctx.Query("login_time_start", ""),
		LoginTimeEnd:   ctx.Query("login_time_end", ""),
		Page:           ctx.QueryInt("page", 1),
		Size:           ctx.QueryInt("size", 10),
	}

	response, total, err := c.UserUseCase.Search(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to search user login history : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	paging := &model.PageMetadata{
		Page:      request.Page,
		Size:      request.Size,
		TotalItem: total,
		TotalPage: int64(math.Ceil(float64(total) / float64(request.Size))),
	}

	return ctx.JSON(model.WebResponse[[]model.UserLoginHistoryResponse]{
		Data:   response,
		Paging: paging,
	})

}
