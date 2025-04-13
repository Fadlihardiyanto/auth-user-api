package usecase

import (
	common "auth-user-api/internal/common/error"
	"auth-user-api/internal/common/util"
	"auth-user-api/internal/model"
	"auth-user-api/internal/model/converter"
	"auth-user-api/internal/repository"
	"context"
	"reflect"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserLoginHistoryUsecase struct {
	DB                         *gorm.DB
	Validate                   *validator.Validate
	Log                        *logrus.Logger
	UserLoginHistoryRepository *repository.UserLoginHistoryRepository
}

func NewUserLoginHistoryUsecase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate, userLoginHistoryRepository *repository.UserLoginHistoryRepository) *UserLoginHistoryUsecase {
	return &UserLoginHistoryUsecase{
		DB:                         db,
		Validate:                   validate,
		Log:                        log,
		UserLoginHistoryRepository: userLoginHistoryRepository,
	}
}

func (u *UserLoginHistoryUsecase) Search(ctx context.Context, request *model.SearchUserLoginHistoryRequest) ([]model.UserLoginHistoryResponse, int64, error) {
	tx := u.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := u.Validate.Struct(request)
	if err != nil {
		u.Log.Warnf("Failed to validate request : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return nil, 0, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	history, total, err := u.UserLoginHistoryRepository.Search(tx, request)
	if err != nil {
		u.Log.Warnf("Failed to search user login history : %+v", err)
		return nil, 0, err
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Warnf("Failed to commit transaction : %+v", err)
		return nil, 0, err
	}

	response := make([]model.UserLoginHistoryResponse, len(history))
	for i, v := range history {
		response[i] = *converter.UserLoginHistoryToResponse(&v)
	}

	return response, total, nil
}
