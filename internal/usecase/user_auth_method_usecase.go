package usecase

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"
	"auth-user-api/internal/model/converter"
	"auth-user-api/internal/repository"
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserAuthMethodUseCase struct {
	DB                       *gorm.DB
	Log                      *logrus.Logger
	Validate                 *validator.Validate
	UserAuthMethodRepository *repository.UserAuthMethodRepository
}

func NewUserAuthMethodUseCase(
	db *gorm.DB,
	log *logrus.Logger,
	validate *validator.Validate,
	userAuthMethodRepository *repository.UserAuthMethodRepository,
) *UserAuthMethodUseCase {
	return &UserAuthMethodUseCase{
		DB:                       db,
		Log:                      log,
		Validate:                 validate,
		UserAuthMethodRepository: userAuthMethodRepository,
	}
}

func (u *UserAuthMethodUseCase) Create(ctx context.Context, CreateUserAuthMethodRequest *model.CreateUserAuthMethodRequest) (*model.UserAuthMethodResponse, error) {
	tx := u.DB.WithContext(ctx).Begin()
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	err := u.Validate.Struct(CreateUserAuthMethodRequest)
	if err != nil {
		u.Log.Warnf("Failed to validate request : %+v", err)
		return nil, err
	}

	// check if user auth method already exists
	userAuthMethod := &entity.UserAuthMethod{
		ID:             uuid.New().String(),
		UserID:         CreateUserAuthMethodRequest.UserID,
		AuthMethod:     CreateUserAuthMethodRequest.AuthMethod,
		AuthIdentifier: CreateUserAuthMethodRequest.AuthIdentifier,
	}

	total, err := u.UserAuthMethodRepository.CountByUserIDAndMethodAndIdentifier(tx, CreateUserAuthMethodRequest.UserID, CreateUserAuthMethodRequest.AuthMethod, CreateUserAuthMethodRequest.AuthIdentifier)
	if err != nil {
		u.Log.Warnf("Failed to count user auth method : %+v", err)
		return nil, err
	}

	if total > 0 {
		u.Log.Warnf("User auth method already exists : %+v", userAuthMethod)
		return nil, fiber.NewError(fiber.StatusConflict, "user auth method already exists")
	}

	if err := u.UserAuthMethodRepository.Create(tx, userAuthMethod); err != nil {
		u.Log.Warnf("Failed to create user auth method : %+v", err)
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Warnf("Failed to commit transaction : %+v", err)
		return nil, err
	}

	committed = true

	return converter.UserAuthMethodToResponse(userAuthMethod), nil
}

func (u *UserAuthMethodUseCase) CreateWithTx(ctx context.Context, tx *gorm.DB, CreateUserAuthMethodRequest *model.CreateUserAuthMethodRequest) (*model.UserAuthMethodResponse, error) {
	err := u.Validate.Struct(CreateUserAuthMethodRequest)
	if err != nil {
		u.Log.Warnf("Failed to validate request : %+v", err)
		return nil, err
	}

	// check if user auth method already exists
	userAuthMethod := &entity.UserAuthMethod{
		ID:             uuid.New().String(),
		UserID:         CreateUserAuthMethodRequest.UserID,
		AuthMethod:     CreateUserAuthMethodRequest.AuthMethod,
		AuthIdentifier: CreateUserAuthMethodRequest.AuthIdentifier,
	}

	total, err := u.UserAuthMethodRepository.CountByUserIDAndMethodAndIdentifier(tx, CreateUserAuthMethodRequest.UserID, CreateUserAuthMethodRequest.AuthMethod, CreateUserAuthMethodRequest.AuthIdentifier)
	if err != nil {
		u.Log.Warnf("Failed to count user auth method : %+v", err)
		return nil, err
	}

	if total > 0 {
		u.Log.Warnf("User auth method already exists : %+v", userAuthMethod)
		return nil, fiber.NewError(fiber.StatusConflict, "user auth method already exists")
	}

	if err := u.UserAuthMethodRepository.Create(tx, userAuthMethod); err != nil {
		u.Log.Warnf("Failed to create user auth method : %+v", err)
		return nil, err
	}

	return converter.UserAuthMethodToResponse(userAuthMethod), nil
}
