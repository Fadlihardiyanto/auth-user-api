package usecase

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/gateway/messaging"
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

type ProfileUseCase struct {
	DB                *gorm.DB
	Log               *logrus.Logger
	Validate          *validator.Validate
	ProfileRepository *repository.ProfileRepository
	ProfileProducer   *messaging.ProfileProducer
}

func NewProfileUseCase(
	db *gorm.DB,
	log *logrus.Logger,
	validate *validator.Validate,
	profileRepository *repository.ProfileRepository,
	profileProducer *messaging.ProfileProducer,
) *ProfileUseCase {
	return &ProfileUseCase{
		DB:                db,
		Log:               log,
		Validate:          validate,
		ProfileRepository: profileRepository,
		ProfileProducer:   profileProducer,
	}
}

func (u *ProfileUseCase) Create(ctx context.Context, request *model.CreateProfileRequest) (*model.ProfileResponse, error) {
	tx := u.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := u.Validate.RegisterValidation("date_format", model.DateFormat)
	if err != nil {
		u.Log.Error("failed to register date format validation: ", err)
		return nil, err
	}

	if err := u.Validate.Struct(request); err != nil {
		u.Log.Error("validation error: ", err)
		return nil, err
	}

	profile := &entity.Profile{
		ID:          uuid.New().String(),
		UserID:      request.UserID,
		FullName:    request.FullName,
		DisplayName: request.DisplayName,
		Language:    request.Language,
		Currency:    request.Currency,
		BirthYear:   request.BirthYear,
		Phone:       request.Phone,
	}

	total, err := u.ProfileRepository.CountByUserID(tx, request.UserID)
	if err != nil {
		u.Log.Error("failed to count profiles: ", err)
		return nil, err
	}

	if total > 0 {
		u.Log.Error("user already has a profile")
		return nil, fiber.NewError(fiber.StatusConflict, "user already has a profile")
	}

	if err := u.ProfileRepository.Create(tx, profile); err != nil {
		u.Log.Error("failed to create profile: ", err)
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Error("failed to commit transaction: ", err)
		return nil, err
	}

	event := converter.ProfileToEvent(profile)
	if err := u.ProfileProducer.Send(event); err != nil {
		u.Log.Error("failed to send profile event: ", err)
		return nil, err
	}

	return converter.ProfileToResponse(profile), nil
}

func (u *ProfileUseCase) Update(ctx context.Context, request *model.UpdateProfileRequest) (*model.ProfileResponse, error) {
	tx := u.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	profile := new(entity.Profile)
	if err := u.ProfileRepository.FindByIDAndUserID(tx, profile, request.ID, request.UserID); err != nil {
		u.Log.Error("failed to find profile: ", err)
		return nil, err
	}

	err := u.Validate.RegisterValidation("date_format", model.DateFormat)
	if err != nil {
		u.Log.Error("failed to register date format validation: ", err)
		return nil, err
	}

	if err := u.Validate.Struct(request); err != nil {
		u.Log.Error("validation error: ", err)
		return nil, err
	}

	profile.UserID = request.UserID
	profile.ID = request.ID
	profile.FullName = request.FullName
	profile.DisplayName = request.DisplayName
	profile.Phone = request.Phone
	profile.Language = request.Language
	profile.Currency = request.Currency
	profile.BirthYear = request.BirthYear

	if err := u.ProfileRepository.Update(tx, profile); err != nil {
		u.Log.Error("failed to update profile: ", err)
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Error("failed to commit transaction: ", err)
		return nil, err
	}

	event := converter.ProfileToEvent(profile)
	if err := u.ProfileProducer.Send(event); err != nil {
		u.Log.Error("failed to send profile event: ", err)
		return nil, err
	}

	return converter.ProfileToResponse(profile), nil
}

func (u *ProfileUseCase) Get(ctx context.Context, request *model.GetProfileRequest) (*model.ProfileResponse, error) {
	tx := u.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	profile := new(entity.Profile)
	if err := u.ProfileRepository.FindByIDAndUserID(tx, profile, request.ID, request.UserID); err != nil {
		u.Log.Error("failed to find profile: ", err)
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Error("failed to commit transaction: ", err)
		return nil, err
	}

	return converter.ProfileToResponse(profile), nil
}

func (u *ProfileUseCase) Delete(ctx context.Context, request *model.DeleteProfileRequest) error {
	tx := u.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	profile := new(entity.Profile)
	if err := u.ProfileRepository.FindByIDAndUserID(tx, profile, request.ID, request.UserID); err != nil {
		u.Log.Error("failed to find profile: ", err)
		return err
	}

	if err := u.ProfileRepository.Delete(tx, profile); err != nil {
		u.Log.Error("failed to delete profile: ", err)
		return err
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Error("failed to commit transaction: ", err)
		return err
	}

	event := converter.ProfileToEvent(profile)
	if err := u.ProfileProducer.Send(event); err != nil {
		u.Log.Error("failed to send profile event: ", err)
		return err
	}

	return nil
}

func (u *ProfileUseCase) Search(ctx context.Context, request *model.SearchProfileRequest) ([]model.ProfileResponse, int64, error) {

	tx := u.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	if err := u.Validate.Struct(request); err != nil {
		u.Log.Error("validation error: ", err)
		return nil, 0, err
	}

	profiles, total, err := u.ProfileRepository.Search(tx, request)
	if err != nil {
		u.Log.Error("failed to search profiles: ", err)
		return nil, 0, err
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Error("failed to commit transaction: ", err)
		return nil, 0, err
	}

	responses := make([]model.ProfileResponse, len(profiles))
	for i, profile := range profiles {
		responses[i] = *converter.ProfileToResponse(&profile)
	}

	return responses, total, nil
}
