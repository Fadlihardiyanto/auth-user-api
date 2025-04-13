package usecase

import (
	"context"
	"fmt"
	"reflect"
	"time"

	common "auth-user-api/internal/common/error"
	"auth-user-api/internal/common/util"
	"auth-user-api/internal/entity"
	"auth-user-api/internal/gateway/messaging"
	"auth-user-api/internal/model"
	"auth-user-api/internal/model/converter"
	"auth-user-api/internal/repository"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserUseCase struct {
	DB                         *gorm.DB
	Log                        *logrus.Logger
	Validate                   *validator.Validate
	UserRepository             *repository.UserRepository
	UserLoginHistoryRepository *repository.UserLoginHistoryRepository
	UserAuthMethodRepository   *repository.UserAuthMethodRepository
	UserProducer               *messaging.UserProducer
	NotificationProducer       *messaging.NotificationProducer
	RedisClient                *redis.Client
	TokenUseCase               *TokenUseCase
	Viper                      *viper.Viper
}

func NewUserUseCase(db *gorm.DB, logger *logrus.Logger, validate *validator.Validate,
	userRepository *repository.UserRepository, UserLoginHistoryRepository *repository.UserLoginHistoryRepository, UserAuthMethodRepository *repository.UserAuthMethodRepository, userProducer *messaging.UserProducer, notificationProducer *messaging.NotificationProducer, redisClient *redis.Client, tokenUseCase *TokenUseCase, viper *viper.Viper) *UserUseCase {
	return &UserUseCase{
		DB:                         db,
		Log:                        logger,
		Validate:                   validate,
		UserRepository:             userRepository,
		UserLoginHistoryRepository: UserLoginHistoryRepository,
		UserAuthMethodRepository:   UserAuthMethodRepository,
		UserProducer:               userProducer,
		NotificationProducer:       notificationProducer,
		RedisClient:                redisClient,
		TokenUseCase:               tokenUseCase,
		Viper:                      viper,
	}
}

func (c *UserUseCase) Verify(ctx context.Context, request *model.VerifyUserRequest) (bool, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return false, fiber.ErrBadRequest
	}

	user := new(entity.User)
	total, err := c.UserRepository.FindEmailVerifiedAt(tx, request.ID)
	if err != nil {
		c.Log.Warnf("Failed find email verified at : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	if total > 0 {
		c.Log.Warnf("Email already verified")
		return false, fiber.ErrConflict
	}

	// update email verified at
	if err := c.UserRepository.UpdateEmailVerifiedAt(tx, user, request.ID, request.Token); err != nil {
		c.Log.Warnf("Failed update email verified at : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	return true, nil
}

func (c *UserUseCase) Create(ctx context.Context, request *model.RegisterUserRequest) (*model.UserResponse, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return nil, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	total, err := c.UserRepository.CountByEmail(tx, request.Email)
	if err != nil {
		c.Log.Warnf("Failed count user by email : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	if total > 0 {
		c.Log.Warnf("Email already registered")
		return nil, fiber.NewError(fiber.StatusConflict, `{"email": "email already registered"}`)
	}

	// generate token
	token, err := util.GenerateToken(32)
	if err != nil {
		c.Log.Warnf("Failed generate token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	password, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Log.Warnf("Failed to generate bcrype hash : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	user := &entity.User{
		ID:         request.ID,
		Password:   string(password),
		Email:      request.Email,
		EmailToken: token,
	}

	if err := c.UserRepository.Create(tx, user); err != nil {
		c.Log.Warnf("Failed create user to database : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	event := converter.UserToEvent(user)
	c.Log.Info("Publishing user created event")
	if err = c.UserProducer.Send(event); err != nil {
		c.Log.Warnf("Failed publish user created event : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// link verification
	linkVerification := fmt.Sprintf(
		"%s://%s:%s/api/v1/verify?id=%s&token=%s",
		c.Viper.GetString("WEB_PROTOCOL"),
		c.Viper.GetString("WEB_HOST"),
		c.Viper.GetString("WEB_PORT"),
		user.ID,
		user.EmailToken,
	)

	// nanti akan dikirimkan email lewat kafka di sini
	notifEvent := &model.NotificationEvent{
		ID:         user.ID,
		Email:      user.Email,
		TemplateID: "registration",
		Type:       "registration",
		Data: map[string]interface{}{
			"verification_link": linkVerification,
		},
	}

	c.Log.Info("Publishing notification event")
	if err = c.NotificationProducer.Send(notifEvent); err != nil {
		c.Log.Warnf("Failed publish notification event : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	return converter.UserToResponse(user), nil
}

func (c *UserUseCase) CreateOauth(ctx context.Context, tx *gorm.DB, request *model.RegisterOauthUserRequest) (*model.UserResponse, error) {

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return nil, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	total, err := c.UserRepository.CountByEmail(tx, request.Email)
	if err != nil {
		c.Log.Warnf("Failed count user by email : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	c.Log.Infof("Total user with email %s: %d", request.Email, total)

	if total > 0 {
		c.Log.Warnf("Email already registered")
		return nil, fiber.NewError(fiber.StatusConflict, `{"email": "email already registered"}`)
	}

	// generate token
	token, err := util.GenerateToken(32)
	if err != nil {
		c.Log.Warnf("Failed generate token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	now := time.Now()

	user := &entity.User{
		ID:              request.ID,
		Email:           request.Email,
		EmailToken:      token,
		EmailVerifiedAt: &now,
	}

	if err := c.UserRepository.Create(tx, user); err != nil {
		c.Log.Warnf("Failed create user to database : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	event := converter.UserToEvent(user)
	c.Log.Info("Publishing user created event")
	if err = c.UserProducer.Send(event); err != nil {
		c.Log.Warnf("Failed publish user created event : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	return converter.UserToResponse(user), nil
}

func (c *UserUseCase) Login(ctx context.Context, request *model.LoginUserRequest) (*model.UserResponse, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return nil, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	user := new(entity.User)
	if err := c.UserRepository.FindByEmailVerified(tx, user, request.Email); err != nil {
		c.Log.Warnf("Failed find user by id in Login : %+v", err)
		return nil, fiber.NewError(fiber.StatusUnauthorized, "email not found or not verified or password not match")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		c.Log.Warnf("Failed to compare user password with bcrype hash : %+v", err)
		return nil, fiber.NewError(fiber.StatusUnauthorized, `email not found or not verified or password not match`)
	}

	// Generate JWT token
	accessToken, refreshToken, refreshTokenID, AccessExpiry, err := c.TokenUseCase.GenerateToken(user.ID, user.Role)
	if err != nil {
		c.Log.Warnf("Failed to generate token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// send access token to client
	user.Token = accessToken

	// send refresh token to redis
	err = c.TokenUseCase.StoreToken(refreshToken, refreshTokenID, user.ID)
	if err != nil {
		c.Log.Warnf("Failed to store token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// save user login history
	userLoginHistory := &entity.UserLoginHistory{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		IpAddress:  request.IpAddress,
		DiviceInfo: request.DeviceInfo,
		LoginTime:  time.Now(),
	}

	if err := c.UserLoginHistoryRepository.Create(tx, userLoginHistory); err != nil {
		c.Log.Warnf("Failed create user login history to database : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	event := converter.UserToEvent(user)
	c.Log.Info("Publishing user created event")
	if err := c.UserProducer.Send(event); err != nil {
		c.Log.Warnf("Failed publish user created event : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	return converter.UserToLoginResponse(user, accessToken, refreshTokenID, AccessExpiry), nil
}

func (c *UserUseCase) LoginOauth(ctx context.Context, tx *gorm.DB, request *model.LoginOauthUserRequest) (*model.UserResponse, error) {

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return nil, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	user := new(entity.User)
	if err := c.UserRepository.FindByEmailVerified(tx, user, request.Email); err != nil {
		c.Log.Warnf("Failed find user by id in LoginOauth : %+v", err)
		return nil, fiber.NewError(fiber.StatusUnauthorized, "email not found or not verified or password not match")
	}

	// check if user auth method exists
	userAuthMethod := new(entity.UserAuthMethod)
	if err := c.UserAuthMethodRepository.FindByUserIDAndMethodAndIdentifier(tx, userAuthMethod, user.ID, request.AuthMethod, request.AuthIdentifier); err != nil {
		c.Log.Warnf("Failed find user auth method by id : %+v", err)
		return nil, fiber.NewError(fiber.StatusUnauthorized, "user already registered. please login with email and password")
	}

	// Generate JWT token
	accessToken, refreshToken, refreshTokenID, AccessExpiry, err := c.TokenUseCase.GenerateToken(user.ID, user.Role)
	if err != nil {
		c.Log.Warnf("Failed to generate token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// send access token to client
	user.Token = accessToken

	// send refresh token to redis
	err = c.TokenUseCase.StoreToken(refreshToken, refreshTokenID, user.ID)
	if err != nil {
		c.Log.Warnf("Failed to store token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// save user login history
	userLoginHistory := &entity.UserLoginHistory{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		IpAddress:  request.IpAddress,
		DiviceInfo: request.DeviceInfo,
		LoginTime:  time.Now(),
	}

	if err := c.UserLoginHistoryRepository.Create(tx, userLoginHistory); err != nil {
		c.Log.Warnf("Failed create user login history to database : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	event := converter.UserToEvent(user)
	c.Log.Info("Publishing user created event")
	if err := c.UserProducer.Send(event); err != nil {
		c.Log.Warnf("Failed publish user created event : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	return converter.UserToLoginResponse(user, accessToken, refreshTokenID, AccessExpiry), nil
}

func (c *UserUseCase) Refresh(ctx context.Context, request *model.RefreshTokenRequest) (*model.RefreshTokenResponse, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	// Validasi input
	if err := c.Validate.Struct(request); err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return nil, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	// Cek apakah token ini sudah digunakan sebelumnya
	isUsed, err := c.TokenUseCase.IsTokenUsed(request.ID)
	if err != nil {
		c.Log.Warnf("Failed to check if token is used : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if isUsed {
		c.Log.Warnf("Token already used")
		return nil, fiber.ErrUnauthorized
	}

	// Ambil token dari Redis
	token, err := c.TokenUseCase.GetToken(request.ID)
	if err != nil {
		c.Log.Warnf("Failed to get token : %+v", err)
		return nil, fiber.ErrUnauthorized
	}

	// Cek TTL token
	if ttl := c.TokenUseCase.GetTTLOfToken(request.ID); ttl <= 0 {
		c.Log.Warnf("Token expired")
		return nil, fiber.ErrUnauthorized
	}

	// Validasi isi token
	auth, err := c.TokenUseCase.ValidateToken(token)
	if err != nil {
		c.Log.Warnf("Failed to validate token : %+v", err)
		return nil, fiber.ErrUnauthorized
	}

	// Generate token baru
	accessToken, refreshToken, refreshTokenID, accessExpiry, err := c.TokenUseCase.GenerateToken(auth.ID, auth.Role)
	if err != nil {
		c.Log.Warnf("Failed to generate token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// Tandai token lama sebagai "used"
	if err := c.TokenUseCase.MarkTokenAsUsed(request.ID); err != nil {
		c.Log.Warnf("Failed to mark token as used : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// Simpan refresh token baru
	if err := c.TokenUseCase.StoreToken(refreshToken, refreshTokenID, auth.ID); err != nil {
		c.Log.Warnf("Failed to store new token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// Optional: publish event (misalnya untuk log login atau notifikasi)
	user := &entity.User{ID: auth.ID}
	user.Token = accessToken

	if err := c.UserProducer.Send(converter.UserToEvent(user)); err != nil {
		c.Log.Warnf("Failed to publish event : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// Kirim ke client
	return &model.RefreshTokenResponse{
		RefreshTokenID: refreshTokenID,
		AccessToken:    accessToken,
		AccessExpiry:   accessExpiry,
	}, nil
}

func (c *UserUseCase) FindByID(ctx context.Context, request *model.GetUserRequest) (*model.UserResponse, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return nil, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	user := new(entity.User)
	if err := c.UserRepository.FindById(tx, user, request.ID); err != nil {
		c.Log.Warnf("Failed find user by id in FindByID : %+v", err)
		return nil, fiber.ErrNotFound
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	return converter.UserToResponse(user), nil
}

func (c *UserUseCase) Search(ctx context.Context, request *model.SearchUserRequest) ([]model.UserResponse, int64, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return nil, 0, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	users, total, err := c.UserRepository.Search(tx, request)
	if err != nil {
		c.Log.Warnf("Failed search user : %+v", err)
		return nil, 0, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, 0, fiber.ErrInternalServerError
	}

	response := make([]model.UserResponse, len(users))
	for i, user := range users {
		response[i] = *converter.UserToResponse(&user)
	}

	return response, total, nil

}

func (c *UserUseCase) Update(ctx context.Context, request *model.UpdateUserRequest) (*model.UserResponse, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return nil, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	user := new(entity.User)
	if err := c.UserRepository.FindById(tx, user, request.ID); err != nil {
		c.Log.Warnf("Failed find user by id In Update : %+v", err)
		return nil, fiber.ErrNotFound
	}

	user.Email = request.Email

	if err := c.UserRepository.Update(tx, user); err != nil {
		c.Log.Warnf("Failed save user : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	event := converter.UserToEvent(user)
	c.Log.Info("Publishing user created event")
	if err := c.UserProducer.Send(event); err != nil {
		c.Log.Warnf("Failed publish user created event : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	return converter.UserToResponse(user), nil
}

func (c *UserUseCase) ForgotPassword(ctx context.Context, request *model.ForgotPasswordRequest) (bool, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return false, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	user := new(entity.User)
	if err := c.UserRepository.FindByEmail(tx, user, request.Email); err != nil {
		c.Log.Warnf("Failed find user by email : %+v", err)
		return false, fiber.ErrNotFound
	}

	// generate token
	token, err := util.GenerateToken(32)
	if err != nil {
		c.Log.Warnf("Failed generate token : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	user.PasswordResetToken = &token

	if err := c.UserRepository.Update(tx, user); err != nil {
		c.Log.Warnf("Failed save user : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	// link verification
	linkVerification := fmt.Sprintf("%s://%s:%s/api/v1/reset-password?id=%s&token=%s",
		c.Viper.GetString("WEB_PROTOCOL"),
		c.Viper.GetString("WEB_HOST"),
		c.Viper.GetString("WEB_PORT"),
		user.ID,
		*user.PasswordResetToken)

	// nanti akan dikirimkan email lewat kafka di sini
	notifEvent := &model.NotificationEvent{
		ID:         user.ID,
		Email:      user.Email,
		TemplateID: "reset_password",
		Type:       "reset_password",
		Data: map[string]interface{}{
			"reset_link": linkVerification,
		},
	}

	c.Log.Info("Publishing notification event")
	if err = c.NotificationProducer.Send(notifEvent); err != nil {
		c.Log.Warnf("Failed publish notification event : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	return true, nil
}

func (c *UserUseCase) ResetPassword(ctx context.Context, request *model.ResetPasswordRequest) (bool, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return false, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	user := new(entity.User)
	if err := c.UserRepository.FindById(tx, user, request.ID); err != nil {
		c.Log.Warnf("Failed find user by id In ResetPassword : %+v", err)
		return false, fiber.ErrNotFound
	}

	if user.PasswordResetToken == nil {
		c.Log.Warnf("Password reset token not found")
		return false, fiber.ErrNotFound
	}

	if *user.PasswordResetToken != request.Token {
		c.Log.Warnf("Invalid password reset token")
		return false, fiber.ErrUnauthorized
	}

	password, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Log.Warnf("Failed to generate bcrype hash : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	user.Password = string(password)
	user.PasswordResetToken = nil

	if err := c.UserRepository.Update(tx, user); err != nil {
		c.Log.Warnf("Failed save user : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	event := converter.UserToEvent(user)
	c.Log.Info("Publishing user created event")
	if err := c.UserProducer.Send(event); err != nil {
		c.Log.Warnf("Failed publish user created event : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	return true, nil
}

func (c *UserUseCase) Logout(ctx context.Context, request *model.LogoutUserRequest) (bool, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return false, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	// check if token is used
	isUsed, err := c.TokenUseCase.IsTokenUsed(request.ID)
	if err != nil {
		c.Log.Warnf("Failed to check if token is used : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	if isUsed {
		c.Log.Warnf("Token already used")
		return false, fiber.ErrUnauthorized
	}

	// mark token as used
	if err := c.TokenUseCase.MarkTokenAsUsed(request.ID); err != nil {
		c.Log.Warnf("Failed to mark token as used : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	c.Log.Infof("User logged out successfully, token ID: %s", request.ID)

	return true, nil
}

func (c *UserUseCase) LogoutAll(ctx context.Context, request *model.LogoutAllUserRequest) (bool, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return false, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	if err := c.TokenUseCase.DeleteAllTokenMember(request.UserID); err != nil {
		c.Log.Warnf("Failed to delete all token : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	c.Log.Infof("User logged out successfully, user ID: %s", request.UserID)

	return true, nil
}

func (c *UserUseCase) ChangeRole(ctx context.Context, request *model.ChangeRoleRequest) (bool, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return false, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	user := new(entity.User)
	if err := c.UserRepository.FindById(tx, user, request.ID); err != nil {
		c.Log.Warnf("Failed find user by id In ChangeRole : %+v", err)
		return false, fiber.ErrNotFound
	}

	user.Role = request.Role

	if err := c.UserRepository.Update(tx, user); err != nil {
		c.Log.Warnf("Failed save user : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	event := converter.UserToEvent(user)
	c.Log.Info("Publishing user created event")
	if err := c.UserProducer.Send(event); err != nil {
		c.Log.Warnf("Failed publish user created event : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	return true, nil
}

func (c *UserUseCase) SoftDelete(ctx context.Context, request *model.DeleteUserRequest) (bool, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		validationErrors := common.FormatValidationError(err, reflect.TypeOf(*request))
		return false, fiber.NewError(fiber.StatusBadRequest, util.MapToJSON(validationErrors))
	}

	user := new(entity.User)
	if err := c.UserRepository.FindById(tx, user, request.ID); err != nil {
		c.Log.Warnf("Failed find user by id in SoftDelete : %+v", err)
		return false, fiber.ErrNotFound
	}

	user.IsDeleted = true

	if err := c.UserRepository.Update(tx, user); err != nil {
		c.Log.Warnf("Failed save user : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	event := converter.UserToEvent(user)
	c.Log.Info("Publishing user created event")
	if err := c.UserProducer.Send(event); err != nil {
		c.Log.Warnf("Failed publish user created event : %+v", err)
		return false, fiber.ErrInternalServerError
	}

	return true, nil
}
