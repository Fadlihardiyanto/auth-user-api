package config

import (
	"auth-user-api/internal/delivery/http"
	"auth-user-api/internal/delivery/http/middleware"
	"auth-user-api/internal/delivery/http/route"
	"auth-user-api/internal/gateway/messaging"
	"auth-user-api/internal/model"
	"auth-user-api/internal/repository"
	"auth-user-api/internal/usecase"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

type BootstrapConfig struct {
	DB        *gorm.DB
	App       *fiber.App
	Log       *logrus.Logger
	Validate  *validator.Validate
	Config    *viper.Viper
	Producer  *kafka.Producer
	Redis     *redis.Client
	JWTConfig *model.JWTConfig
}

func Bootstrap(config *BootstrapConfig) {

	// setup repositories
	userRepository := repository.NewUserRepository(config.Log)
	profileRepository := repository.NewProfileRepository(config.Log)
	userLoginHistoryRepository := repository.NewUserLoginHistoryRepository(config.Log)
	UserAuthMethodRepository := repository.NewUserAuthMethodRepository(config.Log)

	// setup producer
	userProducer := messaging.NewUserProducer(config.Producer, config.Log)
	notifcationProducer := messaging.NewNotificationProducer(config.Producer, config.Log)
	profileProducer := messaging.NewProfileProducer(config.Producer, config.Log)

	// setup use cases
	tokenUseCase := usecase.NewTokenUseCase(config.JWTConfig, config.Redis, config.Log)
	userUseCase := usecase.NewUserUseCase(config.DB, config.Log, config.Validate, userRepository, userLoginHistoryRepository, UserAuthMethodRepository, userProducer, notifcationProducer, config.Redis, tokenUseCase, config.Config)
	profileUseCase := usecase.NewProfileUseCase(config.DB, config.Log, config.Validate, profileRepository, profileProducer)
	userLoginHistoryUserCase := usecase.NewUserLoginHistoryUsecase(config.DB, config.Log, config.Validate, userLoginHistoryRepository)
	userAuthMethodUseCase := usecase.NewUserAuthMethodUseCase(config.DB, config.Log, config.Validate, UserAuthMethodRepository)
	githubUsecase := usecase.NewGithubUseCase(config.DB, config.Log, config.Validate, config.Config, userUseCase, userAuthMethodUseCase)
	googleUsecase := usecase.NewGoogleUsecase(config.DB, config.Log, config.Validate, config.Config, userUseCase, userAuthMethodUseCase)

	// setup controller
	AuthController := http.NewAuthController(userUseCase, githubUsecase, googleUsecase, config.Log)
	UserControlerr := http.NewUserController(userUseCase, config.Log)
	ProfileController := http.NewProfileController(profileUseCase, config.Log)
	UserLoginHistoryController := http.NewUserLoginHistoryController(userLoginHistoryUserCase, config.Log)
	UserAuthMethodController := http.NewUserAuthMethodController(userAuthMethodUseCase, config.Log)

	// setup middleware
	authMiddleware := middleware.NewAuth(tokenUseCase, userUseCase)

	routeConfig := route.RouteConfig{
		App:                        config.App,
		AuthController:             AuthController,
		AuthMiddleware:             authMiddleware,
		UserController:             UserControlerr,
		ProfileController:          ProfileController,
		UserLoginHistoryController: UserLoginHistoryController,
		UserAuthMethodController:   UserAuthMethodController,
	}
	routeConfig.Setup()
}
