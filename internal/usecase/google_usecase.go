package usecase

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"
	"auth-user-api/internal/model/converter"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

type GoogleUseCase struct {
	DB                    *gorm.DB
	Log                   *logrus.Logger
	Validate              *validator.Validate
	Viper                 *viper.Viper
	UserUseCase           *UserUseCase
	UserAuthMethodUseCase *UserAuthMethodUseCase
}

func NewGoogleUsecase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate, viper *viper.Viper, userUseCase *UserUseCase, userAuthMethodUseCase *UserAuthMethodUseCase) *GoogleUseCase {
	return &GoogleUseCase{
		DB:                    db,
		Log:                   log,
		Validate:              validate,
		Viper:                 viper,
		UserUseCase:           userUseCase,
		UserAuthMethodUseCase: userAuthMethodUseCase,
	}
}

func (g *GoogleUseCase) getGoogleOauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  g.Viper.GetString("GOOGLE_REDIRECT_URI"),
		ClientID:     g.Viper.GetString("GOOGLE_CLIENT_ID"),
		ClientSecret: g.Viper.GetString("GOOGLE_CLIENT_SECRET"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/photoslibrary.readonly",
		},
		Endpoint: google.Endpoint,
	}
}

func (g *GoogleUseCase) Login() (string, error) {

	oauthConfig := g.getGoogleOauthConfig()
	authURL := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	g.Log.Infof("Google login URL: %s", authURL)
	return authURL, nil
}

func (g *GoogleUseCase) Callback(ctx context.Context, request *model.GoogleLoginRequest) (*model.UserResponse, error) {
	oauthConfig := g.getGoogleOauthConfig()

	// Exchange the authorization code for a token
	token, err := oauthConfig.Exchange(oauth2.NoContext, request.Code)
	if err != nil {
		g.Log.Errorf("Failed to exchange token: %v", err)
		return nil, err
	}

	// Create a new HTTP client using the token
	client := oauthConfig.Client(oauth2.NoContext, token)

	// Make a request to the Google API to get user info v2
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		g.Log.Errorf("Failed to get user info: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		g.Log.Errorf("Failed to get user info: %s", resp.Status)
		return nil, fmt.Errorf("failed to get user info: %s", resp.Status)
	}

	body, _ := io.ReadAll(resp.Body)

	var userInfo *model.GoogleUser
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		g.Log.Errorf("Failed to unmarshal user info: %v", err)
		return nil, err
	}

	if userInfo.Email == "" {
		g.Log.Error("Email is empty")
		return nil, fmt.Errorf("email is empty")
	}

	// check if user exists in database
	user := new(entity.User)
	var login *model.UserResponse

	err = g.UserUseCase.UserRepository.FindByEmail(g.DB, user, userInfo.Email)
	tx := g.DB.WithContext(ctx).Begin()
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	if err != nil {

		if err == gorm.ErrRecordNotFound {

			// user not found, create new user
			user.ID = uuid.New().String()
			user.Email = userInfo.Email

			registerRequest := &model.RegisterOauthUserRequest{
				ID:    uuid.New().String(),
				Email: userInfo.Email,
			}

			register, err := g.UserUseCase.CreateOauth(ctx, tx, registerRequest)
			if err != nil {
				g.Log.Errorf("Failed to create user: %v", err)
				return nil, err
			}
			g.Log.Infof("User created: %s", user.Email)

			// create user auth method
			userAuthMethod := &model.CreateUserAuthMethodRequest{
				UserID:         register.ID,
				AuthMethod:     "google",
				AuthIdentifier: userInfo.ID,
			}

			authMethod, err := g.UserAuthMethodUseCase.CreateWithTx(ctx, tx, userAuthMethod)
			if err != nil {
				g.Log.Errorf("Failed to create user auth method: %v", err)
				return nil, err
			}

			g.Log.Infof("User auth method created: %s", authMethod.AuthMethodIdentifier)

			// login user
			loginRequest := &model.LoginOauthUserRequest{
				Email:          user.Email,
				AuthMethod:     authMethod.AuthMethod,
				AuthIdentifier: authMethod.AuthMethodIdentifier,
				IpAddress:      request.IpAddress,
				DeviceInfo:     request.DeviceInfo,
			}

			login, err = g.UserUseCase.LoginOauth(ctx, tx, loginRequest)
			if err != nil {
				g.Log.Errorf("Failed to login user: %v", err)
				return nil, err
			}
			g.Log.Infof("User logged in: %s", login.AccessToken)

		} else {
			g.Log.Errorf("Failed to find user: %v", err)
			return nil, err
		}
	} else {
		g.Log.Infof("User already exists: %s", user.Email)

		// login user
		loginRequest := &model.LoginOauthUserRequest{
			Email:          user.Email,
			AuthMethod:     "google",
			AuthIdentifier: userInfo.ID,
			IpAddress:      request.IpAddress,
			DeviceInfo:     request.DeviceInfo,
		}

		login, err = g.UserUseCase.LoginOauth(ctx, tx, loginRequest)
		if err != nil {
			g.Log.Errorf("Failed to login user: %v", err)
			return nil, err
		}
		g.Log.Infof("User logged in: %s", login.AccessToken)
	}

	if err := tx.Commit().Error; err != nil {
		g.Log.Errorf("Failed to commit transaction: %v", err)
		return nil, err
	}

	committed = true

	g.Log.Infof("Access token: %s", login.AccessToken)
	return converter.UserToLoginResponse(user, login.AccessToken, login.RefreshTokenID, login.AccessExpiry), nil
}
