package usecase

import (
	"auth-user-api/internal/entity"
	"auth-user-api/internal/model"
	"auth-user-api/internal/model/converter"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

type GithubUseCase struct {
	DB                    *gorm.DB
	Log                   *logrus.Logger
	Validate              *validator.Validate
	UserUseCase           *UserUseCase
	UserAuthMethodUseCase *UserAuthMethodUseCase
	Viper                 *viper.Viper
}

func NewGithubUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate, viper *viper.Viper, userUseCase *UserUseCase, userAuthMethodUseCase *UserAuthMethodUseCase) *GithubUseCase {
	return &GithubUseCase{
		DB:                    db,
		Log:                   log,
		Validate:              validate,
		Viper:                 viper,
		UserUseCase:           userUseCase,
		UserAuthMethodUseCase: userAuthMethodUseCase,
	}
}

func (g *GithubUseCase) Login() (string, error) {
	clientID := g.Viper.GetString("GITHUB_CLIENT_ID")
	redirectURI := g.Viper.GetString("GITHUB_REDIRECT_URI")

	if clientID == "" || redirectURI == "" {
		g.Log.Error("GitHub OAuth config not set properly")
		return "", fmt.Errorf("GitHub OAuth config missing")
	}

	url := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=user", clientID, redirectURI)
	g.Log.Infof("GitHub login URL: %s", url)
	return url, nil
}

func (g *GithubUseCase) Callback(ctx context.Context, request *model.GithubLoginRequest) (*model.UserResponse, error) {
	clientID := g.Viper.GetString("GITHUB_CLIENT_ID")
	clientSecret := g.Viper.GetString("GITHUB_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		g.Log.Error("GitHub OAuth config not set properly")
		return nil, fmt.Errorf("GitHub OAuth config missing")
	}

	resp, err := http.PostForm("https://github.com/login/oauth/access_token", url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {request.Code},
	})
	if err != nil {
		g.Log.Errorf("Failed to request access token: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		g.Log.Errorf("GitHub token exchange failed, status code: %d", resp.StatusCode)
		return nil, fmt.Errorf("GitHub token exchange failed")
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		g.Log.Errorf("Failed to read response body: %v", err)
		return nil, err
	}

	values, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		g.Log.Errorf("Failed to parse access token response: %v", err)
		return nil, err
	}

	accessToken := values.Get("access_token")
	if accessToken == "" {
		g.Log.Error("Access token is empty")
		return nil, fmt.Errorf("access token not found")
	}

	// get user info
	userInfo, err := g.GetUserInfo(accessToken)
	if err != nil {
		g.Log.Errorf("Failed to get user info: %v", err)
		return nil, err
	}

	if userInfo.Email == "" {
		g.Log.Error("GitHub user email not found")
		return nil, fmt.Errorf("GitHub email not available, please make your email public on GitHub")
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
				AuthMethod:     "github",
				AuthIdentifier: strconv.Itoa(userInfo.ID),
			}

			log.Println("userAuthMethod", register)

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
			AuthMethod:     "github",
			AuthIdentifier: strconv.Itoa(userInfo.ID),
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

	g.Log.Infof("Access token: %s", accessToken)
	return converter.UserToLoginResponse(user, login.AccessToken, login.RefreshTokenID, login.AccessExpiry), nil
}

func (g *GithubUseCase) GetUserInfo(accessToken string) (*model.GithubUser, error) {
	client := &http.Client{
		Timeout: 5 * time.Second, // Set a timeout for the request to avoid hanging indefinitely
	}

	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		g.Log.Errorf("Failed to create request: %v", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		g.Log.Errorf("Failed to get user info: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		g.Log.Errorf("GitHub user info failed: %d, body: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("GitHub user info failed")
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		g.Log.Errorf("Failed to read response body: %v", err)
		return nil, err
	}

	var userInfo *model.GithubUser
	err = json.Unmarshal(bodyBytes, &userInfo)

	if err != nil {
		g.Log.Errorf("Failed to parse user info response: %v", err)
		return nil, err
	}

	if userInfo.Email == "" {
		req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
		if err != nil {
			g.Log.Errorf("Failed to create request: %v", err)
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)
		resp, err := client.Do(req)
		if err != nil {
			g.Log.Errorf("Failed to get user emails: %v", err)
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			g.Log.Errorf("GitHub user emails failed: %d, body: %s", resp.StatusCode, string(body))
			return nil, fmt.Errorf("GitHub user emails failed")
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			g.Log.Errorf("Failed to read response body: %v", err)
			return nil, err
		}

		var emails []model.GithubEmail
		err = json.Unmarshal(bodyBytes, &emails)
		if err != nil {
			g.Log.Errorf("Failed to parse user emails response: %v", err)
			return nil, err
		}

		if len(emails) == 0 {
			g.Log.Error("No email found for user")
			return nil, fmt.Errorf("no email found for user")
		}

		// Prioritaskan email yang primary dan verified
		for _, e := range emails {
			if e.Primary && e.Verified {
				userInfo.Email = e.Email
				break
			}
		}

		// Kalau belum ketemu, ambil yang pertama aja
		if userInfo.Email == "" {
			userInfo.Email = emails[0].Email
		}
	}

	return userInfo, nil
}
