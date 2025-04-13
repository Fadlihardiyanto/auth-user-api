package http

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	common "auth-user-api/internal/common/error"
	"auth-user-api/internal/delivery/http/middleware"
	"auth-user-api/internal/model"
	"auth-user-api/internal/usecase"

	"github.com/google/uuid"
	"github.com/ua-parser/uap-go/uaparser"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type AuthController struct {
	Log           *logrus.Logger
	UseCase       *usecase.UserUseCase
	GithubUseCase *usecase.GithubUseCase
}

func NewAuthController(useCase *usecase.UserUseCase, githubUseCase *usecase.GithubUseCase, logger *logrus.Logger) *AuthController {
	return &AuthController{
		Log:           logger,
		UseCase:       useCase,
		GithubUseCase: githubUseCase,
	}
}

func (c *AuthController) Register(ctx *fiber.Ctx) error {
	request := new(model.RegisterUserRequest)
	err := ctx.BodyParser(request)
	if err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	// make uuid
	request.ID = uuid.New().String()

	_, err = c.UseCase.Create(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to register user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.JSON(model.WebResponse[*string]{
		// Data:    response,
		Message: "Successfully registered please check your email to verify your account",
	})
}

func (c *AuthController) Verify(ctx *fiber.Ctx) error {
	id := ctx.Query("id")
	token := ctx.Query("token")

	request := &model.VerifyUserRequest{
		ID:    id,
		Token: token,
	}

	response, err := c.UseCase.Verify(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	if response {
		return ctx.JSON(model.WebResponse[*string]{
			Message: "Successfully verified user",
		})
	}

	return ctx.JSON(model.WebResponse[*string]{
		Message: "Failed to verify user",
	})
}

func (c *AuthController) ForgotPassword(ctx *fiber.Ctx) error {
	request := new(model.ForgotPasswordRequest)
	err := ctx.BodyParser(request)
	if err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	response, err := c.UseCase.ForgotPassword(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	if response {
		return ctx.JSON(model.WebResponse[*string]{
			Message: "Successfully sent email",
		})
	}

	return ctx.JSON(model.WebResponse[*string]{
		Message: "Failed to send email",
	})
}

func (c *AuthController) ResetPassword(ctx *fiber.Ctx) error {
	token := ctx.Query("token")
	id := ctx.Query("id")

	request := new(model.ResetPasswordRequest)
	err := ctx.BodyParser(request)
	if err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	request.ID = id
	request.Token = token

	response, err := c.UseCase.ResetPassword(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	if response {
		return ctx.JSON(model.WebResponse[*string]{
			Message: "Successfully reset password",
		})
	}

	return ctx.JSON(model.WebResponse[*string]{
		Message: "Failed to reset password",
	})
}

func (c *AuthController) Login(ctx *fiber.Ctx) error {
	request := new(model.LoginUserRequest)
	err := ctx.BodyParser(request)
	if err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	// get ip address
	ip := ctx.IP()
	if ip == "" {
		c.Log.Warnf("Failed to get ip address")
		return fiber.ErrBadRequest
	}
	device := ctx.Get("User-Agent")
	if device == "" {
		c.Log.Warnf("Failed to get device info")
		return fiber.ErrBadRequest
	}

	parser := uaparser.NewFromSaved()
	ua := parser.Parse(device)

	deviceInfo := map[string]string{
		"user_agent": ctx.Get("User-Agent"),
		"os":         strings.TrimSpace(fmt.Sprintf("%s %s", ua.Os.Family, ua.Os.Major)),
		"browser":    ua.UserAgent.Family + " " + ua.UserAgent.Major,
		"device":     ua.Device.Family,
	}
	deviceJson, _ := json.Marshal(deviceInfo)

	request.IpAddress = ip
	request.DeviceInfo = deviceJson

	response, err := c.UseCase.Login(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	// set cookie
	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    response.AccessToken,
		Expires:  response.AccessExpiry,
		HTTPOnly: true,
		Secure:   true,
	})

	return ctx.JSON(model.WebResponse[*model.UserResponse]{Data: response})
}

func (c *AuthController) Current(ctx *fiber.Ctx) error {
	auth := middleware.GetUser(ctx)

	request := &model.GetUserRequest{
		ID: auth.ID,
	}

	response, err := c.UseCase.FindByID(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.JSON(model.WebResponse[*model.UserResponse]{Data: response})
}

func (c *AuthController) FindByID(ctx *fiber.Ctx) error {
	id := ctx.Params("id")

	request := &model.GetUserRequest{
		ID: id,
	}

	response, err := c.UseCase.FindByID(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	return ctx.JSON(model.WebResponse[*model.UserResponse]{Data: response})
}

func (c *AuthController) Refresh(ctx *fiber.Ctx) error {
	request := new(model.RefreshTokenRequest)
	if err := ctx.BodyParser(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	response, err := c.UseCase.Refresh(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	// set cookie
	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    response.AccessToken,
		Expires:  response.AccessExpiry,
		HTTPOnly: true,
		Secure:   true,
	})

	return ctx.JSON(model.WebResponse[*model.RefreshTokenResponse]{Data: response})
}

func (c *AuthController) Update(ctx *fiber.Ctx) error {
	auth := middleware.GetUser(ctx)

	request := new(model.UpdateUserRequest)
	if err := ctx.BodyParser(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	request.ID = auth.ID
	response, err := c.UseCase.Update(ctx.UserContext(), request)
	if err != nil {
		c.Log.WithError(err).Warnf("Failed to update user")
		return err
	}

	// set cookie
	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    response.AccessToken,
		Expires:  time.Now().Add(time.Hour * 24), // Expires in 24 hours
		HTTPOnly: true,
		Secure:   true,
	})

	return ctx.JSON(model.WebResponse[*model.UserResponse]{Data: response})
}

func (c *AuthController) Logout(ctx *fiber.Ctx) error {

	request := new(model.LogoutUserRequest)
	err := ctx.BodyParser(request)
	if err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	response, err := c.UseCase.Logout(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	var data string
	if response {
		cookie := fiber.Cookie{
			Name:     "jwt",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			Secure:   true,
		}
		ctx.Cookie(&cookie)
		data = "Successfully logged out"
	}

	return ctx.JSON(model.WebResponse[*string]{Message: data})
}

func (c *AuthController) LogoutAll(ctx *fiber.Ctx) error {

	request := new(model.LogoutAllUserRequest)
	err := ctx.BodyParser(request)
	if err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	response, err := c.UseCase.LogoutAll(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to login user : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	var data string
	if response {
		cookie := fiber.Cookie{
			Name:     "jwt",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			Secure:   true,
		}
		ctx.Cookie(&cookie)
		data = "Successfully logged out from all devices"
	}

	return ctx.JSON(model.WebResponse[string]{Data: data})
}

func (c *AuthController) GithubLogin(ctx *fiber.Ctx) error {
	url, err := c.GithubUseCase.Login()
	if err != nil {
		c.Log.Warnf("Failed to get github login url : %+v", err)
		return fiber.ErrBadRequest
	}
	return ctx.Redirect(url, fiber.StatusTemporaryRedirect)
}

func (c *AuthController) GithubCallback(ctx *fiber.Ctx) error {
	code := ctx.Query("code")
	if code == "" {
		c.Log.Warnf("Failed to get code from github")
		return fiber.ErrBadRequest
	}

	// get ip address
	ip := ctx.IP()
	if ip == "" {
		c.Log.Warnf("Failed to get ip address")
		return fiber.ErrBadRequest
	}
	device := ctx.Get("User-Agent")
	if device == "" {
		c.Log.Warnf("Failed to get device info")
		return fiber.ErrBadRequest
	}

	parser := uaparser.NewFromSaved()
	ua := parser.Parse(device)

	deviceInfo := map[string]string{
		"user_agent": ctx.Get("User-Agent"),
		"os":         strings.TrimSpace(fmt.Sprintf("%s %s", ua.Os.Family, ua.Os.Major)),
		"browser":    ua.UserAgent.Family + " " + ua.UserAgent.Major,
		"device":     ua.Device.Family,
	}
	deviceJson, _ := json.Marshal(deviceInfo)

	request := &model.GithubLoginRequest{
		Code:       code,
		IpAddress:  ip,
		DeviceInfo: deviceJson,
	}

	response, err := c.GithubUseCase.Callback(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to get github callback : %+v", err)
		return common.HandleErrorResponse(ctx, err)
	}

	// set cookie
	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    response.AccessToken,
		Expires:  response.AccessExpiry,
		HTTPOnly: true,
		Secure:   true,
	})

	return ctx.JSON(model.WebResponse[*model.UserResponse]{Data: response})
}
