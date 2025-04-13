package route

import (
	"auth-user-api/internal/delivery/http"
	"auth-user-api/internal/delivery/http/middleware"

	"github.com/gofiber/fiber/v2"
)

type RouteConfig struct {
	App                        *fiber.App
	AuthController             *http.AuthController
	UserController             *http.UserController
	ProfileController          *http.ProfileController
	UserLoginHistoryController *http.UserLoginHistoryController
	UserAuthMethodController   *http.UserAuthMethodController
	AuthMiddleware             fiber.Handler
}

func (c *RouteConfig) Setup() {
	group := c.App.Group("/api/v1")

	// public route
	c.SetupGuestRoute(group)

	// auth middleware
	c.App.Use(c.AuthMiddleware)

	// auth route
	c.SetupAuthRoute(group)
}

func (c *RouteConfig) SetupGuestRoute(group fiber.Router) {
	// redirect to /api
	c.App.Get("/", func(ctx *fiber.Ctx) error {
		return ctx.Redirect("/api")
	})

	c.App.Get("/api", func(ctx *fiber.Ctx) error {
		return ctx.SendString("Welcome to auth-user-api")
	})

	group.Post("/register", c.AuthController.Register)
	group.Get("/verify", c.AuthController.Verify)
	group.Post("/login", c.AuthController.Login)
	group.Post("/refresh", c.AuthController.Refresh)
	group.Post("/forgot-password", c.AuthController.ForgotPassword)
	group.Post("/reset-password", c.AuthController.ResetPassword)

	// github auth
	group.Get("/auth/github", c.AuthController.GithubLogin)
	group.Get("/auth/github/callback", c.AuthController.GithubCallback)

}

func (c *RouteConfig) SetupAuthRoute(group fiber.Router) {

	// user login
	group.Patch("/users/current", c.AuthController.Update)
	group.Get("/users/current", c.AuthController.Current)
	group.Post("/logout", c.AuthController.Logout)
	group.Post("/logout-all", c.AuthController.LogoutAll)

	// user
	group.Get("/users", middleware.RoleMiddleware("admin"), c.UserController.List)
	group.Get("/users/:id", c.UserController.FindById)
	group.Put("/users/:id", c.UserController.Update)
	group.Delete("/users/:id", middleware.RoleMiddleware("admin"), c.UserController.Delete)
	group.Patch("/users/change-role/:id", middleware.RoleMiddleware("admin"), c.UserController.ChangeRole)

	// profile
	profile := group.Group("/profile")
	profile.Get("/", c.ProfileController.List)
	profile.Post("/", c.ProfileController.Create)
	profile.Put("/:id", c.ProfileController.Update)
	profile.Get("/:id", c.ProfileController.Get)
	profile.Delete("/:id", c.ProfileController.Delete)

	// user login history
	group.Get("/user-login-history", c.UserLoginHistoryController.List)

	// auth method
	group.Post("/user-auth-method", c.UserAuthMethodController.Create)
}
