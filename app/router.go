package app

import (
	"go-api-skeleton/controller"
	"go-api-skeleton/middlewares"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "go-api-skeleton/docs" // swagger doc
)

func route() {
	router.HandleMethodNotAllowed = true
	//router.POST("/todo", middlewares.TokenAuthMiddleware(), controller.CreateTodo)
	v1 := router.Group("/api/v1")
	user := v1.Group("/user")
	user.POST("/register", controller.CreateUser)                                                // Register
	user.POST("/login", controller.Login)                                                        // Login
	user.POST("/logout", middlewares.TokenAuthMiddleware(), controller.LogOut)                   // Logout
	user.GET("/profile", middlewares.TokenAuthMiddleware(), controller.GetProfile)               // Get current profile
	user.POST("/profile", middlewares.TokenAuthMiddleware(), controller.UpdateProfile)           // Update current profile
	user.GET("/profile/:iduser", middlewares.TokenAuthMiddleware(), controller.GetProfileID)     // Get profile by User ID
	user.POST("/profile/:iduser", middlewares.TokenAuthMiddleware(), controller.UpdateProfileID) // Update profile by User ID
	user.POST("/password", middlewares.TokenAuthMiddleware(), controller.ChangePassword)         // Change password
	user.GET("/confirm", controller.ConfirmUser)                                                 // Confirm user based on secret token
	router.GET("/", controller.Index)                                                            // Root index
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))                    // Swagger ui
}
