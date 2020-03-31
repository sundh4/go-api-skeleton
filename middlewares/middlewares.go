package middlewares

import (
	"go-api-skeleton/auth"
	"net/http"

	"github.com/gin-gonic/gin"

	msg "go-api-skeleton/utils"
)

// TokenAuthMiddleware function
func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := auth.TokenValid(c.Request)
		if err != nil {
			resp := msg.Message(false, "You need to be authorized to access this route!")
			resp["value"] = "{}"
			c.JSON(http.StatusUnauthorized, gin.H(resp))
			c.Abort()
			return
		}
		c.Next()
	}
}
