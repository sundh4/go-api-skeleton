package controller

import (
	"go-api-skeleton/auth"
	"go-api-skeleton/model"
	"net/http"

	"github.com/gin-gonic/gin"
)

// CreateTodo function
func CreateTodo(c *gin.Context) {

	var td model.Todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	tokenAuth, err := auth.ExtractTokenAuth(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	foundAuth, err := model.Model.FetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = foundAuth.UserID
	todo, err := model.Model.CreateTodo(&td)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusCreated, todo)
}
