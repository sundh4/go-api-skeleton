package main

import (
	"go-api-skeleton/app"
)

// @title Swagger for Go REST API
// @version 1.0.0
// @description For serve swagger ui

// @contact.name Surya
// @contact.url https://www.omitsindo.com
// @contact.email surya@omitsindo.com

// @tag.name User API
// @tag.description All user API operation

// @tag.name Auth API
// @tag.description Authentication user API

// @schemes https

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host go.omitsindo.com
// @BasePath /api/v1

// @securityDefinitions.apikey Bearer Token
// @in header
// @name Authorization

// @x-extension-openapi {"example": "value on a json format"}

func main() {
	app.StartApp()
}
