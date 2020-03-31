package app

import (
	"go-api-skeleton/model"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func init() {
	var err error
	err = godotenv.Load()
	if err != nil {
		log.Fatalf("Error getting env, %v", err)
	}
}

var router = gin.Default()

// StartApp func
func StartApp() {
	//var conn Connect
	dbdriver := os.Getenv("DB_DRIVER")
	username := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbhost := os.Getenv("DB_HOST")
	database := os.Getenv("DB_NAME")
	dbport := os.Getenv("DB_PORT")

	_, err := model.Model.Initialize(dbdriver, username, password, dbport, dbhost, database)
	if err != nil {
		log.Fatal("Error connecting to the database: ", err)
	}
	route()

	port := os.Getenv("SRV_PORT")
	host := os.Getenv("SRV_HOST")
	if port == "" {
		port = "8888"
	}
	if host == "" {
		host = "localhost"
	}
	log.Fatal(router.Run(host + ":" + port))
}
