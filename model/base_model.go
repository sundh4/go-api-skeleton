package model

import (
	"fmt"
	"go-api-skeleton/auth"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"    // mysql driver
	_ "github.com/jinzhu/gorm/dialects/postgres" //postgres database driver
)

// Server type
type Server struct {
	DB *gorm.DB
}

// _
var (
	//Server now implements the modelInterface, so he can define its methods
	Model modelInterface = &Server{}
)

type modelInterface interface {
	//db initialization
	Initialize(Dbdriver, DbUser, DbPassword, DbPort, DbHost, DbName string) (*gorm.DB, error)

	//user methods
	ValidateEmail(string) error
	CreateUser(*User, uint) (*TempUser, error)
	GetUserByEmail(string) (*FullData, error)
	GetUserByName(string) (*FullData, error)
	GetUserDataByID(uint64) (*FullData, error)
	GetUserByID(uint64) (*Profile, error)
	ProfileUpdate(uint64, UpdateProfile) (*UpdateProfile, error)
	ConfirmUserAcc(uint64, string, string) (*Profile, error)

	//admin methods
	GetAdminStatus(uint64) (*Admin, error)
	AddAdmin(*Admin) (*Admin, error)

	//password methods
	UpdatePassword(uint64, string) (*User, error)

	//todo methods:
	CreateTodo(*Todo) (*Todo, error)

	//auth methods:
	FetchAuth(*auth.Details) (*Auth, error)
	DeleteAuth(*auth.Details) error
	CreateAuth(uint64) (*Auth, error)
	GetTempToken(uint64, uint) ([]byte, error)
}

// Initialize function
func (s *Server) Initialize(Dbdriver, DbUser, DbPassword, DbPort, DbHost, DbName string) (*gorm.DB, error) {
	var err error
	//PostgreSQL DSN
	//DBURL := fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=disable password=%s", DbHost, DbPort, DbUser, DbName, DbPassword)
	//MySQL DSN
	DBURL := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", DbUser, DbPassword, DbHost, DbPort, DbName)
	s.DB, err = gorm.Open(Dbdriver, DBURL)
	if err != nil {
		return nil, err
	}
	s.DB.Debug().AutoMigrate(
		&User{},
		&Auth{},
		&Todo{},
		&Admin{},
		&TempUser{},
	)
	return s.DB, nil
}
