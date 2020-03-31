package model

import (
	"go-api-skeleton/auth"

	"github.com/twinj/uuid"
)

// Auth structure
type Auth struct {
	ID       uint64 `gorm:"primary_key;auto_increment" json:"id"`
	UserID   uint64 `gorm:";not null;" json:"user_id"`
	AuthUUID string `gorm:"size:255;not null;" json:"auth_uuid"`
}

// FetchAuth function
func (s *Server) FetchAuth(authD *auth.Details) (*Auth, error) {
	au := &Auth{}
	err := s.DB.Debug().Where("user_id = ? AND auth_uuid = ?", authD.UserID, authD.AuthUUID).Take(&au).Error
	if err != nil {
		return nil, err
	}
	return au, nil
}

// DeleteAuth Once a user row in the auth table
func (s *Server) DeleteAuth(authD *auth.Details) error {
	au := &Auth{}
	db := s.DB.Debug().Where("user_id = ? AND auth_uuid = ?", authD.UserID, authD.AuthUUID).Take(&au).Delete(&au)
	if db.Error != nil {
		return db.Error
	}
	return nil
}

// CreateAuth Once the user signup/login, create a row in the auth table, with a new uuid
func (s *Server) CreateAuth(userID uint64) (*Auth, error) {
	au := &Auth{}
	au.AuthUUID = uuid.NewV4().String() //generate a new UUID each time
	au.UserID = userID
	err := s.DB.Debug().Create(&au).Error
	if err != nil {
		return nil, err
	}
	return au, nil
}
