package model

import (
	"errors"
	"go-api-skeleton/utils"
	"regexp"

	"github.com/badoux/checkmail"
	"golang.org/x/crypto/bcrypt"
)

// User struct
type User struct {
	ID        uint64 `gorm:"primary_key;auto_increment" json:"-"`
	Username  string `gorm:"size:255;not null;unique" json:"username" example:"Username"`
	FirstName string `json:"firstName" example:"First name"`
	LastName  string `json:"lastName" example:"Last name"`
	Email     string `gorm:"size:255;not null;unique" json:"email" example:"surya@omitsindo.com"`
	Password  string `json:"password" example:"more than 6 char"`
	Status    uint   `json:"status" default:"3"`
}

// RegisUser struct
type RegisUser struct {
	Username  string `gorm:"size:255;not null;unique" json:"username" example:"Username"`
	FirstName string `json:"firstName" example:"First name"`
	LastName  string `json:"lastName" example:"Last name"`
	Email     string `gorm:"size:255;not null;unique" json:"email" example:"surya@omitsindo.com"`
	Password  string `json:"password" example:"more than 6 char"`
}

// TempUser struct
type TempUser struct {
	UserID uint64 `json:"userid"`                            // User id
	Status uint   `json:"status" default:"3"`                // Status of user based on table user, should be 3
	Token  []byte `json:"tempToken" example:"random string"` // One Time Token for user confirmation
}

// ProfileToken JWT
type ProfileToken struct {
	Profile
	Token string `json:"token"`
}

// Profile only
type Profile struct {
	UserID    uint64 `json:"userid"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	IsAdmin   uint   `json:"isAdmin" default:"0"`
	Status    uint   `json:"status" default:"3"`
}

// UpdateProfile only
type UpdateProfile struct {
	Email     string `json:"email" example:"surya@omitsindo.com"`
	FirstName string `json:"firstName" example:"leave empty if don't want to update"`
	LastName  string `json:"lastName" example:"leave empty if don't want to update"`
}

// Admin struct
type Admin struct {
	UserID  uint64 `gorm:"unique" json:"userid"`
	IsAdmin uint   `gorm:"size:1" json:"isAdmin"`
	Note    string `json:"note"`
}

// Password struct
type Password struct {
	OldPassword string `json:"oldPass"`
	NewPassword string `json:"newPass"`
}

// LoginUser struct
type LoginUser struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginEmail struct
type LoginEmail struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// FullData struct
type FullData struct {
	User
	IsAdmin uint `gorm:"size:1" json:"isAdmin"`
}

// ValidateEmail function
func (s *Server) ValidateEmail(email string) error {
	if email == "" {
		return errors.New("Email address is required")
	}
	if email != "" {
		if err := checkmail.ValidateFormat(email); err != nil {
			return errors.New("invalid email")
		}
	}
	return nil
}

var isStringAlphabetic = regexp.MustCompile(`^[a-zA-Z]+$`).MatchString

// ValidateUser function
func (s *Server) ValidateUser(username string) error {
	if username == "" && !isStringAlphabetic(username) {
		return errors.New("invalid username")
	}
	return nil
}

// ValidatePass string function
func (s *Server) ValidatePass(pass string) error {
	if len(pass) < 6 {
		return errors.New("password required")
	}
	return nil
}

// CreateUser function
func (s *Server) CreateUser(user *User, isadmin uint) (*TempUser, error) {
	// Assign status = 3 for default user creation
	var stat uint = 3
	user.Status = stat

	// Check if email address format valid and exist or not
	emailErr := s.ValidateEmail(user.Email)
	if emailErr != nil {
		return nil, emailErr
	}
	chkmail := s.DB.Debug().Where("email = ?", user.Email).Take(&user).Error
	if chkmail == nil {
		err := errors.New("Duplicate email")
		return nil, err
	}

	// Check user validity and exist or not
	userErr := s.ValidateUser(user.Username)
	if userErr != nil {
		return nil, userErr
	}
	chkuser := s.DB.Debug().Where("username = ?", user.Username).Take(&user).Error
	if chkuser == nil {
		err := errors.New("Duplicate user")
		return nil, err
	}
	// Check if password format valid or not
	passErr := s.ValidatePass(user.Password)
	if passErr != nil {
		return nil, passErr
	}

	// Create has password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hashedPassword)
	// Start DB transaction
	tx := s.DB.Debug().Begin()
	// Create user
	err := tx.Create(&user).Error
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	// Create admin user if isadmin = 1
	if isadmin == 1 {
		adm := &Admin{
			UserID:  user.ID,
			IsAdmin: isadmin,
		}
		err = tx.Create(&adm).Error
		if err != nil {
			tx.Rollback()
			err = errors.New("Admin Failed")
			return nil, err
		}
	}
	// Generate one time token for confirmation
	otp, _ := utils.GenOTP(user.ID, user.Username, user.Email)
	tmpUser := &TempUser{
		Token:  otp,
		UserID: user.ID,
		Status: user.Status,
	}
	err = tx.Create(&tmpUser).Error
	if err != nil {
		tx.Rollback()
		err = errors.New("create token failed")
		return nil, err
	}
	// Commit if all succeed
	tx.Commit()
	return tmpUser, nil
}

// AddAdmin function
func (s *Server) AddAdmin(adm *Admin) (*Admin, error) {
	_, idErr := s.GetUserByID(adm.UserID)
	if idErr != nil {
		return nil, idErr
	}
	addErr := s.DB.Debug().Create(&adm).Error
	if addErr != nil {
		err := errors.New("Admin Failed")
		return nil, err
	}
	return adm, nil
}

// GetTempToken function
func (s *Server) GetTempToken(uid uint64, status uint) ([]byte, error) {
	tmpUser := &TempUser{}
	err := s.DB.Debug().Model(&tmpUser).Where("user_id = ? AND status = ?", uid, status).Select("token").Take(&tmpUser).Error
	if err != nil {
		err := errors.New("token not exists")
		return nil, err
	}
	return tmpUser.Token, nil
}

// GetUserByEmail function
func (s *Server) GetUserByEmail(email string) (*FullData, error) {
	user := &FullData{}
	//err := s.DB.Debug().Where("email = ?", email).Take(&user).Error
	err := s.DB.Debug().Table("users").
		Select("users.id, users.username, users.email, users.first_name, users.last_name, users.password, users.status, IFNULL(admins.is_admin,0) as is_admin").
		Joins("LEFT JOIN admins ON admins.user_id = users.id").Where("email = ?", email).Take(&user).Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByName function
func (s *Server) GetUserByName(username string) (*FullData, error) {
	user := &FullData{}
	//err := s.DB.Debug().Where("username = ?", username).Take(&user).Error
	err := s.DB.Debug().Table("users").
		Select("users.id, users.username, users.email, users.first_name, users.last_name, users.password, users.status, IFNULL(admins.is_admin,0) as is_admin").
		Joins("LEFT JOIN admins ON admins.user_id = users.id").Where("username = ?", username).Take(&user).Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserDataByID function to get all data on users and admin
func (s *Server) GetUserDataByID(uid uint64) (*FullData, error) {
	user := &FullData{}
	err := s.DB.Debug().Table("users").
		Select("users.id, users.username, users.email, users.first_name, users.last_name, users.password, users.status, IFNULL(admins.is_admin,0) as is_admin").
		Joins("LEFT JOIN admins ON admins.user_id = users.id").Where("id = ?", uid).Take(&user).Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByID function to get data only for showing profile
func (s *Server) GetUserByID(uid uint64) (*Profile, error) {
	user := &Profile{
		UserID: uid,
	}
	err := s.DB.Debug().Table("users").
		Select("users.id, users.username, users.email, users.first_name, users.last_name, users.status, IFNULL(admins.is_admin,0) as is_admin").
		Joins("LEFT JOIN admins ON admins.user_id = users.id").Where("id = ?", uid).Take(&user).Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetAllUserByStatus function
func (s *Server) GetAllUserByStatus(status uint) (*User, error) {
	user := &User{}
	var err error
	if status == 0 {
		err = s.DB.Debug().Find(&user).Error
	} else {
		err = s.DB.Debug().Where("status = ?", status).Find(&user).Error
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetAdminStatus function
func (s *Server) GetAdminStatus(uid uint64) (*Admin, error) {
	adm := &Admin{}
	err := s.DB.Debug().Where("user_id = ? and is_admin = 1", uid).Take(&adm).Error
	if err != nil {
		return nil, err
	}
	return adm, nil
}

// UpdatePassword function
func (s *Server) UpdatePassword(uid uint64, newPwd string) (*User, error) {
	user := &User{
		Password: newPwd,
	}
	err := s.DB.Debug().Model(&user).Where("id = ?", uid).Update(&user).Error
	if err != nil {
		return nil, errors.New("update pass failed")
	}
	return user, nil
}

// ProfileUpdate function based on id
func (s *Server) ProfileUpdate(uid uint64, upd UpdateProfile) (*UpdateProfile, error) {
	// Check if email address format valid and exist or not
	if upd.Email != "" {
		if err := checkmail.ValidateFormat(upd.Email); err != nil {
			return nil, errors.New("invalid email")
		}
		// Check if email exist or not
		isExist, _ := Model.GetUserByEmail(upd.Email)
		if isExist != nil {
			return nil, errors.New("email exists")
		}

	}
	// Assign model
	pr := &UpdateProfile{
		Email:     upd.Email,
		FirstName: upd.FirstName,
		LastName:  upd.LastName,
	}
	err := s.DB.Debug().Model(&User{}).Where("id = ?", uid).Update(&pr).Error
	if err != nil {
		return nil, errors.New("update profile failed")
	}
	return pr, nil
}

// ConfirmUserAcc function based on id
func (s *Server) ConfirmUserAcc(uid uint64, user, mail string) (*Profile, error) {
	u := &User{
		ID:       uid,
		Username: user,
		Email:    mail,
		Status:   1,
	}
	tmp := &TempUser{
		UserID: uid,
	}
	// Start DB transaction
	tx := s.DB.Debug().Begin()

	err := tx.Model(&u).Where("username = ? AND email = ?", user, mail).Update(&u).Error
	if err != nil {
		tx.Rollback()
		return nil, errors.New("failed confirm")
	}
	// delete temp_users
	err = tx.Where("user_id = ?", uid).Delete(&tmp).Error
	if err != nil {
		tx.Rollback()
		return nil, errors.New("failed confirm")
	}
	//commit transaction
	tx.Commit()
	//Get user by id
	pr, _ := s.GetUserByID(uid)
	return pr, nil
}
