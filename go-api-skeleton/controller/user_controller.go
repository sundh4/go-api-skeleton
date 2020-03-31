package controller

import (
	"bytes"
	"go-api-skeleton/auth"
	"go-api-skeleton/model"
	"go-api-skeleton/utils"
	msg "go-api-skeleton/utils"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// CreateUser godoc
// @Summary Register a User
// @Description To add to admin, add param in url as ?isAdmin=true
// @tags User API
// @Accept  json
// @Produce  json
// @Param data body model.RegisUser true "User data"
// @param isAdmin query boolean false "Is admin true or false"
// @Security Bearer Token
// @Success 200 {array} model.Profile
// @Failure 500 {object} model.InErrResp "Many failure messages"
// @Router /user/register [post]
func CreateUser(c *gin.Context) {
	//path := c.Request.URL
	url := c.Request.Host
	var u model.User
	var adm model.Admin
	isAdmin := c.DefaultQuery("isAdmin", "false")
	if isAdmin != "false" && isAdmin != "true" {
		adm.IsAdmin = 0
		resp := msg.Message(false, "Invalid isAdmin param, only false or true!")
		resp["value"] = "{}"
		c.JSON(http.StatusInternalServerError, gin.H(resp))
		return
	} else if isAdmin == "true" {
		// Init IsAdmin value
		adm.IsAdmin = 1

		// Check token and admin
		tokenAuth, _ := auth.ExtractTokenAuth(c.Request)
		if tokenAuth == nil {
			resp := msg.Message(false, "Empty Token Header")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		}
		errTk, _ := CheckAdminByToken(tokenAuth)
		if errTk != nil {
			c.JSON(http.StatusUnauthorized, gin.H(errTk))
			return
		}
	}
	// Check json payload
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	user, err := model.Model.CreateUser(&u, adm.IsAdmin)
	/*
		Check the result of error
		if error not empty, switch case error handling
		if not just go to restponse
	*/
	if err != nil {
		switch err.Error() {
		case "Duplicate email":
			resp := msg.Message(false, "Email already used!")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		case "Email address is required":
			resp := msg.Message(false, "Email can't empty!")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		case "invalid email":
			resp := msg.Message(false, "Invalid email format!")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		case "Duplicate user":
			resp := msg.Message(false, "User already exists")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		case "invalid username":
			resp := msg.Message(false, "Username can't be empty or contain special char!")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		case "password required":
			resp := msg.Message(false, "Password can't be empty or less then 6 char")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		default:
			resp := msg.Message(false, "Internal server Error")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		}
	} else {
		// Assign profile value
		p := &model.Profile{
			UserID:    user.UserID,
			Username:  u.Username,
			Email:     u.Email,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			IsAdmin:   adm.IsAdmin,
			Status:    user.Status,
		}
		// encode token to hex
		tkEmail := utils.EncodeHex(user.Token)
		// assignt email content
		fullPath := "https://" + url + "/api/v1/user/confirm?s=" + tkEmail
		fullName := p.FirstName + " " + p.LastName
		mailSend := utils.SentConfirmEmail(fullName, p.Email, fullPath)
		if mailSend != nil {
			resp := msg.Message(false, "Sending Email Failed")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
		}
		resp := msg.Message(true, "User created")
		resp["value"] = p
		c.JSON(http.StatusOK, gin.H(resp))
		return
	}
}

// GetProfile godoc
// @Summary Get Current Profile
// @Description Only retrive profile for own user.
// @tags User API
// @Accept  json
// @Produce  json
// @Security Bearer Token
// @Success 200 {object} model.ProfileResp
// @Failure 401 {object} model.UnAuthResp "Unauthorize"
// @Failure 500 {object} model.InErrResp "Internal Server Error"
// @Router /user/profile [get]
func GetProfile(c *gin.Context) {
	// Token Validation
	tokenAuth, _ := auth.ExtractTokenAuth(c.Request)
	errTk, userid := CheckTokenOnly(tokenAuth)
	if errTk != nil {
		c.JSON(http.StatusUnauthorized, gin.H(errTk))
		return
	}

	// Check if user exist based on the user id
	pr, err := model.Model.GetUserByID(userid)
	if err != nil {
		resp := msg.Message(false, "Internal Server Error")
		resp["value"] = "{}"
		c.JSON(http.StatusInternalServerError, gin.H(resp))
		return
	}
	resp := msg.Message(true, "Profile exists")
	resp["value"] = pr
	c.JSON(http.StatusOK, gin.H(resp))
}

// GetProfileID godoc
// @Summary Get User Profile by UserID
// @Description Get user profile by id only for admin user
// @tags User API
// @Accept  json
// @Produce  json
// @Param id path uint64 true "UserID"
// @Security Bearer Token
// @Success 200 {object} model.ProfileResp
// @Failure 401 {object} model.UnAuthResp "Unauthorize, Need admin privileges"
// @Failure 500 {object} model.InErrResp "Internal Server Error"
// @Router /user/profile/{id} [get]
func GetProfileID(c *gin.Context) {
	// Assign path param
	iduser := c.Param("iduser")
	idUint, _ := strconv.ParseUint(iduser, 10, 64)
	// Check Admin
	tokenAuth, _ := auth.ExtractTokenAuth(c.Request)
	errTk, _ := CheckAdminByToken(tokenAuth)
	if errTk != nil {
		c.JSON(http.StatusUnauthorized, gin.H(errTk))
		return
	}

	// Check if user exist based on the user id
	pr, err := model.Model.GetUserByID(idUint)
	if err != nil {
		resp := msg.Message(false, "User not Found!")
		resp["value"] = "{}"
		c.JSON(http.StatusNotFound, gin.H(resp))
		return
	}
	resp := msg.Message(true, "Profile exists")
	resp["value"] = pr
	c.JSON(http.StatusOK, gin.H(resp))
}

// ChangePassword godoc
// @Summary Change Password
// @Description Change password for current user
// @tags User API
// @Accept  json
// @Produce  json
// @Security Bearer Token
// @Param data body model.Password true "Current and old password"
// @Success 200 {object} model.ProfileResp "Password changed"
// @Failure 400 {object} model.BadResp "Invalid payload/password"
// @Failure 401 {object} model.UnAuthResp "Unauthorize"
// @Failure 500 {object} model.InErrResp "Internal Server Error"
// @Router /user/password [post]
func ChangePassword(c *gin.Context) {
	// Token Validation
	tokenAuth, _ := auth.ExtractTokenAuth(c.Request)
	errTk, userid := CheckTokenOnly(tokenAuth)
	if errTk != nil {
		c.JSON(http.StatusUnauthorized, gin.H(errTk))
		return
	}

	// Check if user exist based on the user id
	pr, err := model.Model.GetUserDataByID(userid)
	if err != nil {
		resp := msg.Message(false, "Internal Server Error")
		resp["value"] = "{}"
		c.JSON(http.StatusInternalServerError, gin.H(resp))
		return
	}

	// Define pwd as Password model and bind to json request
	var pwd model.Password
	if err := c.ShouldBindJSON(&pwd); err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}

	// password checker
	err = bcrypt.CompareHashAndPassword([]byte(pr.Password), []byte(pwd.OldPassword))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword { //Password does not match!
		resp := msg.Message(false, "Invalid Current password!")
		resp["value"] = "{}"
		c.JSON(http.StatusBadRequest, gin.H(resp))
		return
	}

	// Generate new password hash
	if pwd.NewPassword == "" {
		resp := msg.Message(false, "New Password can't be empty")
		resp["value"] = "{}"
		c.JSON(http.StatusNotAcceptable, gin.H(resp))
	}
	newHashPass, _ := bcrypt.GenerateFromPassword([]byte(pwd.NewPassword), bcrypt.DefaultCost)
	pwd.NewPassword = string(newHashPass)

	// Update password
	_, chkErr := model.Model.UpdatePassword(pr.ID, pwd.NewPassword)
	if chkErr != nil {
		resp := msg.Message(false, "Internal Server Error")
		resp["value"] = "{}"
		c.JSON(http.StatusInternalServerError, gin.H(resp))
		return
	}
	resp := msg.Message(true, "Password Updated")
	resp["value"] = "{}"
	c.JSON(http.StatusOK, gin.H(resp))
}

// UpdateProfile godoc
// @Summary Update Profile
// @Description Update profile for current user.
// @tags User API
// @Accept  json
// @Produce  json
// @Param data body model.UpdateProfile true "User data"
// @Security Bearer Token
// @Success 200 {object} model.EmptyResp "Profile updated"
// @Failure 400 {object} model.BadResp "Invalid payload"
// @Failure 401 {object} model.UnAuthResp "Unauthorize"
// @Failure 403 {object} model.ForbResp "Already in use"
// @Failure 500 {object} model.InErrResp "Internal Server Error"
// @Router /user/profile [post]
func UpdateProfile(c *gin.Context) {
	// Token Validation
	tokenAuth, _ := auth.ExtractTokenAuth(c.Request)
	errTk, userid := CheckTokenOnly(tokenAuth)
	if errTk != nil {
		c.JSON(http.StatusUnauthorized, gin.H(errTk))
		return
	}

	// Check if user exist based on the user id
	user, chkUser := model.Model.GetUserByID(userid)
	if chkUser != nil {
		resp := msg.Message(false, "Internal Server Error")
		resp["value"] = "{}"
		c.JSON(http.StatusInternalServerError, gin.H(resp))
		return
	}

	// Define model of profile to update
	var updt model.UpdateProfile
	if err := c.ShouldBindJSON(&updt); err != nil {
		resp := msg.Message(false, "Invalid json Payload! Should be email, firstName, lastName")
		resp["value"] = "{}"
		c.JSON(http.StatusBadRequest, gin.H(resp))
		return
	}

	// Run update
	_, errUp := model.Model.ProfileUpdate(user.UserID, updt)
	// Error checking
	if errUp != nil {
		switch errUp.Error() {
		case "invalid email":
			resp := msg.Message(false, "Invalid email format")
			resp["value"] = "{}"
			c.JSON(http.StatusBadRequest, gin.H(resp))
			return
		case "email exists":
			resp := msg.Message(false, "Email already in use! Please choose another Email")
			resp["value"] = "{}"
			c.JSON(http.StatusForbidden, gin.H(resp))
			return
		default:
			resp := msg.Message(false, "Internal Server Error")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		}
	}

	resp := msg.Message(true, "Profile updated")
	resp["value"] = "{}"
	c.JSON(http.StatusOK, gin.H(resp))
}

// UpdateProfileID godoc
// @Summary Update User Profile by UserID
// @Description Update only for admin user
// @tags User API
// @Accept  json
// @Produce  json
// @Param id path uint64 true "UserID"
// @Param data body model.UpdateProfile true "User data"
// @Security Bearer Token
// @Success 200 {object} model.EmptyResp "Profile updated"
// @Failure 400 {object} model.BadResp "Invalid payload"
// @Failure 401 {object} model.UnAuthResp "Unauthorize"
// @Failure 403 {object} model.ForbResp "Already in use or user not found"
// @Failure 500 {object} model.InErrResp "Internal Server Error"
// @Router /user/profile/{id} [post]
func UpdateProfileID(c *gin.Context) {
	// Assign path param
	iduser := c.Param("iduser")
	idUint, _ := strconv.ParseUint(iduser, 10, 64)
	// Check Admin
	tokenAuth, _ := auth.ExtractTokenAuth(c.Request)
	errTk, _ := CheckAdminByToken(tokenAuth)
	if errTk != nil {
		c.JSON(http.StatusUnauthorized, gin.H(errTk))
		return
	}

	// Define model of profile to update
	var updt model.UpdateProfile
	if err := c.ShouldBindJSON(&updt); err != nil {
		resp := msg.Message(false, "Invalid json Payload! Should be email, firstName, lastName")
		resp["value"] = "{}"
		c.JSON(http.StatusBadRequest, gin.H(resp))
		return
	}

	// Check if user exist based on the user id
	_, chkUser := model.Model.GetUserByID(idUint)
	if chkUser != nil {
		resp := msg.Message(false, "User not Found!")
		resp["value"] = "{}"
		c.JSON(http.StatusForbidden, gin.H(resp))
		return
	}

	// Run update
	_, errUp := model.Model.ProfileUpdate(idUint, updt)
	// Error checking
	if errUp != nil {
		switch errUp.Error() {
		case "invalid email":
			resp := msg.Message(false, "Invalid email format")
			resp["value"] = "{}"
			c.JSON(http.StatusBadRequest, gin.H(resp))
			return
		case "email exists":
			resp := msg.Message(false, "Email already in use! Please choose another Email")
			resp["value"] = "{}"
			c.JSON(http.StatusForbidden, gin.H(resp))
			return
		default:
			resp := msg.Message(false, "Internal Server Error")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		}
	}

	resp := msg.Message(true, "Profile updated")
	resp["value"] = "{}"
	c.JSON(http.StatusOK, gin.H(resp))
}

// CheckAdminByToken Function
func CheckAdminByToken(token *auth.Details) (map[string]interface{}, *model.Admin) {
	/*
		Token Validation
		* Get token and extract the format
		* Validate token to authID on server side.
	*/
	foundAuth, err := model.Model.FetchAuth(token)
	if err != nil {
		resp := msg.Message(false, "Invalid token. Please login first!")
		resp["value"] = "{}"
		return resp, nil
	} // End of Token validation

	// If not admin user, sent unauthorize response.
	adm, err := model.Model.GetAdminStatus(foundAuth.UserID)
	if err != nil || adm.IsAdmin != 1 {
		resp := msg.Message(false, "You need to be Admin for Accessing this Route!")
		resp["value"] = "{}"
		return resp, nil
	}
	var resp map[string]interface{} = nil
	return resp, adm
}

// CheckTokenOnly Function and Return ID
func CheckTokenOnly(token *auth.Details) (map[string]interface{}, uint64) {
	/*
		Token Validation
		* Get token and extract the format
		* Validate token to authID on server side.
	*/
	foundAuth, err := model.Model.FetchAuth(token)
	if err != nil {
		resp := msg.Message(false, "Invalid token. Please login first!")
		resp["value"] = "{}"
		return resp, 0
	} // End of Token validation
	var resp map[string]interface{} = nil
	return resp, foundAuth.UserID
}

// ConfirmUser godoc
// @Summary To activate user based on Email confirmation
// @Description Update profile for current user.
// @tags User API
// @Accept  json
// @Produce  json
// @param s query string secret_token "Secret token that sent to email"
// @Success 200 {object} model.EmptyResp "User Confirmed"
// @Failure 400 {object} model.BadResp "Empty Token Confirmation"
// @Failure 403 {object} model.ForbResp "Invalid Token Confirmation"
// @Router /user/confirm [get]
func ConfirmUser(c *gin.Context) {
	// Init query
	s := c.Query("s")
	if s == "" {
		resp := msg.Message(false, "Empty Token Confirmation")
		resp["value"] = "{}"
		c.JSON(http.StatusBadRequest, gin.H(resp))
		return
	}

	// Decode Token
	// 1. Decode otp hex format to byte using: DecodeHex(text)
	// 2. Decrypt to original string with: Decrypt([]byte(secret_key), byte_from_DecodeHex)
	dcd, err := utils.DecodeHex([]byte(s))
	if err != nil {
		resp := msg.Message(false, "Invalid Token Confirmation")
		resp["value"] = "{}"
		c.JSON(http.StatusForbidden, gin.H(resp))
		return
	}
	// Get secret token from user param
	secretToken := os.Getenv("SECRET_KEY")
	usrByte, err := utils.Decrypt([]byte(secretToken), dcd)
	if err != nil {
		resp := msg.Message(false, "Invalid Token Confirmation")
		resp["value"] = "{}"
		c.JSON(http.StatusForbidden, gin.H(resp))
		return
	}
	userStr := string(usrByte)
	uid, _ := strconv.ParseUint(utils.Between(userStr, "<id>", "</id>"), 10, 64)

	// Get secret token from db
	gtTkDb, err := model.Model.GetTempToken(uid, 3)
	if err != nil {
		resp := msg.Message(false, "Invalid Token Confirmation")
		resp["value"] = "{}"
		c.JSON(http.StatusForbidden, gin.H(resp))
		return
	}
	dbByte, _ := utils.Decrypt([]byte(secretToken), gtTkDb)
	// Compare token from user and server
	res := bytes.Compare(usrByte, dbByte)
	if res != 0 {
		resp := msg.Message(false, "Invalid Token Confirmation")
		resp["value"] = "{}"
		c.JSON(http.StatusForbidden, gin.H(resp))
		return
	}

	userName := utils.Between(userStr, "<user>", "</user>")
	mail := utils.Between(userStr, "<email>", "</email>")

	pr, err := model.Model.ConfirmUserAcc(uid, userName, mail)
	if err != nil {
		resp := msg.Message(false, "Internal Server Error")
		resp["value"] = "{}"
		c.JSON(http.StatusForbidden, gin.H(resp))
	}

	resp := msg.Message(true, "User Confirmed")
	resp["value"] = pr
	c.JSON(http.StatusOK, gin.H(resp))
	// Send welcome email
	fullname := pr.FirstName + " " + pr.LastName
	_ = utils.EmailNotifAccount(fullname, pr.Email, "https://www.omitsindo.com")
	return

}
