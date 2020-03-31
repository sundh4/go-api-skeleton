package controller

import (
	"go-api-skeleton/auth"
	"go-api-skeleton/model"
	"go-api-skeleton/service"
	msg "go-api-skeleton/utils"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"golang.org/x/crypto/bcrypt"
)

// Login godoc
// @Summary Login User
// @Description Login will return token, admin status and user profile
// @tags Auth API
// @Accept  json
// @Produce  json
// @Param data body model.LoginUser true "Login by Username"
// @Success 200 {object} model.ProfileTokResp
// @Failure 400 {object} model.BadResp "Invalid payload"
// @Failure 401 {object} model.UnAuthResp "Unauthorize"
// @Failure 403 {object} model.ForbResp "Invalid credential"
// @Failure 500 {object} model.InErrResp "Internal Server Error"
// @Router /user/login [post]
func Login(c *gin.Context) {
	// var u model.LoginUser
	// var m model.LoginEmail
	u, m := model.LoginUser{}, model.LoginEmail{}
	var passWd string
	// Assign var
	var user *model.FullData
	var err, uerr, merr error

	// use ShouldBindBodyWith
	uerr = c.ShouldBindBodyWith(&u, binding.JSON)
	if uerr == nil {
		// Handler all json request if not empty
		if u.Password == "" {
			resp := msg.Message(false, "Password can't Empty")
			resp["value"] = "{}"
			c.JSON(http.StatusForbidden, gin.H(resp))
			return
		}
		if u.Username == "" {
			resp := msg.Message(false, "Username can't Empty")
			resp["value"] = "{}"
			c.JSON(http.StatusForbidden, gin.H(resp))
			return
		}
		passWd = u.Password
		//check if user exist or not by user
		user, err = model.Model.GetUserByName(u.Username)
		if err != nil {
			resp := msg.Message(false, "User not found")
			resp["value"] = "{}"
			c.JSON(http.StatusForbidden, gin.H(resp))
			return
		}
	} else if uerr != nil {
		if merr = c.ShouldBindBodyWith(&m, binding.JSON); merr == nil {
			// Handler all json request if not empty
			if m.Password == "" {
				resp := msg.Message(false, "Password can't Empty")
				resp["value"] = "{}"
				c.JSON(http.StatusForbidden, gin.H(resp))
				return
			}
			if m.Email == "" {
				resp := msg.Message(false, "Email can't Empty")
				resp["value"] = "{}"
				c.JSON(http.StatusForbidden, gin.H(resp))
				return
			}
			passWd = m.Password
			//check if user exist or not by email
			user, err = model.Model.GetUserByEmail(m.Email)
			if err != nil {
				resp := msg.Message(false, "User not found")
				resp["value"] = "{}"
				c.JSON(http.StatusForbidden, gin.H(resp))
				return
			}
		} else {
			if passWd == "" {
				resp := msg.Message(false, "Password can't Empty")
				resp["value"] = "{}"
				c.JSON(http.StatusForbidden, gin.H(resp))
				return
			}
			resp := msg.Message(false, "Invalid Json Request")
			resp["value"] = "{}"
			c.JSON(http.StatusBadRequest, gin.H(resp))
			return
		}
	}

	// password checker
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(passWd))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword { //Password does not match!
		resp := msg.Message(false, "Login failed, wrong credentials")
		resp["value"] = "{}"
		c.JSON(http.StatusForbidden, gin.H(resp))
		return
	}

	// User active or not checker
	if user.Status != 1 {
		switch user.Status {
		case 2:
			resp := msg.Message(false, "User banned, please contact hello@omitsindo.com for more information!")
			resp["value"] = "{}"
			c.JSON(http.StatusForbidden, gin.H(resp))
			return
		case 3:
			resp := msg.Message(false, "User not activated yet. Check email for account activation!")
			resp["value"] = "{}"
			c.JSON(http.StatusForbidden, gin.H(resp))
			return
		default:
			resp := msg.Message(false, "Invalid User")
			resp["value"] = "{}"
			c.JSON(http.StatusInternalServerError, gin.H(resp))
			return
		}
	}

	// Auth ID and JWT token generator
	authData, err := model.Model.CreateAuth(user.ID)
	if err != nil {
		return
	}
	var authD auth.Details
	authD.UserID = authData.UserID
	authD.AuthUUID = authData.AuthUUID
	token, loginErr := service.Authorize.SignIn(authD)
	if loginErr != nil {
		resp := msg.Message(false, "Please try to login later")
		resp["value"] = "{}"
		c.JSON(http.StatusInternalServerError, gin.H(resp))
		return
	}
	// Assign profile to response after succeed login
	p := &model.ProfileToken{
		Token: token,
	}
	p.Profile.UserID = user.ID
	p.Profile.Username = user.Username
	p.Profile.Email = user.Email
	p.Profile.FirstName = user.FirstName
	p.Profile.LastName = user.LastName
	p.Profile.IsAdmin = user.IsAdmin
	p.Profile.Status = user.Status
	resp := msg.Message(true, "Login succeed")
	resp["value"] = p
	c.JSON(http.StatusOK, gin.H(resp))
}

// LogOut godoc
// @Summary Logout User
// @Description Logout user and remove auth token.
// @tags Auth API
// @Accept  json
// @Produce  json
// @Security Bearer Token
// @Success 200 {array} model.EmptyResp
// @Failure 401 {array} model.UnAuthResp "Unauthorize"
// @Failure 500 {object} model.InErrResp "Internal Server Error"
// @Router /user/logout [post]
func LogOut(c *gin.Context) {
	au, err := auth.ExtractTokenAuth(c.Request)
	if err != nil {
		resp := msg.Message(false, "Unauthorized")
		resp["value"] = "{}"
		c.JSON(401, gin.H(resp))
		return
	}
	delErr := model.Model.DeleteAuth(au)
	if delErr != nil {
		log.Println(delErr)
		resp := msg.Message(false, "Unauthorized")
		resp["value"] = "{}"
		c.JSON(500, gin.H(resp))
		return
	}
	// Succeed
	resp := msg.Message(true, "Successfully logged out")
	resp["value"] = "{}"
	c.JSON(http.StatusOK, gin.H(resp))
}
