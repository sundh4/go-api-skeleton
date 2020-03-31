package model

// EmptyResp - for success empty response
type EmptyResp struct {
	IsSuccess bool   `json:"isSuccess"`
	Message   string `json:"message"`
	Value     string `json:"value"`
}

// ProfileResp - for success empty response
type ProfileResp struct {
	IsSuccess bool     `json:"isSuccess"`
	Message   string   `json:"message"`
	Value     *Profile `json:"value"`
}

// ProfileTokResp - for success empty response
type ProfileTokResp struct {
	IsSuccess bool          `json:"isSuccess"`
	Message   string        `json:"message"`
	Value     *ProfileToken `json:"value"`
}

// UnAuthResp - for unauthorize response
type UnAuthResp struct {
	IsSuccess bool   `json:"isSuccess" example:"false"`
	Message   string `json:"message" example:"Unauthorized"`
	Value     string `json:"value" example:"{}"`
}

// InErrResp - for internal server error response
type InErrResp struct {
	IsSuccess bool   `json:"isSuccess" example:"false"`
	Message   string `json:"message" example:"Internal Server Error"`
	Value     string `json:"value" example:"{}"`
}

// BadResp - for bad request
type BadResp struct {
	IsSuccess bool   `json:"isSuccess" example:"false"`
	Message   string `json:"message" example:"Bad request/Invalid json"`
	Value     string `json:"value" example:"{}"`
}

// ForbResp - for forbiden response
type ForbResp struct {
	IsSuccess bool   `json:"isSuccess" example:"false"`
	Message   string `json:"message" example:"Invalid credential"`
	Value     string `json:"value" example:"{}"`
}
