package service

import "go-api-skeleton/auth"

//because i will mock signin in the future while writing test cases, it will be defined in an interface:
type sigInInterface interface {
	SignIn(auth.Details) (string, error)
}

type signInStruct struct{}

//let expose this interface:
var (
	Authorize sigInInterface = &signInStruct{}
)

func (si *signInStruct) SignIn(authD auth.Details) (string, error) {
	token, err := auth.CreateToken(authD)
	if err != nil {
		return "", err
	}
	return token, nil
}
