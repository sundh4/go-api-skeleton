package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

/*
	Example how to use:
	* Encrypt:
		1. Generate OTP with: GenOTP(user_id, username, email)
		2. Encode OTP to hex format using: EncodeHex(token_from_GenOTP)
	* Decrypt
		1. Decode otp hex format to byte using: DecodeHex(text)
		2. Decrypt to original string with: Decrypt([]byte(secret_key), byte_from_DecodeHex)

*/

/*
Between substract string
example string <s1>Hello World</s1><s2>Test Substract string</s2>
*/
func Between(value string, after string, before string) string {
	// Get substring between two strings.
	posFirst := strings.Index(value, after)
	if posFirst == -1 {
		return ""
	}
	posLast := strings.Index(value, before)
	if posLast == -1 {
		return ""
	}
	posFirstAdjusted := posFirst + len(after)
	if posFirstAdjusted >= posLast {
		return ""
	}
	return value[posFirstAdjusted:posLast]
}

/*
Encrypt function
Used to encrypt string to use AES with Secret Key
*/
func Encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

/*
Decrypt function
Used to decrypt chiper from AES encryption with Secret Key
*/
func Decrypt(key, text []byte) ([]byte, error) {
	// Generate chiper block from secret key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	// Decode encypted byte to base64 format
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	// Decode base64 to original byte code
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// GenOTP function
func GenOTP(uid uint64, user string, email string) ([]byte, error) {
	// Get secret token
	secretToken := os.Getenv("SECRET_KEY")
	// Build user string information
	userid := fmt.Sprintf("<id>%s</id>", strconv.FormatUint(uid, 10))
	username := fmt.Sprintf("<user>%s</user>", user)
	mail := fmt.Sprintf("<email>%s</email>", email)
	fullStr := userid + username + mail
	// Encrypt string
	ciphertext, _ := Encrypt([]byte(secretToken), []byte(fullStr))
	return ciphertext, nil
}

// DecodeHex from hex to byte data
func DecodeHex(src []byte) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	res := dst[:n]
	return res, nil
}

// EncodeHex from byte to hex string
func EncodeHex(src []byte) string {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	strHex := string(dst)
	return strHex
}
