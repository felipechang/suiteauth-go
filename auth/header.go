package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"strconv"
	"time"
)

type Header interface {

	// GetRestApiBaseUri returns a base uri for the REST API
	GetRestApiBaseUri() string

	// GetRestApiAuthHeader returns a valid Suitetalk RESTlet OAuth1.0 header
	GetRestApiAuthHeader(method string, requestUrl string) string

	// GetSoapApiBaseUri returns a base uri for the SOAP API
	GetSoapApiBaseUri(apiVersion string) string

	// GetSoapApiAuthHeader returns a valid Suitetalk SOAP header
	GetSoapApiAuthHeader(apiVersion string) *TokenPassport
}

type HeaderOptions struct {
	AccountId      string
	ConsumerKey    string
	ConsumerSecret string
	TokenId        string
	TokenSecret    string
}

// NewHeader make a new Header
func NewHeader(c *HeaderOptions) Header {
	var p Header = c
	return p
}

// calculateSignature gets a base64 hashed SHA-256 string
func calculateSignature(base string, key string) string {
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(base))
	signature := hash.Sum(nil)
	return base64.StdEncoding.EncodeToString(signature)
}

// generateNonce returns an 11 character random string
func generateNonce() string {
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 11)
	for i := range b {
		b[i] = allowed[rand.Intn(len(allowed))]
	}
	return string(b)
}

// timeStamp returns a current timestamp
func timeStamp() string {
	return strconv.Itoa(int(time.Now().Unix()))
}
