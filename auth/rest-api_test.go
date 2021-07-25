package auth

import (
	"strings"
	"testing"
)

// TestGetRestApiBaseUri should return a valid RESTlet API base path
func TestGetRestApiBaseUri(t *testing.T) {

	expected := "https://1234567-sb1.suitetalk.api.netsuite.com/services/rest/record/v1/"

	p := NewHeader(&HeaderOptions{
		AccountId:      "1234567-sb1",
		ConsumerKey:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		ConsumerSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenId:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenSecret:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	})

	if p.GetRestApiBaseUri() != expected {
		t.Fatal("incorrect base path returned")
	}
}

// TestGetRestApiAuthHeader should return a valid RESTlet API base path
func TestGetRestApiAuthHeader(t *testing.T) {

	expected := "OAuth realm=\"1234567_SB1\",oauth_consumer_key=\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"," +
		"oauth_token=\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\",oauth_signature_method=\"HMAC-SHA256\""

	p := NewHeader(&HeaderOptions{
		AccountId:      "1234567-sb1",
		ConsumerKey:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		ConsumerSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenId:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenSecret:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	})

	var authHeader = p.GetRestApiAuthHeader("GET", p.GetRestApiBaseUri())

	if !strings.Contains(authHeader, expected) {
		t.Fatal("invalid auth header created")
	}
}
