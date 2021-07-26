package auth

import (
	"strings"
	"testing"
)

// TestGetSoapApiBaseUri should return a valid SOAP API base path
func TestGetSoapApiBaseUri(t *testing.T) {

	expected := "https://1234567-sb1.suitetalk.api.netsuite.com/services/NetSuitePort_2021_1"

	p := NewHeader(&HeaderOptions{
		AccountId:      "1234567-sb1",
		ConsumerKey:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		ConsumerSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenId:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenSecret:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	})

	if p.GetSoapApiBaseUri("2021_1") != expected {
		t.Fatal("incorrect base path returned")
	}
}

// TestGetSoapApiAuthHeader should return a valid SOAP API base path
func TestGetSoapApiAuthHeader(t *testing.T) {

	expected := "<platformMsgs:tokenPassport xmlns:platformCore=\"urn:core_2021_1.platform.webservices.netsuite.com\" "
	expected += "xmlns:platformMsgs=\"urn:messages_2021_1.platform.webservices.netsuite.com\" "
	expected += "xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">"

	p := NewHeader(&HeaderOptions{
		AccountId:      "1234567-sb1",
		ConsumerKey:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		ConsumerSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenId:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenSecret:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	})

	authHeader, err := p.GetSoapApiAuthHeader("2021_1")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(authHeader), expected) {
		t.Fatal("invalid auth header created")
	}
}
