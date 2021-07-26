package auth

import (
	"encoding/xml"
	"strings"
)

type TokenPassport struct {
	XMLName      xml.Name `xml:"platformMsgs:tokenPassport"`
	PlatformCore string   `xml:"xmlns:platformCore,attr"`
	PlatformMsgs string   `xml:"xmlns:platformMsgs,attr"`
	Xs           string   `xml:"xmlns:xs,attr"`
	Account      line     `xml:"platformCore:account"`
	ConsumerKey  line     `xml:"platformCore:consumerKey"`
	Token        line     `xml:"platformCore:token"`
	Nonce        line     `xml:"platformCore:nonce"`
	Timestamp    line     `xml:"platformCore:timestamp"`
	Signature    lineSign `xml:"platformCore:signature"`
}

type line struct {
	Value string `xml:",chardata"`
}

type lineSign struct {
	Value     string `xml:",chardata"`
	Algorithm string `xml:"algorithm,attr"`
}

// GetSoapApiBaseUri returns a base uri for the SOAP API
func (h *HeaderOptions) GetSoapApiBaseUri(apiVersion string) string {
	u := "https://"
	u += h.AccountId
	u += ".suitetalk.api.netsuite.com"
	u += "/services/NetSuitePort_"
	u += apiVersion
	return u
}

// GetSoapApiAuthHeader returns a valid Suitetalk SOAP header
func (h *HeaderOptions) GetSoapApiAuthHeader(apiVersion string) *TokenPassport {

	// generate nonce and timestamp
	nonce := generateNonce()
	timestamp := timeStamp()

	// calculate signature from base and signing Key
	base := strings.Join([]string{
		h.AccountId,
		h.ConsumerKey,
		h.TokenId,
		nonce,
		timestamp,
	}, "&")
	key := strings.Join([]string{
		h.ConsumerSecret,
		h.TokenSecret,
	}, "&")
	signature := calculateSignature(base, key)

	v := &TokenPassport{
		PlatformCore: "urn:core_" + apiVersion + ".platform.webservices.netsuite.com",
		PlatformMsgs: "urn:messages_" + apiVersion + ".platform.webservices.netsuite.com",
		Xs:           "http://www.w3.org/2001/XMLSchema",
		Account: line{
			Value: h.AccountId,
		},
		ConsumerKey: line{
			Value: h.ConsumerKey,
		},
		Token: line{
			Value: h.TokenId,
		},
		Nonce: line{
			Value: nonce,
		},
		Timestamp: line{
			Value: timestamp,
		},
		Signature: lineSign{
			Value:     signature,
			Algorithm: "HMAC-SHA256",
		},
	}

	return v
}
