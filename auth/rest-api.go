package auth

import (
	"fmt"
	"net/url"
	"strings"
)

// GetRestApiBaseUri returns a base uri for the REST API
func (h *HeaderOptions) GetRestApiBaseUri() string {
	u := "https://"
	u += h.AccountId
	u += ".suitetalk.api.netsuite.com"
	u += "/services/rest/record/v1/"
	return u
}

// GetRestApiAuthHeader returns a valid Suitetalk RESTlet OAuth1.0 header
func (h *HeaderOptions) GetRestApiAuthHeader(method string, requestUrl string) string {

	method = strings.ToUpper(method)

	// add OAuth values
	values := url.Values{}
	values.Add("oauth_nonce", generateNonce())
	values.Add("oauth_consumer_key", h.ConsumerKey)
	values.Add("oauth_signature_method", "HMAC-SHA256")
	values.Add("oauth_timestamp", timeStamp())
	values.Add("oauth_token", h.TokenId)
	values.Add("oauth_version", "1.0")

	// add query params
	basePath, queryParams := splitURL(requestUrl)
	insertQueryParams(&values, queryParams)

	// net/url package QueryEscape escapes " " into "+", this replaces it with the percentage encoding of " "
	p := strings.Replace(values.Encode(), "+", "%20", -1)

	// calculate signature from base and signing Key
	base := method + "&"
	base += url.QueryEscape(basePath) + "&"
	base += url.QueryEscape(p)

	key := url.QueryEscape(h.ConsumerSecret) + "&"
	key += url.QueryEscape(h.TokenSecret)

	signature := calculateSignature(base, key)

	// build and return header string
	return fmt.Sprintf(``+
		`OAuth realm="%s",`+
		`oauth_consumer_key="%s",`+
		`oauth_token="%s",`+
		`oauth_signature_method="%s",`+
		`oauth_timestamp="%s",`+
		`oauth_nonce="%s",`+
		`oauth_version="%s",`+
		`oauth_signature="%s"`,

		strings.ReplaceAll(strings.ToUpper(h.AccountId), "-", "_"),
		url.QueryEscape(values.Get("oauth_consumer_key")),
		url.QueryEscape(values.Get("oauth_token")),
		url.QueryEscape(values.Get("oauth_signature_method")),
		url.QueryEscape(values.Get("oauth_timestamp")),
		url.QueryEscape(values.Get("oauth_nonce")),
		url.QueryEscape(values.Get("oauth_version")),
		url.QueryEscape(signature),
	)
}

// insertQueryParams inserts query values into header
func insertQueryParams(values *url.Values, urlParameters string) {
	if urlParameters == "" {
		return
	}
	var aux []string
	split := strings.Split(urlParameters, "&")
	for i := 0; i < len(split); i++ {
		aux = strings.Split(split[i], "=")
		values.Add(aux[0], aux[1])
	}
}

// splitURL splits URL into base and query
func splitURL(urlPath string) (string, string) {
	split := strings.Split(urlPath, "?")
	if len(split) == 1 {
		return split[0], ""
	}
	return split[0], split[1]
}
