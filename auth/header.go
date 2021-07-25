package auth

type Header interface {

	// GetRestApiAuthHeader returns a NS RESTlet OAuth1.0 valid header
	GetRestApiAuthHeader(method string, requestUrl string) string

	// GetRestApiBaseUri returns the uri for the REST API
	GetRestApiBaseUri() string
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
