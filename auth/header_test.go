package auth

import (
	"testing"
)

// TestBuildHeader should build a NetSuite OAuth header
func TestBuildHeader(t *testing.T) {

	p := NewHeader(&HeaderOptions{
		AccountId:      "1234567-sb1",
		ConsumerKey:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		ConsumerSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenId:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenSecret:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	})

	if p == nil {
		t.Fatal("could not create header")
	}
}
