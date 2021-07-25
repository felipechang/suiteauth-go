package main

import (
	"log"
	"suiteauth-go/auth"
)

func main() {

	p := auth.NewHeader(&auth.HeaderOptions{
		AccountId:      "1234567-sb1",
		ConsumerKey:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		ConsumerSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenId:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TokenSecret:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	})

	header := p.GetRestApiAuthHeader("GET", p.GetRestApiBaseUri()+"customer?q=1")

	log.Printf("auth header: %s", header)
}
