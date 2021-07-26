# SuiteAuth-Go

Generate Authentication headers for NetSuite SOAP/REST requests

## Usage:

    package main

    import (
        "github.com/felipechang/suiteauth-go/auth"
        "log"
    )

    func main() {

        p := auth.NewHeader(&auth.HeaderOptions{
            AccountId:      "1234567-sb1",
            ConsumerKey:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            ConsumerSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            TokenId:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            TokenSecret:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        })
    
        soapUri := p.GetSoapApiBaseUri("2021_1")
        soapHeader, err := p.GetSoapApiAuthHeader("2021_1")
        if err != nil {
            log.Fatalln(err)
        }
        log.Printf("auth soapUri: %s", soapUri)
        log.Printf("auth soapHeader: %s", string(soapHeader))
    
        restUri := p.GetRestApiBaseUri()
        restHeader := p.GetRestApiAuthHeader("GET", restUri)
        log.Printf("auth restUri: %s", restUri)
        log.Printf("auth restHeader: %s", restHeader)
    }
