package main

import "github.com/Azure/go-autorest/autorest/adal"

type HardCodedToken struct {
	adal.OAuthTokenProvider
}

func (HardCodedToken) OAuthToken() string {
	return ""
}