/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"crypto/x509"
	"encoding/pem"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/websocket"
	gojose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	fakeAdminRole          = "role:admin"
	fakeAdminRoleURL       = "/admin*"
	fakeAuthAllURL         = "/auth_all/*"
	fakeClientID           = "test"
	fakeSecret             = "test"
	fakeTestAdminRolesURL  = "/test_admin_roles"
	fakeTestRole           = "role:test"
	fakeTestRoleURL        = "/test_role"
	fakeTestWhitelistedURL = "/auth_all/white_listed*"
	testProxyAccepted      = "Proxy-Accepted"
	validUsername          = "test"
	validPassword          = "test"
)

type RoleClaim struct {
	Roles []string `json:"roles"`
}

type DefaultTestTokenClaims struct {
	Aud               string               `json:"aud"`
	Azp               string               `json:"azp"`
	ClientSession     string               `json:"client_session"`
	Email             string               `json:"email"`
	FamilyName        string               `json:"family_name"`
	GivenName         string               `json:"given_name"`
	Username          string               `json:"username"`
	Iat               int64                `json:"iat"`
	Iss               string               `json:"iss"`
	Jti               string               `json:"jti"`
	Name              string               `json:"name"`
	Nbf               int                  `json:"nbf"`
	Exp               int64                `json:"exp"`
	PreferredUsername string               `json:"preferred_username"`
	SessionState      string               `json:"session_state"`
	Sub               string               `json:"sub"`
	Typ               string               `json:"typ"`
	Groups            []string             `json:"groups"`
	RealmAccess       RoleClaim            `json:"realm_access"`
	ResourceAccess    map[string]RoleClaim `json:"resource_access"`
	Item              string               `json:"item"`
	Found             string               `json:"found"`
	Item1             []string             `json:"item1"`
	Item2             []string             `json:"item2"`
	Item3             []string             `json:"item3"`
}

var defTestTokenClaims = DefaultTestTokenClaims{
	Aud:               "test",
	Azp:               "clientid",
	ClientSession:     "f0105893-369a-46bc-9661-ad8c747b1a69",
	Email:             "gambol99@gmail.com",
	FamilyName:        "Jayawardene",
	GivenName:         "Rohith",
	Username:          "Jayawardene",
	Iat:               1450372669,
	Iss:               "test",
	Jti:               "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
	Name:              "Rohith Jayawardene",
	Nbf:               0,
	Exp:               0,
	PreferredUsername: "rjayawardene",
	SessionState:      "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
	Sub:               "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
	Typ:               "Bearer",
	Groups:            []string{"default"},
	RealmAccess:       RoleClaim{Roles: []string{"default"}},
	ResourceAccess: map[string]RoleClaim{
		"defaultclient": {
			Roles: []string{"default"},
		},
	},
	Item:  "item",
	Item1: []string{"default"},
	Item2: []string{"default"},
	Item3: []string{"default"},
}

func TestNewKeycloakProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	authConfig := &fakeAuthConfig{}
	authConfig.EnableTLS = false

	cfg.DiscoveryURL = newFakeAuthServer(authConfig).getLocation()
	cfg.Listen = "127.0.0.1:0"
	cfg.ListenHTTP = ""

	proxy, err := newProxy(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.config)
	assert.NotNil(t, proxy.router)
	assert.NotNil(t, proxy.endpoint)
	assert.NoError(t, proxy.Run())
}

func TestReverseProxyHeaders(t *testing.T) {
	p := newFakeProxy(nil, &fakeAuthConfig{})
	token := newTestToken(p.idp.getLocation())
	token.addRealmRoles([]string{fakeAdminRole})
	jwt, _ := token.getToken()
	uri := "/auth_all/test"
	requests := []fakeRequest{
		{
			URI:           uri,
			RawToken:      jwt,
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Email":    "gambol99@gmail.com",
				"X-Auth-Roles":    "role:admin,defaultclient:default",
				"X-Auth-Subject":  token.claims.Sub,
				"X-Auth-Userid":   "rjayawardene",
				"X-Auth-Username": "rjayawardene",
			},
			ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
				"X-Auth-Token": func(t *testing.T, c *Config, value string) {
					assert.Equal(t, jwt, value)
					assert.False(t, checkAccessTokenEncryption(t, c, value))
				},
			},
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: `"uri":"` + uri + `"`,
		},
	}
	p.RunTests(t, requests)
}

func TestAuthTokenHeader(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestClearTextWithEnableEncryptedToken",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"X-Auth-Token": func(t *testing.T, c *Config, value string) {
							_, err := jwt.ParseSigned(value)
							assert.Nil(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
				},
				{
					URI:           fakeAuthAllURL,
					ExpectedProxy: true,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"X-Auth-Token": func(t *testing.T, c *Config, value string) {
							_, err := jwt.ParseSigned(value)
							assert.Nil(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestClearTextWithForceEncryptedCookie",
			ProxySettings: func(c *Config) {
				c.EnableEncryptedToken = false
				c.ForceEncryptedCookie = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"X-Auth-Token": func(t *testing.T, c *Config, value string) {
							_, err := jwt.ParseSigned(value)
							assert.Nil(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
				},
				{
					URI:           fakeAuthAllURL,
					ExpectedProxy: true,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"X-Auth-Token": func(t *testing.T, c *Config, value string) {
							_, err := jwt.ParseSigned(value)
							assert.Nil(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		cfgCopy := *cfg
		c := &cfgCopy
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{})
				// p.idp.setTokenExpiration(1000 * time.Millisecond)
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestForwardingProxy(t *testing.T) {
	s := httptest.NewServer(&fakeUpstreamService{})

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestPasswordGrant",
			ProxySettings: func(c *Config) {
				c.EnableForwarding = true
				c.ForwardingDomains = []string{}
				c.ForwardingUsername = validUsername
				c.ForwardingPassword = validPassword
				c.ForwardingGrantType = GrantTypeUserCreds
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestPasswordGrantWithRefreshing",
			ProxySettings: func(c *Config) {
				c.EnableForwarding = true
				c.ForwardingDomains = []string{}
				c.ForwardingUsername = validUsername
				c.ForwardingPassword = validPassword
				c.ForwardingGrantType = GrantTypeUserCreds
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "Bearer ey",
				},
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestClientCredentialsGrant",
			ProxySettings: func(c *Config) {
				c.EnableForwarding = true
				c.ForwardingDomains = []string{}
				c.ClientID = validUsername
				c.ClientSecret = validPassword
				c.ForwardingGrantType = GrantTypeClientCreds
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestClientCredentialsGrantWithRefreshing",
			ProxySettings: func(c *Config) {
				c.EnableForwarding = true
				c.ForwardingDomains = []string{}
				c.ClientID = validUsername
				c.ClientSecret = validPassword
				c.ForwardingGrantType = GrantTypeClientCreds
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "Bearer ey",
				},
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				c := newFakeKeycloakConfig()
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{Expiration: 900 * time.Millisecond})
				<-time.After(time.Duration(100) * time.Millisecond)
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestSkipOpenIDProviderTLSVerifyForwardingProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableForwarding = true
	cfg.ForwardingDomains = []string{}
	cfg.ForwardingUsername = validUsername
	cfg.ForwardingPassword = validPassword
	cfg.SkipOpenIDProviderTLSVerify = true
	cfg.ForwardingGrantType = "password"
	s := httptest.NewServer(&fakeUpstreamService{})
	requests := []fakeRequest{
		{
			URL:                     s.URL + "/test",
			ProxyRequest:            true,
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Bearer ey",
		},
	}
	p := newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true})
	<-time.After(time.Duration(100) * time.Millisecond)
	p.RunTests(t, requests)

	cfg.SkipOpenIDProviderTLSVerify = false

	defer func() {
		if r := recover(); r != nil {
			check := strings.Contains(
				r.(string),
				"failed to retrieve the provider configuration from discovery url",
			)
			assert.True(t, check)
		}
	}()

	p = newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true})
	<-time.After(time.Duration(100) * time.Millisecond)
	p.RunTests(t, requests)
}

func TestForbiddenTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.ForbiddenPage = "templates/forbidden.html.tmpl"
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     "/test",
			Redirects:               false,
			HasToken:                true,
			ExpectedCode:            http.StatusForbidden,
			ExpectedContentContains: "403 Permission Denied",
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestErrorTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestErrorTemplateDisplayed",
			ProxySettings: func(c *Config) {
				c.ErrorPage = "templates/error.html.tmpl"
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/callback",
					Redirects:               true,
					ExpectedCode:            http.StatusBadRequest,
					ExpectedContentContains: "400 Bad Request",
				},
			},
		},
		{
			Name: "TestWithBadErrorTemplate",
			ProxySettings: func(c *Config) {
				c.ErrorPage = "templates/error-bad-formatted.html.tmpl"
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/callback",
					Redirects:               true,
					ExpectedCode:            http.StatusBadRequest,
					ExpectedContentContains: "",
				},
			},
		},
		{
			Name: "TestWithEmptyErrorTemplate",
			ProxySettings: func(c *Config) {
				c.ErrorPage = ""
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/callback",
					Redirects:               true,
					ExpectedCode:            http.StatusBadRequest,
					ExpectedContentContains: "",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		cfgCopy := *cfg
		c := &cfgCopy
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestSkipOpenIDProviderTLSVerify(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.SkipOpenIDProviderTLSVerify = true
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(c, &fakeAuthConfig{EnableTLS: true}).RunTests(t, requests)
	c.SkipOpenIDProviderTLSVerify = false

	defer func() {
		if r := recover(); r != nil {
			check := strings.Contains(
				r.(string),
				"failed to retrieve the provider configuration from discovery url",
			)
			assert.True(t, check)
		}
	}()

	newFakeProxy(c, &fakeAuthConfig{EnableTLS: true}).RunTests(t, requests)
}

func TestRequestIDHeader(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableRequestID = true
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedHeaders: map[string]string{
				"X-Request-ID": "",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestAuthTokenHeaderDisabled(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableTokenHeader = false
	p := newFakeProxy(c, &fakeAuthConfig{})
	token := newTestToken(p.idp.getLocation())
	jwt, _ := token.getToken()

	requests := []fakeRequest{
		{
			URI:                    "/auth_all/test",
			RawToken:               jwt,
			ExpectedNoProxyHeaders: []string{"X-Auth-Token"},
			ExpectedProxy:          true,
			ExpectedCode:           http.StatusOK,
		},
	}
	p.RunTests(t, requests)
}

func TestAudienceHeader(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.NoRedirects = false
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Audience": "test",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestDefaultDenial(t *testing.T) {
	config := newFakeKeycloakConfig()
	config.EnableDefaultDeny = true
	config.Resources = []*Resource{
		{
			URL:         "/public/*",
			Methods:     allHTTPMethods,
			WhiteListed: true,
		},
	}
	requests := []fakeRequest{
		{
			URI:           "/public/allowed",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			Method:       "get",
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(config, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestAuthorizationTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.SignInPage = "templates/sign_in.html.tmpl"
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     cfg.WithOAuthURI(authorizationURL),
			Redirects:               true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Sign In",
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestProxyProtocol(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableProxyProtocol = true
	requests := []fakeRequest{
		{
			URI:           fakeAuthAllURL + "/test",
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			URI:           fakeAuthAllURL + "/test",
			HasToken:      true,
			ProxyProtocol: "189.10.10.1",
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Forwarded-For": "189.10.10.1",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestXForwarded(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestEmptyXForwarded",
			ProxySettings: func(c *Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL + "/test",
					HasToken:      true,
					ExpectedProxy: true,
					ExpectedProxyHeaders: map[string]string{
						"X-Forwarded-For": "127.0.0.1",
						"X-Real-IP":       "127.0.0.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestXForwardedPresent",
			ProxySettings: func(c *Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL + "/test",
					HasToken:      true,
					ExpectedProxy: true,
					Headers: map[string]string{
						"X-Forwarded-For": "189.10.10.1",
					},
					ExpectedProxyHeaders: map[string]string{
						"X-Forwarded-For": "189.10.10.1",
						"X-Real-IP":       "189.10.10.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestXRealIP",
			ProxySettings: func(c *Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL + "/test",
					HasToken:      true,
					ExpectedProxy: true,
					Headers: map[string]string{
						"X-Real-IP": "189.10.10.1",
					},
					ExpectedProxyHeaders: map[string]string{
						"X-Forwarded-For": "189.10.10.1",
						"X-Real-IP":       "189.10.10.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				c := newFakeKeycloakConfig()
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestTokenEncryption(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableEncryptedToken = true
	c.EncryptionKey = "US36S5kubc4BXbfzCIKTQcTzG6lvixVv"
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Email":    "gambol99@gmail.com",
				"X-Auth-Userid":   "rjayawardene",
				"X-Auth-Username": "rjayawardene",
				"X-Forwarded-For": "127.0.0.1",
			},
			ExpectedCode: http.StatusOK,
		},
		// the token must be encrypted
		{
			URI:          "/auth_all/test",
			HasToken:     true,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestCustomResponseHeaders(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.ResponseHeaders = map[string]string{
		"CustomReponseHeader": "True",
	}
	p := newFakeProxy(c, &fakeAuthConfig{})

	requests := []fakeRequest{
		{
			URI:       "/auth_all/test",
			HasLogin:  true,
			Redirects: true,
			ExpectedHeaders: map[string]string{
				"CustomReponseHeader": "True",
			},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	p.RunTests(t, requests)
}

func TestSkipClientIDDisabled(t *testing.T) {
	// !!!! Before in keycloak in audience of access_token was client_id of
	// client for which was access token released, but this is not according spec
	// as access_token could be also other type not just JWT
	c := newFakeKeycloakConfig()
	p := newFakeProxy(c, &fakeAuthConfig{})
	// create two token, one with a bad client id
	bad := newTestToken(p.idp.getLocation())
	bad.claims.Aud = "bad_client_id"
	badSigned, _ := bad.getToken()
	// and the good
	good := newTestToken(p.idp.getLocation())
	goodSigned, _ := good.getToken()
	requests := []fakeRequest{
		{
			URI:               "/auth_all/test",
			RawToken:          goodSigned,
			ExpectedProxy:     true,
			ExpectedCode:      http.StatusOK,
			SkipClientIDCheck: false,
		},
		{
			URI:               "/auth_all/test",
			RawToken:          goodSigned,
			ExpectedProxy:     true,
			ExpectedCode:      http.StatusOK,
			SkipClientIDCheck: true,
		},
		{
			URI:               "/auth_all/test",
			RawToken:          badSigned,
			ExpectedCode:      http.StatusForbidden,
			ExpectedProxy:     false,
			SkipClientIDCheck: false,
		},
		{
			URI:               "/auth_all/test",
			RawToken:          badSigned,
			ExpectedProxy:     true,
			ExpectedCode:      http.StatusOK,
			SkipClientIDCheck: true,
		},
	}
	p.RunTests(t, requests)
}

func TestSkipIssuer(t *testing.T) {
	c := newFakeKeycloakConfig()
	p := newFakeProxy(c, &fakeAuthConfig{})
	// create two token, one with a bad client id
	bad := newTestToken(p.idp.getLocation())
	bad.claims.Iss = "bad_issuer"
	badSigned, _ := bad.getToken()
	// and the good
	good := newTestToken(p.idp.getLocation())
	goodSigned, _ := good.getToken()
	requests := []fakeRequest{
		{
			URI:             "/auth_all/test",
			RawToken:        goodSigned,
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			SkipIssuerCheck: false,
		},
		{
			URI:             "/auth_all/test",
			RawToken:        goodSigned,
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			SkipIssuerCheck: true,
		},
		{
			URI:             "/auth_all/test",
			RawToken:        badSigned,
			ExpectedCode:    http.StatusForbidden,
			ExpectedProxy:   false,
			SkipIssuerCheck: false,
		},
		{
			URI:             "/auth_all/test",
			RawToken:        badSigned,
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			SkipIssuerCheck: true,
		},
	}
	p.RunTests(t, requests)
}

func TestAuthTokenHeaderEnabled(t *testing.T) {
	p := newFakeProxy(nil, &fakeAuthConfig{})
	token := newTestToken(p.idp.getLocation())
	signed, _ := token.getToken()

	requests := []fakeRequest{
		{
			URI:      "/auth_all/test",
			RawToken: signed,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Token": signed,
			},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	p.RunTests(t, requests)
}

func TestDisableAuthorizationCookie(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableAuthorizationCookies = false
	p := newFakeProxy(c, &fakeAuthConfig{})
	token := newTestToken(p.idp.getLocation())
	signed, _ := token.getToken()

	requests := []fakeRequest{
		{
			URI: "/auth_all/test",
			Cookies: []*http.Cookie{
				{Name: c.CookieAccessName, Value: signed},
				{Name: "mycookie", Value: "myvalue"},
			},
			HasToken:                true,
			ExpectedContentContains: "kc-access=censored; mycookie=myvalue",
			ExpectedCode:            http.StatusOK,
			ExpectedProxy:           true,
		},
	}
	p.RunTests(t, requests)
}

func newTestService() string {
	_, _, u := newTestProxyService(nil)
	return u
}

func newTestProxyService(config *Config) (*oauthProxy, *fakeAuthServer, string) {
	if config == nil {
		config = newFakeKeycloakConfig()
	}

	authConfig := &fakeAuthConfig{}
	if config.SkipOpenIDProviderTLSVerify {
		authConfig.EnableTLS = true
	}

	auth := newFakeAuthServer(authConfig)

	config.DiscoveryURL = auth.getLocation()
	config.RevocationEndpoint = auth.getRevocationURL()
	config.Verbose = false
	config.EnableLogging = false

	proxy, err := newProxy(config)
	if err != nil {
		panic("failed to create proxy service, error: " + err.Error())
	}

	// step: create an fake upstream endpoint
	proxy.upstream = new(fakeUpstreamService)
	service := httptest.NewServer(proxy.router)
	config.RedirectionURL = service.URL

	// step: we need to update the client config
	if proxy.provider, proxy.idpClient, err = proxy.newOpenIDProvider(); err != nil {
		panic("failed to recreate the openid client, error: " + err.Error())
	}

	return proxy, auth, service.URL
}

func newFakeHTTPRequest(method, path string) *http.Request {
	return &http.Request{
		Method: method,
		Header: make(map[string][]string),
		Host:   "127.0.0.1",
		URL: &url.URL{
			Scheme: "http",
			Host:   "127.0.0.1",
			Path:   path,
		},
	}
}

func newFakeKeycloakConfig() *Config {
	return &Config{
		ClientID:                    fakeClientID,
		ClientSecret:                fakeSecret,
		CookieAccessName:            "kc-access",
		CookieRefreshName:           "kc-state",
		DisableAllLogging:           true,
		DiscoveryURL:                "127.0.0.1:0",
		EnableAuthorizationCookies:  true,
		EnableAuthorizationHeader:   true,
		EnableLogging:               false,
		EnableLoginHandler:          true,
		EnableTokenHeader:           true,
		EnableCompression:           false,
		EnableMetrics:               false,
		Listen:                      "127.0.0.1:0",
		ListenAdmin:                 "",
		ListenAdminScheme:           "http",
		TLSAdminCertificate:         "",
		TLSAdminPrivateKey:          "",
		TLSAdminCaCertificate:       "",
		OAuthURI:                    "/oauth",
		OpenIDProviderTimeout:       time.Second * 5,
		SkipOpenIDProviderTLSVerify: false,
		SkipUpstreamTLSVerify:       false,
		Scopes:                      []string{},
		Verbose:                     false,
		Resources: []*Resource{
			{
				URL:     fakeAdminRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeAdminRole},
			},
			{
				URL:     fakeTestRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeTestRole},
			},
			{
				URL:     fakeTestAdminRolesURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeAdminRole, fakeTestRole},
			},
			{
				URL:     fakeAuthAllURL,
				Methods: allHTTPMethods,
				Roles:   []string{},
			},
			{
				URL:         fakeTestWhitelistedURL,
				WhiteListed: true,
				Methods:     allHTTPMethods,
				Roles:       []string{},
			},
		},
	}
}

func makeTestCodeFlowLogin(location string) (*http.Response, []*http.Cookie, error) {
	flowCookies := make([]*http.Cookie, 0)

	u, err := url.Parse(location)

	if err != nil {
		return nil, nil, err
	}
	// step: get the redirect
	var resp *http.Response
	for count := 0; count < 4; count++ {
		req, err := http.NewRequest(http.MethodGet, location, nil)

		if err != nil {
			return nil, nil, err
		}

		if resp != nil {
			cookies := resp.Cookies()
			flowCookies = append(flowCookies, cookies...)
		}

		// step: make the request
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gas
				InsecureSkipVerify: true,
			},
		}

		resp, err = tr.RoundTrip(req)

		if err != nil {
			return nil, nil, err
		}

		if resp.StatusCode != http.StatusSeeOther {
			return nil, nil, fmt.Errorf("no redirection found in resp, status code %d", resp.StatusCode)
		}

		location = resp.Header.Get("Location")

		if !strings.HasPrefix(location, "http") && !strings.HasPrefix(location, "https") {
			location = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, location)
		}
	}
	return resp, flowCookies, nil
}

// fakeUpstreamResponse is the response from fake upstream
type fakeUpstreamResponse struct {
	URI     string      `json:"uri"`
	Method  string      `json:"method"`
	Address string      `json:"address"`
	Headers http.Header `json:"headers"`
}

// fakeUpstreamService acts as a fake upstream service, returns the headers and request
type fakeUpstreamService struct{}

func (f *fakeUpstreamService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(testProxyAccepted, "true")

	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	if upgrade == "websocket" {
		websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
			var data []byte
			err := websocket.Message.Receive(ws, &data)
			if err != nil {
				ws.WriteClose(http.StatusBadRequest)
				return
			}
			content, _ := json.Marshal(&fakeUpstreamResponse{
				URI:     r.RequestURI,
				Method:  r.Method,
				Address: r.RemoteAddr,
				Headers: r.Header,
			})
			_ = websocket.Message.Send(ws, content)
		}).ServeHTTP(w, r)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		content, _ := json.Marshal(&fakeUpstreamResponse{
			// r.RequestURI is what was received by the proxy.
			// r.URL.String() is what is actually sent to the upstream service.
			// KEYCLOAK-10864, KEYCLOAK-11276, KEYCLOAK-13315
			URI:     r.URL.String(),
			Method:  r.Method,
			Address: r.RemoteAddr,
			Headers: r.Header,
		})
		_, _ = w.Write(content)
	}
}

type fakeToken struct {
	claims DefaultTestTokenClaims
}

func newTestToken(issuer string) *fakeToken {
	claims := defTestTokenClaims
	claims.Exp = time.Now().Add(1 * time.Hour).Unix()
	claims.Iat = time.Now().Unix()
	claims.Iss = issuer

	return &fakeToken{claims: claims}
}

// getToken returns a JWT token from the clains
func (t *fakeToken) getToken() (string, error) {
	input := []byte("")
	block, _ := pem.Decode([]byte(fakePrivateKey))
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS8PrivateKey(input)

	if err0 != nil {
		return "", err0
	}

	alg := gojose.SignatureAlgorithm("RS256")
	privKey := &gojose.JSONWebKey{Key: priv, Algorithm: string(alg), KeyID: "test-kid"}
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: alg, Key: privKey}, nil)

	if err != nil {
		return "", err
	}

	b := jwt.Signed(signer).Claims(&t.claims)
	jwt, err := b.CompactSerialize()

	if err != nil {
		return "", err
	}

	return jwt, nil
}

// getUnsignedToken returns a unsigned JWT token from the clains
func (t *fakeToken) getUnsignedToken() (string, error) {
	input := []byte("")
	block, _ := pem.Decode([]byte(fakePrivateKey))
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS8PrivateKey(input)

	if err0 != nil {
		return "", err0
	}

	alg := gojose.SignatureAlgorithm("RS256")
	privKey := &gojose.JSONWebKey{Key: priv, Algorithm: string(alg), KeyID: ""}
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: alg, Key: privKey}, nil)

	if err != nil {
		return "", err
	}

	b := jwt.Signed(signer).Claims(&t.claims)
	jwt, err := b.CompactSerialize()

	if err != nil {
		return "", err
	}

	items := strings.Split(jwt, ".")
	jwt = strings.Join(items[0:1], ".")

	return jwt, nil
}

// setExpiration sets the expiration of the token
func (t *fakeToken) setExpiration(tm time.Time) {
	t.claims.Exp = tm.Unix()
}

// addGroups adds groups to then token
func (t *fakeToken) addGroups(groups []string) {
	t.claims.Groups = groups
}

// addRealmRoles adds realms roles to token
func (t *fakeToken) addRealmRoles(roles []string) {
	t.claims.RealmAccess.Roles = roles
}

// addClientRoles adds client roles to the token
func (t *fakeToken) addClientRoles(client string, roles []string) {
	t.claims.ResourceAccess = make(map[string]RoleClaim)
	t.claims.ResourceAccess[client] = RoleClaim{Roles: roles}
}
