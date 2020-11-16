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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"crypto/x509"
	"encoding/pem"

	"github.com/coreos/go-oidc/jose"
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

var (
	defaultTestTokenClaims = jose.Claims{
		"aud":                "test",
		"azp":                "clientid",
		"client_session":     "f0105893-369a-46bc-9661-ad8c747b1a69",
		"email":              "gambol99@gmail.com",
		"family_name":        "Jayawardene",
		"given_name":         "Rohith",
		"iat":                "1450372669",
		"iss":                "test",
		"jti":                "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
		"name":               "Rohith Jayawardene",
		"nbf":                0,
		"preferred_username": "rjayawardene",
		"session_state":      "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
		"sub":                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
		"typ":                "Bearer",
	}
)

type DefaultTestTokenClaims struct {
	aud                string
	azp                string
	client_session     string
	email              string
	family_name        string
	given_name         string
	iat                string
	iss                string
	jti                string
	name               string
	nbf                int
	preferred_username string
	session_state      string
	sub                string
	typ                string
}

var defTestTokenClaims = DefaultTestTokenClaims{
	aud:                "test",
	azp:                "clientid",
	client_session:     "f0105893-369a-46bc-9661-ad8c747b1a69",
	email:              "gambol99@gmail.com",
	family_name:        "Jayawardene",
	given_name:         "Rohith",
	iat:                "1450372669",
	iss:                "test",
	jti:                "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
	name:               "Rohith Jayawardene",
	nbf:                0,
	preferred_username: "rjayawardene",
	session_state:      "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
	sub:                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
	typ:                "Bearer",
}

var testPrivRSAKey1 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIHBvDHAr7jh8h
xaqBCl11fjI9YZtdC5b3HtXTXZW3c2dIOImNUjffT8POP6p5OpzivmC1om7iOyuZ
3nJjC9LT3zqqs3f2i5d4mImxEuqG6uWdryFfkp0uIv5VkjVO+iQWd6pDAPGP7r1Z
foXCleyCtmyNH4JSkJneNPOk/4BxO8vcvRnCMT/Gv81IT6H+OQ6OovWOuJr8RX9t
1wuCjC9ezZxeI9ONffhiO5FMrVh5H9LJTl3dPOVa4aEcOvgd45hBmvxAyXqf8daE
6Kl2O7vQ4uwgnSTVXYIIjCjbepuersApIMGx/XPSgiU1K3Xtah/TBvep+S3VlwPc
q/QH25S9AgMBAAECggEAe+y8XKYfPw4SxY1uPB+5JSwT3ON3nbWxtjSIYy9Pqp5z
Vcx9kuFZ7JevQSk4X38m7VzM8282kC/ono+d8yy9Uayq3k/qeOqV0X9Vti1qxEbw
ECkG1/MqGApfy4qSLOjINInDDV+mOWa2KJgsKgdCwuhKbVMYGB2ozG2qfYIlfvlY
vLcBEpGWmswJHNmkcjTtGFIyJgPbsI6ndkkOeQbqQKAaadXtG1xUzH+vIvqaUl/l
AkNf+p4qhPkHsoAWXf1qu9cYa2T8T+mEo79AwlgVC6awXQWNRTiyClDJC7cu6NBy
ZHXCLFMbalzWF9qeI2OPaFX2x3IBWrbyDxcJ4TSdQQKBgQD/Fp/uQonMBh1h4Vi4
HlxZdqSOArTitXValdLFGVJ23MngTGV/St4WH6eRp4ICfPyldsfcv6MZpNwNm1Rn
lB5Gtpqpby1dsrOSfvVbY7U3vpLnd8+hJ/lT5zCYt5Eor46N6iWRkYWzNe4PixiF
z1puGUvFCbZdeeACVrPLmW3JKQKBgQDI0y9WTf8ezKPbtap4UEE6yBf49ftohVGz
p4iD6Ng1uqePwKahwoVXKOc179CjGGtW/UUBORAoKRmxdHajHq6LJgsBxpaARz21
COPy99BUyp9ER5P8vYn63lC7Cpd/K7uyMjaz1DAzYBZIeVZHIw8O9wuGNJKjRFy9
SZyD3V0ddQKBgFMdohrWH2QVEfnUnT3Q1rJn0BJdm2bLTWOosbZ7G72TD0xAWEnz
sQ1wXv88n0YER6X6YADziEdQykq8s/HT91F/KkHO8e83zP8M0xFmGaQCOoelKEgQ
aFMIX3NDTM7+9OoUwwz9Z50PE3SJFAJ1n7eEEoYvNfabQXxBl+/dHEKRAoGAPEvU
EaiXacrtg8EWrssB2sFLGU/ZrTciIbuybFCT4gXp22pvXXAHEvVP/kzDqsRhLhwb
BNP6OuSkNziNikpjA5pngZ/7fgZly54gusmW/m5bxWdsUl0iOXVYbeAvPlqGH2me
LP4Pfs1hw17S/cbT9Z1NE31jbavP4HFikeD73SUCgYEArQfuudml6ei7XZ1Emjq8
jZiD+fX6e6BD/ISatVnuyZmGj9wPFsEhY2BpLiAMQHMDIvH9nlKzsFvjkTPB86qG
jCh3D67Os8eSBk5uRC6iW3Fc4DXvB5EFS0W9/15Sl+V5vXAcrNMpYS82OTSMG2Gt
b9Ym/nxaqyTu0PxajXkKm5Q=
-----END PRIVATE KEY-----`

func TestNewKeycloakProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.DiscoveryURL = newFakeAuthServer().getLocation()
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
	p := newFakeProxy(nil)
	token := newTestToken(p.idp.getLocation())
	token.addRealmRoles([]string{fakeAdminRole})
	signed, _ := p.idp.signToken(token.claims)
	uri := "/auth_all/test"
	requests := []fakeRequest{
		{
			URI:           uri,
			RawToken:      signed.Encode(),
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Email":    "gambol99@gmail.com",
				"X-Auth-Roles":    "role:admin",
				"X-Auth-Subject":  token.claims["sub"].(string),
				"X-Auth-Token":    signed.Encode(),
				"X-Auth-Userid":   "rjayawardene",
				"X-Auth-Username": "rjayawardene",
			},
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: `"uri":"` + uri + `"`,
		},
	}
	p.RunTests(t, requests)
}

func TestForwardingProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableForwarding = true
	cfg.ForwardingDomains = []string{}
	cfg.ForwardingUsername = validUsername
	cfg.ForwardingPassword = validPassword
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
	p := newFakeProxy(cfg)
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
	newFakeProxy(cfg).RunTests(t, requests)
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
	newFakeProxy(c).RunTests(t, requests)
}

func TestAuthTokenHeaderDisabled(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableTokenHeader = false
	p := newFakeProxy(c)
	token := newTestToken(p.idp.getLocation())
	signed, _ := p.idp.signToken(token.claims)

	requests := []fakeRequest{
		{
			URI:                    "/auth_all/test",
			RawToken:               signed.Encode(),
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
	newFakeProxy(c).RunTests(t, requests)
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
	}
	newFakeProxy(config).RunTests(t, requests)
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
	newFakeProxy(cfg).RunTests(t, requests)
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
	newFakeProxy(c).RunTests(t, requests)
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
	newFakeProxy(c).RunTests(t, requests)
}

func TestCustomResponseHeaders(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.ResponseHeaders = map[string]string{
		"CustomReponseHeader": "True",
	}
	p := newFakeProxy(c)

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
	c := newFakeKeycloakConfig()
	p := newFakeProxy(c)
	// create two token, one with a bad client id
	bad := newTestToken(p.idp.getLocation())
	bad.merge(jose.Claims{"aud": "bad_client_id"})
	badSigned, _ := p.idp.signToken(bad.claims)
	// and the good
	good := newTestToken(p.idp.getLocation())
	goodSigned, _ := p.idp.signToken(good.claims)
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			RawToken:      goodSigned.Encode(),
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/auth_all/test",
			RawToken:     badSigned.Encode(),
			ExpectedCode: http.StatusForbidden,
		},
	}
	p.RunTests(t, requests)
}

func TestAuthTokenHeaderEnabled(t *testing.T) {
	p := newFakeProxy(nil)
	token := newTestToken(p.idp.getLocation())
	signed, _ := p.idp.signToken(token.claims)

	requests := []fakeRequest{
		{
			URI:      "/auth_all/test",
			RawToken: signed.Encode(),
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Token": signed.Encode(),
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
	p := newFakeProxy(c)
	token := newTestToken(p.idp.getLocation())
	signed, _ := p.idp.signToken(token.claims)

	requests := []fakeRequest{
		{
			URI: "/auth_all/test",
			Cookies: []*http.Cookie{
				{Name: c.CookieAccessName, Value: signed.Encode()},
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
	auth := newFakeAuthServer()
	if config == nil {
		config = newFakeKeycloakConfig()
	}
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
		ClientID:                   fakeClientID,
		ClientSecret:               fakeSecret,
		CookieAccessName:           "kc-access",
		CookieRefreshName:          "kc-state",
		DisableAllLogging:          true,
		DiscoveryURL:               "127.0.0.1:0",
		EnableAuthorizationCookies: true,
		EnableAuthorizationHeader:  true,
		EnableLogging:              false,
		EnableLoginHandler:         true,
		EnableTokenHeader:          true,
		EnableCompression:          false,
		Listen:                     "127.0.0.1:0",
		OAuthURI:                   "/oauth",
		OpenIDProviderTimeout:      time.Second * 5,
		Scopes:                     []string{},
		Verbose:                    false,
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

func makeTestCodeFlowLogin(location string) (*http.Response, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	// step: get the redirect
	var resp *http.Response
	for count := 0; count < 4; count++ {
		req, err := http.NewRequest(http.MethodGet, location, nil)
		if err != nil {
			return nil, err
		}
		// step: make the request
		resp, err = http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusSeeOther {
			return nil, errors.New("no redirection found in resp")
		}
		location = resp.Header.Get("Location")
		if !strings.HasPrefix(location, "http") {
			location = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, location)
		}
	}
	return resp, nil
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
	claims jose.Claims
}

func newTestToken(issuer string) *fakeToken {
	claims := make(jose.Claims)
	for k, v := range defaultTestTokenClaims {
		claims[k] = v
	}
	claims.Add("exp", float64(time.Now().Add(1*time.Hour).Unix()))
	claims.Add("iat", float64(time.Now().Unix()))
	claims.Add("iss", issuer)

	return &fakeToken{claims: claims}
}

// merge is responsible for merging claims into the token
func (t *fakeToken) merge(claims jose.Claims) {
	for k, v := range claims {
		t.claims.Add(k, v)
	}
}

// getToken returns a JWT token from the clains
func (t *fakeToken) getToken() (string, error) {
	input := []byte("")
	block, _ := pem.Decode([]byte(testPrivRSAKey1))
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS1PrivateKey(input)

	if err0 != nil {
		return "", err0
	}

	alg := gojose.SignatureAlgorithm("RS256")
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: alg, Key: priv}, nil)

	b := jwt.Signed(signer).Claims(&defTestTokenClaims)
	jwt, err := b.FullSerialize()

	if err != nil {
		return "", err
	}

	return jwt, nil
}

// setExpiration sets the expiration of the token
func (t *fakeToken) setExpiration(tm time.Time) {
	t.claims.Add("exp", float64(tm.Unix()))
}

// addGroups adds groups to then token
func (t *fakeToken) addGroups(groups []string) {
	t.claims.Add("groups", groups)
}

// addRealmRoles adds realms roles to token
func (t *fakeToken) addRealmRoles(roles []string) {
	t.claims.Add("realm_access", map[string]interface{}{
		"roles": roles,
	})
}

// addClientRoles adds client roles to the token
func (t *fakeToken) addClientRoles(client string, roles []string) {
	t.claims.Add("resource_access", map[string]interface{}{
		client: map[string]interface{}{
			"roles": roles,
		},
	})
}
