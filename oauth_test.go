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
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/stretchr/testify/assert"
	jose2 "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type fakeAuthServer struct {
	location   *url.URL
	key        jose2.JSONWebKey
	server     *httptest.Server
	expiration time.Duration
}

const fakePrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxMLIwi//YG6GPdYUPaV0PCXBEXjg2Xhf8/+NMB/1nt+wip4Z
rrAQf14PTCTlN4sbc2QGgRGtYikJBHQyfg/lCthrnasfdgL8c6SErr7Db524SqiD
m+/yKGI680LmBUIPkA0ikCJgb4cYVCiJ3HuYnFZUTsUAeK14SoXgcJdWulj0h6aP
iUIg5VrehuqAG+1RlK+GURgr9DbOmXJ/SYVKX/QArdBzjZ3BiQ1nxWWwBCLHfwv4
8bWxPJIbDDnUNl6LolpSJkxg4qlp+0I/xgEveK1n1CMEA0mHuXFHeekKO72GDKAk
h89C9qVF2GmpDfo8G0D3lFm2m3jFNyMQTWkSkwIDAQABAoIBADwhOrD9chHKNQQY
tD7SnV70OrhYNH7BJrGuWztlyO4wdgcmobqc263Q1OP0Mohy3oS5ALPY7x+cYsEV
sYiM2vYhhWG9tfOenf/JOzMb4SXvES7fqLiy71IgEtvcieb5dUAUg4eAue/bXTf6
24ahztWYHFOmKKq4eJZtq1U9KqfvlW1T4bg3mXV70huvfoMhYKwYryTOsQ5yiYCf
Yo4UGUBLfg3capIB5gxQdcqdDk+UTe9be7GQBj+3oziALb1nIhW7cpy0nw/r22A5
pv1FbRqND2VYKjZCQyUbxnjty5eDIW7fKBIh0Ez9yZHqz4KHb1u/KlFm31NGZpMU
Xs/WN+ECgYEA+kcAi7fTUjagqov5a4Y595ptu2gmU4Cxr+EBhMWadJ0g7enCXjTI
HAFEsVi2awbSRswjxdIG533SiKg8NIXThMntfbTm+Kw3LSb0/++Zyr7OuKJczKvQ
KfjAHvqsV8yJqy1gApYqVOeU4/jMLDs2sMY59/IQNkUVHNncZO09aa8CgYEAyUKG
BUyvxSim++YPk3OznBFZhqJqR75GYtWSu91BgZk/YmgYM4ht2u5q96AIRbJ664Ks
v93varNfqyKN1BN3JPLw8Ph8uX/7k9lMmECXoNp2Tm3A54zlsHyNOGOSvU7axvUg
PfIhpvRZKA0QQK3c1CZDghs94siJeBSIpuzCsl0CgYEA8Z28LCZiT3tHbn5FY4Wo
zp36k7L/VRvn7niVg71U2IGc+bHzoAjqqwaab2/KY9apCAop+t9BJRi2OJHZ1Ybg
5dAfg30ygh2YAvIaEj8YxL+iSGMOndS82Ng5eW7dFMH0ohnjF3wrD96mQdO+IHFl
4hDsg67f8dSNhlXYzGKwKCcCgYEAlAsrKprOcOkGbCU/L+fcJuFcSX0PUNbWT71q
wmZu2TYxOeH4a2/f3zuh06UUcLBpWvQ0vq4yfvqTVP+F9IqdCcDrG1at6IYMOSWP
AjABWYFZpTd2vt0V2EzGVMRqHHb014VYwjhqKLV1H9D8M5ew6R18ayg+zaNV+86e
9qsSTMECgYEA322XUN8yUBTTWBkXY7ipzTHSWkxMuj1Pa0gtBd6Qqqu3v7qI+jMZ
hlWS2akhJ+3e7f3+KCslG8YMItld4VvAK0eHKQbQM/onav/+/iiR6C2oRBm3OwqO
Ka0WPQGKjQJhZRtqDAT3sfnrEEUa34+MkXQeKFCu6Yi0dRFic4iqOYU=
-----END RSA PRIVATE KEY-----
`

const fakeCert = `
-----BEGIN CERTIFICATE-----
MIIDYjCCAkqgAwIBAgIJAIiInNaxV42WMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwIBcNMjAxMjE4MDEzNjUwWhgPMjEyMDExMjQwMTM2NTBa
MEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJ
bnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDEwsjCL/9gboY91hQ9pXQ8JcEReODZeF/z/40wH/We37CKnhmusBB/
Xg9MJOU3ixtzZAaBEa1iKQkEdDJ+D+UK2Gudqx92AvxzpISuvsNvnbhKqIOb7/Io
YjrzQuYFQg+QDSKQImBvhxhUKInce5icVlROxQB4rXhKheBwl1a6WPSHpo+JQiDl
Wt6G6oAb7VGUr4ZRGCv0Ns6Zcn9JhUpf9ACt0HONncGJDWfFZbAEIsd/C/jxtbE8
khsMOdQ2XouiWlImTGDiqWn7Qj/GAS94rWfUIwQDSYe5cUd56Qo7vYYMoCSHz0L2
pUXYaakN+jwbQPeUWbabeMU3IxBNaRKTAgMBAAGjUzBRMB0GA1UdDgQWBBQAgj89
hTjJ2QkGUTipvlmM59Q1KDAfBgNVHSMEGDAWgBQAgj89hTjJ2QkGUTipvlmM59Q1
KDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAhkC1rZ8MO3v3e
AUZXL2qUeT6CIEjCBlIBDPdoSVny9sixtzYLcNktL9Q3q/rg7yM7wpNuPJjfvZ77
mI5f6FZfDYaU8d92Y+n1EJVD3w0hMz450tyGN+dwcP+6espLIVjHiPBQPbXLw5Ii
z9rK0uqIWSfbjbVPkmZQiEkicaHhwmQzhkB+nVOCz/1vbMIja/ssPAFTRI9EntsQ
oPk9iblhvtUKX4/NWQPXbE2E7GGtIXaiuK7+gNGrbq0ifhIVhf8rUJX1AMGaqaJD
pwV3LE2/HWIp0xtWA33YyU8jQOPWROCW5zvD6hESGYwg3ll7KdLv49h0XTJddpCj
drpOwbzZ
-----END CERTIFICATE-----
`

type fakeOidcDiscoveryResponse struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

type fakeAuthConfig struct {
	EnableTLS bool
}

// newFakeAuthServer simulates a oauth service
func newFakeAuthServer(config *fakeAuthConfig) *fakeAuthServer {
	certBlock, _ := pem.Decode([]byte(fakeCert))

	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(certBlock.Bytes)

	if err != nil {
		panic("failed to parse certificate from block, error: " + err.Error())
	}

	x5tSHA1 := sha1.Sum(cert.Raw)
	x5tSHA256 := sha256.Sum256(cert.Raw)

	service := &fakeAuthServer{
		key: jose2.JSONWebKey{
			Key:                         cert.PublicKey,
			KeyID:                       "test-kid",
			Algorithm:                   "RS256",
			Certificates:                []*x509.Certificate{cert},
			CertificateThumbprintSHA1:   x5tSHA1[:],
			CertificateThumbprintSHA256: x5tSHA256[:],
		},
	}

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/auth/realms/hod-test/.well-known/openid-configuration", service.discoveryHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/certs", service.keysHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/auth", service.authHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/userinfo", service.userInfoHandler)
	r.Post("/auth/realms/hod-test/protocol/openid-connect/logout", service.logoutHandler)
	r.Post("/auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)

	if config.EnableTLS {
		service.server = httptest.NewTLSServer(r)
	} else {
		service.server = httptest.NewServer(r)
	}

	location, err := url.Parse(service.server.URL)
	if err != nil {
		panic("unable to create fake oauth service, error: " + err.Error())
	}
	service.location = location
	service.expiration = time.Duration(1) * time.Hour

	return service
}

func (r *fakeAuthServer) Close() {
	r.server.Close()
}

func (r *fakeAuthServer) getLocation() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test", r.location.Scheme, r.location.Host)
}

func (r *fakeAuthServer) getRevocationURL() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/logout", r.location.Scheme, r.location.Host)
}

func (r *fakeAuthServer) setTokenExpiration(tm time.Duration) *fakeAuthServer {
	r.expiration = tm
	return r
}

func (r *fakeAuthServer) discoveryHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, fakeOidcDiscoveryResponse{
		Issuer:      fmt.Sprintf("%s://%s/auth/realms/hod-test", r.location.Scheme, r.location.Host),
		AuthURL:     fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/auth", r.location.Scheme, r.location.Host),
		TokenURL:    fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/token", r.location.Scheme, r.location.Host),
		JWKSURL:     fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/certs", r.location.Scheme, r.location.Host),
		UserInfoURL: fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/userinfo", r.location.Scheme, r.location.Host),
		Algorithms:  []string{"RS256"},
	})
}

func (r *fakeAuthServer) keysHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, jose2.JSONWebKeySet{Keys: []jose2.JSONWebKey{r.key}})
}

func (r *fakeAuthServer) authHandler(w http.ResponseWriter, req *http.Request) {
	state := req.URL.Query().Get("state")
	redirect := req.URL.Query().Get("redirect_uri")
	if redirect == "" {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if state == "" {
		state = "/"
	}

	randString, err := getRandomString(32)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	redirectionURL := fmt.Sprintf("%s?state=%s&code=%s", redirect, state, randString)

	http.Redirect(w, req, redirectionURL, http.StatusSeeOther)
}

func (r *fakeAuthServer) logoutHandler(w http.ResponseWriter, req *http.Request) {
	if refreshToken := req.FormValue("refresh_token"); refreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (r *fakeAuthServer) userInfoHandler(w http.ResponseWriter, req *http.Request) {
	items := strings.Split(req.Header.Get("Authorization"), " ")
	if len(items) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := jwt.ParseSigned(items[1])

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	user, err := extractIdentity(token)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	renderJSON(http.StatusOK, w, req, map[string]interface{}{
		"sub":                user.claims["sub"],
		"name":               user.claims["name"],
		"given_name":         user.claims["given_name"],
		"family_name":        user.claims["familty_name"],
		"preferred_username": user.claims["preferred_username"],
		"email":              user.claims["email"],
		"picture":            user.claims["picture"],
	})
}

func (r *fakeAuthServer) tokenHandler(w http.ResponseWriter, req *http.Request) {
	expires := time.Now().Add(r.expiration)
	token := newTestToken(r.getLocation())
	token.setExpiration(expires)

	// sign the token with the private key
	jwt, err := token.getToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch req.FormValue("grant_type") {
	case GrantTypeUserCreds:
		username := req.FormValue("username")
		password := req.FormValue("password")
		if username == "" || password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if username == validUsername && password == validPassword {
			renderJSON(http.StatusOK, w, req, tokenResponse{
				IDToken:      jwt,
				AccessToken:  jwt,
				RefreshToken: jwt,
				ExpiresIn:    float64(expires.UTC().Second()),
			})
			return
		}
		renderJSON(http.StatusUnauthorized, w, req, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid user credentials",
		})
	case GrantTypeRefreshToken:
		fallthrough
	case GrantTypeAuthCode:
		renderJSON(http.StatusOK, w, req, tokenResponse{
			IDToken:      jwt,
			AccessToken:  jwt,
			RefreshToken: jwt,
			ExpiresIn:    float64(expires.Second()),
		})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func TestGetUserinfo(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token, err := newTestToken(idp.getLocation()).getToken()
	assert.NoError(t, err)
	tokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)

	ctx, cancel := context.WithTimeout(context.Background(), px.config.OpenIDProviderTimeout)
	defer cancel()

	userInfo, err := px.provider.UserInfo(ctx, tokenSource)
	assert.NoError(t, err)

	claims := DefaultTestTokenClaims{}
	err = userInfo.Claims(&claims)

	assert.NoError(t, err)
	assert.NotEqual(t, (DefaultTestTokenClaims{}), claims)
}

func TestTokenExpired(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token := newTestToken(idp.getLocation())
	cs := []struct {
		Expire time.Duration
		OK     bool
	}{
		{
			Expire: 1 * time.Hour,
			OK:     true,
		},
		{
			Expire: -5 * time.Hour,
		},
	}
	for i, x := range cs {
		token.setExpiration(time.Now().Add(x.Expire))
		jwt, err := token.getToken()
		if err != nil {
			t.Errorf("case %d unable to sign the token, error: %s", i, err)
			continue
		}

		verifier := px.provider.Verifier(
			&oidc3.Config{
				ClientID:          px.config.ClientID,
				SkipClientIDCheck: true,
			},
		)
		_, err = verifier.Verify(context.Background(), jwt)

		if x.OK && err != nil {
			t.Errorf("case %d, expected: %t got error: %s", i, x.OK, err)
		}
		if !x.OK && err == nil {
			t.Errorf("case %d, expected: %t got no error", i, x.OK)
		}
	}
}

func getRandomString(n int) (string, error) {
	b := make([]rune, n)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(n)))

		if err != nil {
			return "", err
		}

		b[i] = letterRunes[num.Int64()]
	}
	return string(b), nil
}

func renderJSON(code int, w http.ResponseWriter, req *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
