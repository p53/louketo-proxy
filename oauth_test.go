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
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jochasinga/relay"
	"github.com/stretchr/testify/assert"
	jose2 "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type fakeAuthServer struct {
	location      *url.URL
	proxyLocation string
	key           jose2.JSONWebKey
	server        *httptest.Server
	expiration    time.Duration
}

const fakePrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0E2cxe1nDLCE7
U4k3Zvd4nMiAHqKZBxCPuADbzR15IcOlcLTqBBPNCpwgXSZwobgeEl1aDi9fAsEK
XZNPU2GbIPmw5nBHfE/RZ5JmU2GXdEm2R2Irnwpi8kk8hHWPK4ETN8+6yk4qKF1P
xkoHIilm37T8zWoqzYtIuj3/Obqi3Io67pvKYCsA1qMR3RRlI9IegUAc3WHMrKIL
YQShEo66pg8cTb7Q/LdgaSxR3KLi9eox0vTE72AmVQoBZlZ/ej7sJpwPKKmkszXU
AMPGf1s3Hx/lgDtM3MxtHk0pxLBHgP+P5i77dF9edW9hc/fMirdOmCpYZboox3Lr
IGoVcJodAgMBAAECggEAahX4OEV0BzArT7kR4GqvpgWvdRMXNVHdJt3+237GO0Nx
8DgqzKakR6pVeheGeto7DrRA/LnYnH+R3Bpum1AC85IEp3vKb8LDfxkmPVQn7ULb
3h/FrO8f/lTAYn+ihjrZ6sl5fpCKZfmrp0CpAfTVMT7fcANP5XF7+deGiKKo2iJW
g1O8ZflihEDclPtqBABpRjBejRiv+7YUR/8HeqNUjmLEWGwAHEqrsFwMz92CvJd+
N9U03Cs1LvpXkIXHG84SUvbDQRuyxoONXKauasYr01kMFqBTjOc86xXSNsMWCzu4
UaWB1ZtMugNjyMNdVQUSLz1EABI4aQhWptmJud4LwQKBgQDuq3L3gOEaCmi4+46B
vnHdu0j6shULDdjxb4r8xY4tf4T8c+/4Lm/siM2+Fb+g01OECVRPVQlFd0inoTy+
j8ARveuRvrrGzAS5CB1tl+PiLJ5HbdltzTrV3ZUb99fvbnHAi7up7daZg9IBfc1n
ABWTA1pdOzK82g8qDeFBMSCJUQKBgQDBJsVvbheKL2xdKyIzd2je3gwInkYpAUqa
S9zS6h5wpG8TqFt90OYvmawyvTwspgp3nUUHTv9Z5FChFPgtoZJJO/0OYt6DjpUs
Ohg3DhthG5q6fG+kS2zGGHxQSCzQB6CvKdeZ5iMO/L0arKs9UuIdLV/SNfMdKm6v
8tdcYCdRDQKBgQC5cCzbcR91BDFpyMpotHf0N9f0MPl4pUGyFWCAFV7qqvHA1LPW
uP3tYj25O1ywsIFrTXRcT03s00l4NSblSPuKzW2CyBaG722b9lonFKTSzqgMB6Ww
Uo0sLgX0vRThy4ZGfEtLNKhQjsNUtVIqfT5GA4zqc1xwr1yo6C/kXy9QgQKBgQCX
Vh552WOeRNv9/+7TLms/u/Dny8MjG7ztOiVyKDfjgCL73vyYjtXcU+ak9rowLYSk
BdhxCoduUkKOg5SUhDTPJq522CaKI2xj87zHXkk7g9pu5VLAAszeRY8ZhAOAl4lh
1UH1dmjftE0imkmtScSaodOjK9wpbPa+62GsIjaL/QKBgFdwyRTp7GzbTDsQ94bA
u6MoFT7Ln2I48zaA07G76r9t3oOAsO8doED+hdSwlzA7RyM2l6jOkJli+NXmVA1G
eJN9LU6cvrgsyw2XF54Zi+sRdXb1LU9pVHcINIOwY7zNMvYRAkStkxhPXUDBinxo
wqVzh3GBBzPxAb3aM8Tu0W+1
-----END PRIVATE KEY-----
`

const fakeCert = `
-----BEGIN CERTIFICATE-----
MIIDXjCCAkagAwIBAgIUVUN+CQWv4afaLwWyBYA3hzYUK1UwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTAzMTcyMzU2NDFaFw00MTAz
MTIyMzU2NDFaMHgxCzAJBgNVBAYTAlhYMQwwCgYDVQQIDANOL0ExDDAKBgNVBAcM
A04vQTEgMB4GA1UECgwXU2VsZi1zaWduZWQgY2VydGlmaWNhdGUxKzApBgNVBAMM
IjEyMC4wLjAuMTogU2VsZi1zaWduZWQgY2VydGlmaWNhdGUwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC0E2cxe1nDLCE7U4k3Zvd4nMiAHqKZBxCPuADb
zR15IcOlcLTqBBPNCpwgXSZwobgeEl1aDi9fAsEKXZNPU2GbIPmw5nBHfE/RZ5Jm
U2GXdEm2R2Irnwpi8kk8hHWPK4ETN8+6yk4qKF1PxkoHIilm37T8zWoqzYtIuj3/
Obqi3Io67pvKYCsA1qMR3RRlI9IegUAc3WHMrKILYQShEo66pg8cTb7Q/LdgaSxR
3KLi9eox0vTE72AmVQoBZlZ/ej7sJpwPKKmkszXUAMPGf1s3Hx/lgDtM3MxtHk0p
xLBHgP+P5i77dF9edW9hc/fMirdOmCpYZboox3LrIGoVcJodAgMBAAGjEzARMA8G
A1UdEQQIMAaHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAIyJDSwNHcr6xstklu/K
HypaivAFa95eAI1QrCsJF1V/mm9LEEGes/iHbvkpFJHQKhJkO6aoQmek8zF2wKc/
3RhnxrR32/ujHetJFka/LtvytVhXoSqkUWeaXOfBOCR/XrwTwRHzbbCNJpUsetXr
9aeDvSrtuB/AaRU2tBlQ9GR1H+CcoBgDmD3IpuKCievvJbmU+KzuW9AUg6d0yLNP
2VtZUA/9JpF9PZOMPw+iOhmjhTqfRD2QvbkR7e34d+1mLBn524KIc8Y2U3OMpDuG
BfVHOQ5JhTNGn9aogxpzF3L9oMUZ+fCbobVyHMMyE6b82H8FUpm1FDJpZaILI5kT
isg=
-----END CERTIFICATE-----
`

const fakeCA = `
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUCDok30ZdCF+fn3KuK/odxYyqJR0wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTAzMTcyMzM0MTZaFw00MTAz
MTIyMzM0MTZaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDVwtjZoJiDALDrovZviHWRhCgPXBxaLYoi5d3sa1UX
F28fEHHcqHChMHng0XmQDwBRvdGXfEL+d+TyOk6H2EfC5YzF4BFA9jEuX/xvINWd
STYFkq4uqjFVl5/1WA6fme0UfpIT+BNSqMufH1Q63rBMgZmQS10/mYBWMXzW9MpC
Mc/VqGiNfVD1fGf3d86gmteHPSR0yABeIyF3BhWkea50sNu7jz7Vw65OdAZxuw9W
o0UGT0Bc2ml8clnkhnXipvyYUJQqVgyCcFsI5rc5Gsie8rJ36LyZsf3nnGF56hjw
i49YmH3z0xl70XUIxkm2o2h55P5tgA5KauZB3v0mFuTxAgMBAAGjUzBRMB0GA1Ud
DgQWBBQ5Fw8voBMO1GoQl1Qqm5UdFzbuHDAfBgNVHSMEGDAWgBQ5Fw8voBMO1GoQ
l1Qqm5UdFzbuHDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDU
msNwnbl8uI4VcFsiyrNS7Np2xLmcs6LgCfP9WzsA4h6Ag2K15d9eh+CgaL59oza8
q0pxRcasLFtuk0egRc+HwNR5ynwt4W2al4zB1dRpTWgrnNaoOBdhsb3ifNEjFcYD
di+dPoKLST6xqKGh0zl+W4FLevUDg7KzJVcttaQ8tFh5KafcmSHZ7PfNbFsfbx/R
wthh/acHnCkOndcTBEoHdIv283bONr1Zpe9Sok2mM3uVsCvv6fRYnG+mRqcZ3C9d
hHbOowWOqA2rxWxSHrkBTQju/uYQKG5GMnXWgZokUgwRDMaNMpdp03GG4Bgeg/06
8cad+/Bp0tBaKmnCtxOC
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
	EnableTLS   bool
	EnableProxy bool
	Expiration  time.Duration
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
	r.Post("/auth/realms/hod-test/protocol/openid-connect/revoke", service.revocationHandler)
	r.Post("/auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)

	if config.EnableTLS {
		service.server = httptest.NewTLSServer(r)
	} else {
		service.server = httptest.NewServer(r)
	}

	if config.EnableProxy {
		delay := time.Duration(0) * time.Second
		proxy := relay.NewProxy(delay, service.server)
		service.proxyLocation = proxy.URL
	}

	location, err := url.Parse(service.server.URL)
	if err != nil {
		panic("unable to create fake oauth service, error: " + err.Error())
	}
	service.location = location
	service.expiration = time.Duration(1) * time.Hour

	if config.Expiration.Seconds() > 0 {
		service.expiration = config.Expiration
	}

	return service
}

func (r *fakeAuthServer) Close() {
	r.server.Close()
}

func (r *fakeAuthServer) getProxyURL() string {
	return r.proxyLocation
}

func (r *fakeAuthServer) getLocation() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test", r.location.Scheme, r.location.Host)
}

func (r *fakeAuthServer) getRevocationURL() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/revoke", r.location.Scheme, r.location.Host)
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
	w.WriteHeader(http.StatusNoContent)
}

func (r *fakeAuthServer) revocationHandler(w http.ResponseWriter, req *http.Request) {
	// according RFC revocation endpoint can be access/refresh token, keycloak
	// implementation https://github.com/keycloak/keycloak/pull/6704, accepts
	// refresh/offline tokens
	if token := req.FormValue("token"); token == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
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
	case GrantTypeClientCreds:
		clientID := req.FormValue("client_id")
		clientSecret := req.FormValue("client_secret")

		if clientID == "" || clientSecret == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if clientID == validUsername && clientSecret == validPassword {
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
