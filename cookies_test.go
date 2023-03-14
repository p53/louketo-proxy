//go:build !e2e
// +build !e2e

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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/config"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/testsuite.go"
	"github.com/stretchr/testify/assert"
)

func TestCookieDomainHostHeader(t *testing.T) {
	svc := newTestService()
	resp, _, err := makeTestCodeFlowLogin(svc+"/admin", false)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == constant.AccessCookie {
			cookie = c
		}
	}
	defer resp.Body.Close()

	assert.NotNil(t, cookie)
	assert.Equal(t, cookie.Domain, "")
}

func TestCookieBasePath(t *testing.T) {
	const baseURI = "/base-uri"
	cfg := newFakeKeycloakConfig()
	cfg.BaseURI = baseURI

	_, _, svc := newTestProxyService(cfg)

	resp, _, err := makeTestCodeFlowLogin(svc+"/admin", false)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == constant.AccessCookie {
			cookie = c
		}
	}
	defer resp.Body.Close()

	assert.NotNil(t, cookie)
	assert.Equal(t, baseURI, cookie.Path)
}

func TestCookieWithoutBasePath(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	_, _, svc := newTestProxyService(cfg)

	resp, _, err := makeTestCodeFlowLogin(svc+"/admin", false)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == constant.AccessCookie {
			cookie = c
		}
	}
	defer resp.Body.Close()

	assert.NotNil(t, cookie)
	assert.Equal(t, "/", cookie.Path)
}

func TestCookieDomain(t *testing.T) {
	p, _, svc := newTestProxyService(nil)
	p.config.CookieDomain = "domain.com"
	resp, _, err := makeTestCodeFlowLogin(svc+"/admin", false)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == constant.AccessCookie {
			cookie = c
		}
	}
	defer resp.Body.Close()

	assert.NotNil(t, cookie)
	assert.Equal(t, cookie.Domain, "domain.com")
}

func TestDropCookie(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/",
		"we have not set the cookie, headers: %v", resp.Header())

	req = newFakeHTTPRequest("GET", "/admin")
	resp = httptest.NewRecorder()
	proxy.config.SecureCookie = false
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/",
		"we have not set the cookie, headers: %v", resp.Header())

	req = newFakeHTTPRequest("GET", "/admin")
	resp = httptest.NewRecorder()
	proxy.config.SecureCookie = true
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)
	assert.NotEqual(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; HttpOnly; Secure",
		"we have not set the cookie, headers: %v", resp.Header())

	proxy.config.CookieDomain = "test.com"
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)
	proxy.config.SecureCookie = false
	assert.NotEqual(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=test.com;",
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestDropRefreshCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.dropRefreshTokenCookie(req, resp, "test", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		constant.RefreshCookie+"=test; Path=/",
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestSessionOnlyCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	p.config.EnableSessionCookies = true

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.dropCookie(resp, req.Host, "test-cookie", "test-value", 1*time.Hour)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/",
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestSameSiteCookie(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/",
		"we have not set the cookie, headers: %v", resp.Header())

	req = newFakeHTTPRequest("GET", "/admin")
	resp = httptest.NewRecorder()
	proxy.config.SameSiteCookie = constant.SameSiteStrict
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; SameSite=Strict",
		"we have not set the cookie, headers: %v", resp.Header())

	req = newFakeHTTPRequest("GET", "/admin")
	resp = httptest.NewRecorder()
	proxy.config.SameSiteCookie = constant.SameSiteLax
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; SameSite=Lax",
		"we have not set the cookie, headers: %v", resp.Header())

	req = newFakeHTTPRequest("GET", "/admin")
	resp = httptest.NewRecorder()
	proxy.config.SameSiteCookie = constant.SameSiteNone
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/",
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestHTTPOnlyCookie(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/",
		"we have not set the cookie, headers: %v", resp.Header())

	req = newFakeHTTPRequest("GET", "/admin")
	resp = httptest.NewRecorder()
	proxy.config.HTTPOnlyCookie = true
	proxy.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; HttpOnly",
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestClearAccessTokenCookie(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	proxy.clearAccessTokenCookie(req, resp)
	assert.Contains(t, resp.Header().Get("Set-Cookie"),
		constant.AccessCookie+"=; Path=/; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestClearRefreshAccessTokenCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.clearRefreshTokenCookie(req, resp)
	assert.Contains(t, resp.Header().Get("Set-Cookie"),
		constant.RefreshCookie+"=; Path=/; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestClearAllCookies(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.clearAllCookies(req, resp)
	assert.Contains(t, resp.Header().Get("Set-Cookie"),
		constant.AccessCookie+"=; Path=/; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestGetMaxCookieChunkLength(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)
	req := newFakeHTTPRequest("GET", "/admin")

	proxy.config.HTTPOnlyCookie = true
	proxy.config.EnableSessionCookies = true
	proxy.config.SecureCookie = true
	proxy.config.SameSiteCookie = "Strict"
	proxy.config.CookieDomain = "1234567890"
	assert.Equal(t, proxy.getMaxCookieChunkLength(req, "1234567890"), 4017,
		"cookie chunk calculation is not correct")

	proxy.config.SameSiteCookie = "Lax"
	assert.Equal(t, proxy.getMaxCookieChunkLength(req, "1234567890"), 4020,
		"cookie chunk calculation is not correct")

	proxy.config.HTTPOnlyCookie = false
	proxy.config.EnableSessionCookies = false
	proxy.config.SecureCookie = false
	proxy.config.SameSiteCookie = "None"
	proxy.config.CookieDomain = ""
	assert.Equal(t, proxy.getMaxCookieChunkLength(req, ""), 4021,
		"cookie chunk calculation is not correct")
}

func TestCustomCookieNames(t *testing.T) {
	customStateName := "customState"
	customRedirectName := "customRedirect"
	customAccessName := "customAccess"
	customRefreshName := "customRefresh"
	customPKCEName := "customPKCE"
	customIDTokenName := "customID"

	testCases := []struct {
		Name              string
		ProxySettings     func(cfg *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestCustomStateCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.CookieOAuthStateName = customStateName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testsuite.FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customStateName: func(t *testing.T, c *config.Config, value string) bool {
							return assert.NotEqual(t, "", value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomAccessCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.CookieAccessName = customAccessName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testsuite.FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customAccessName: func(t *testing.T, c *config.Config, value string) bool {
							return assert.NotEqual(t, "", value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomRefreshCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.EnableRefreshTokens = true
				cfg.CookieRefreshName = customRefreshName
				cfg.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testsuite.FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customRefreshName: func(t *testing.T, c *config.Config, value string) bool {
							return assert.NotEqual(t, "", value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomRedirectUriCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.CookieOAuthStateName = customStateName
				cfg.CookieRequestURIName = customRedirectName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testsuite.FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customRedirectName: func(t *testing.T, c *config.Config, value string) bool {
							return assert.NotEqual(t, "", value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomPKCECookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.EnablePKCE = true
				cfg.CookieOAuthStateName = customStateName
				cfg.CookiePKCEName = customPKCEName
				cfg.CookieRequestURIName = customRedirectName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testsuite.FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customPKCEName: func(t *testing.T, c *config.Config, value string) bool {
							return assert.NotEqual(t, "", value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomIDTokenCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.CookieOAuthStateName = customStateName
				cfg.CookieRequestURIName = customRedirectName
				cfg.CookieIDTokenName = customIDTokenName
				cfg.CookieAccessName = customAccessName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testsuite.FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customIDTokenName: func(t *testing.T, c *config.Config, value string) bool {
							return assert.NotEqual(t, "", value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomIDTokenCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.CookieOAuthStateName = customStateName
				cfg.CookieRequestURIName = customRedirectName
				cfg.CookieIDTokenName = customIDTokenName
				cfg.CookieAccessName = customAccessName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testsuite.FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customIDTokenName: func(t *testing.T, c *config.Config, value string) bool {
							return assert.NotEqual(t, "", value)
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				cfg := newFakeKeycloakConfig()
				testCase.ProxySettings(cfg)
				fProxy := newFakeProxy(
					cfg,
					&fakeAuthConfig{
						EnablePKCE: cfg.EnablePKCE,
					},
				)
				fProxy.idp.setTokenExpiration(90 * time.Second)
				fProxy.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}
