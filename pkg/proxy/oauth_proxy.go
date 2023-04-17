package proxy

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v12"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/config"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/storage"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2/jwt"
)

type PAT struct {
	Token *gocloak.JWT
	m     sync.Mutex
}

// reverseProxy is a wrapper
type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}

type OauthProxy struct {
	Provider       *oidc3.Provider
	Config         *config.Config
	Endpoint       *url.URL
	IdpClient      *gocloak.GoCloak
	Listener       net.Listener
	Log            *zap.Logger
	metricsHandler http.Handler
	Router         http.Handler
	adminRouter    http.Handler
	Server         *http.Server
	Store          storage.Storage
	templates      *template.Template
	Upstream       reverseProxy
	pat            *PAT
}

// TokenResponse
type TokenResponse struct {
	TokenType    string  `json:"token_type"`
	AccessToken  string  `json:"access_token"`
	IDToken      string  `json:"id_token"`
	RefreshToken string  `json:"refresh_token,omitempty"`
	ExpiresIn    float64 `json:"expires_in"`
	Scope        string  `json:"scope,omitempty"`
}

// RequestScope is a request level context scope passed between middleware
type RequestScope struct {
	// AccessDenied indicates the request should not be proxied on
	AccessDenied bool
	// Identity is the user Identity of the request
	Identity *UserContext
	// The parsed (unescaped) value of the request path
	Path string
	// Preserve the original request path: KEYCLOAK-10864, KEYCLOAK-11276, KEYCLOAK-13315
	// The exact path received in the request, if different than Path
	RawPath string
	Logger  *zap.Logger
}

// ExtractIdentity parse the jwt token and extracts the various elements is order to construct
func ExtractIdentity(token *jwt.JSONWebToken) (*UserContext, error) {
	stdClaims := &jwt.Claims{}

	type RealmRoles struct {
		Roles []string `json:"roles"`
	}

	// Extract custom claims
	type custClaims struct {
		Email          string                    `json:"email"`
		PrefName       string                    `json:"preferred_username"`
		RealmAccess    RealmRoles                `json:"realm_access"`
		Groups         []string                  `json:"groups"`
		ResourceAccess map[string]interface{}    `json:"resource_access"`
		FamilyName     string                    `json:"family_name"`
		GivenName      string                    `json:"given_name"`
		Username       string                    `json:"username"`
		Authorization  authorization.Permissions `json:"authorization"`
	}

	customClaims := custClaims{}

	err := token.UnsafeClaimsWithoutVerification(stdClaims, &customClaims)

	if err != nil {
		return nil, err
	}

	jsonMap := make(map[string]interface{})
	err = token.UnsafeClaimsWithoutVerification(&jsonMap)

	if err != nil {
		return nil, err
	}

	// @step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	preferredName := customClaims.PrefName
	if preferredName == "" {
		preferredName = customClaims.Email
	}

	audiences := stdClaims.Audience

	// @step: extract the realm roles
	roleList := make([]string, 0)
	roleList = append(roleList, customClaims.RealmAccess.Roles...)

	// @step: extract the client roles from the access token
	for name, list := range customClaims.ResourceAccess {
		scopes, assertOk := list.(map[string]interface{})

		if !assertOk {
			return nil, fmt.Errorf("assertion failed")
		}

		if roles, found := scopes[constant.ClaimResourceRoles]; found {
			rolesVal, assertOk := roles.([]interface{})

			if !assertOk {
				return nil, fmt.Errorf("assertion failed")
			}

			for _, r := range rolesVal {
				roleList = append(roleList, fmt.Sprintf("%s:%s", name, r))
			}
		}
	}

	return &UserContext{
		Audiences:     audiences,
		Email:         customClaims.Email,
		ExpiresAt:     stdClaims.Expiry.Time(),
		Groups:        customClaims.Groups,
		ID:            stdClaims.Subject,
		Name:          preferredName,
		PreferredName: preferredName,
		Roles:         roleList,
		Claims:        jsonMap,
		Permissions:   customClaims.Authorization,
	}, nil
}

// isExpired checks if the token has expired
func (r *UserContext) IsExpired() bool {
	return r.ExpiresAt.Before(time.Now())
}

// String returns a string representation of the user context
func (r *UserContext) String() string {
	return fmt.Sprintf(
		"user: %s, expires: %s, roles: %s",
		r.PreferredName,
		r.ExpiresAt.String(),
		strings.Join(r.Roles, ","),
	)
}

// userContext holds the information extracted the token
type UserContext struct {
	// the id of the user
	ID string
	// the audience for the token
	Audiences []string
	// whether the context is from a session cookie or authorization header
	BearerToken bool
	// the email associated to the user
	Email string
	// the expiration of the access token
	ExpiresAt time.Time
	// groups is a collection of groups the user in in
	Groups []string
	// a name of the user
	Name string
	// preferredName is the name of the user
	PreferredName string
	// roles is a collection of roles the users holds
	Roles []string
	// rawToken
	RawToken string
	// claims
	Claims map[string]interface{}
	// permissions
	Permissions authorization.Permissions
}

var (
	release  = ""
	gitsha   = "no gitsha provided"
	compiled = "0"
	version  = ""
)

var (
	certificateRotationMetric = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "proxy_certificate_rotation_total",
			Help: "The total amount of times the certificate has been rotated",
		},
	)
	oauthTokensMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_oauth_tokens_total",
			Help: "A summary of the tokens issuesd, renewed or failed logins",
		},
		[]string{"action"},
	)
	oauthLatencyMetric = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "proxy_oauth_request_latency",
			Help: "A summary of the request latancy for requests against the openid provider, in seconds",
		},
		[]string{"action"},
	)
	latencyMetric = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "proxy_request_duration",
			Help: "A summary of the http request latency for proxy requests, in seconds",
		},
	)
	statusMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_request_status_total",
			Help: "The HTTP requests partitioned by status code",
		},
		[]string{"code", "method"},
	)
)

// GetVersion returns the proxy version
func GetVersion() string {
	if version == "" {
		tm, err := strconv.ParseInt(compiled, 10, 64)
		if err != nil {
			return "unable to parse compiled time"
		}
		version = fmt.Sprintf("%s (git+sha: %s, built: %s)", release, gitsha, time.Unix(tm, 0).Format("02-01-2006"))
	}

	return version
}
