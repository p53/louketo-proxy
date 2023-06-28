package constant

type contextKey int8

const (
	Prog        = "gatekeeper"
	Author      = "go-gatekeeper"
	Email       = ""
	Description = "is a proxy using the keycloak service for auth and authorization"

	AuthorizationHeader = "Authorization"
	AuthorizationType   = "Bearer"
	EnvPrefix           = "PROXY_"
	HeaderUpgrade       = "Upgrade"
	VersionHeader       = "X-Auth-Proxy-Version"

	AuthorizationURL = "/authorize"
	CallbackURL      = "/callback"
	ExpiredURL       = "/expired"
	HealthURL        = "/health"
	LoginURL         = "/login"
	LogoutURL        = "/logout"
	MetricsURL       = "/metrics"
	TokenURL         = "/token"
	DebugURL         = "/debug/pprof"
	DiscoveryURL     = "/discovery"

	ClaimResourceRoles = "roles"

	AccessCookie       = "kc-access"
	RefreshCookie      = "kc-state"
	RequestURICookie   = "request_uri"
	RequestStateCookie = "OAuth_Token_Request_State"
	PKCECookie         = "pkce"
	IDTokenCookie      = "id_token"
	UnsecureScheme     = "http"
	SecureScheme       = "https"
	AnyMethod          = "ANY"

	_ contextKey = iota
	ContextScopeName
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"

	DurationType = "time.Duration"

	// SameSite cookie config options
	SameSiteStrict = "Strict"
	SameSiteLax    = "Lax"
	SameSiteNone   = "None"

	AllPath = "/*"

	IdpWellKnownUri   = "/.well-known/openid-configuration"
	IdpCertsUri       = "/protocol/openid-connect/certs"
	IdpTokenUri       = "/protocol/openid-connect/token"
	IdpAuthUri        = "/protocol/openid-connect/auth"
	IdpUserUri        = "/protocol/openid-connect/userinfo"
	IdpLogoutUri      = "/protocol/openid-connect/logout"
	IdpRevokeUri      = "/protocol/openid-connect/revoke"
	IdpResourceSetUri = "/authz/protection/resource_set"
	IdpProtectPermUri = "/authz/protection/permission"
)
