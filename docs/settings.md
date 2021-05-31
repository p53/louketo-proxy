
| CONFIG                                     | DESCRIPTION | DEFAULT | ENV |
--- | --- | --- | ---
|    --config value                          | path the a configuration file | | PROXY_CONFIG_FILE
|    --listen value                          | Defines the binding interface for main listener, e.g. {address}:{port}. This is required and there is no default value | | PROXY_LISTEN
|    --listen-http value                     | interface we should be listening to for HTTP traffic | | PROXY_LISTEN_HTTP
|    --listen-admin value                    | defines the interface to bind admin-only endpoint (live-status, debug, prometheus...). If not defined, this defaults to the main listener defined by Listen | | PROXY_LISTEN_ADMIN
|    --listen-admin-scheme value             | scheme to serve admin-only endpoint (http or https). | | PROXY_LISTEN_ADMIN_SCHEME
|    --discovery-url value                   | discovery url to retrieve the openid configuration | | PROXY_DISCOVERY_URL
|    --client-id value                       | client id used to authenticate to the oauth service | | PROXY_CLIENT_ID
|    --client-secret value                   | client secret used to authenticate to the oauth service | | PROXY_CLIENT_SECRET
|    --redirection-url value                 | redirection url for the oauth callback url, defaults to host header if absent | | PROXY_REDIRECTION_URL
|    --revocation-url value                  | url for the revocation endpoint to revoke refresh token | | PROXY_REVOCATION_URL
|    --skip-openid-provider-tls-verify       | skip the verification of any TLS communication with the openid provider | false |
|    --openid-provider-proxy value           | proxy for communication with the openid provider
|    --openid-provider-timeout value         | timeout for openid configuration on .well-known/openid-configuration | 30s |
|    --base-uri value                        | common prefix for all URIs | | PROXY_BASE_URI
|    --oauth-uri value                       | the uri for proxy oauth endpoints | /oauth | PROXY_OAUTH_URI
|    --scopes value                          | list of scopes requested when authenticating the user | |
|    --upstream-url value                    | url for the upstream endpoint you wish to proxy | | PROXY_UPSTREAM_URL
|    --upstream-ca value                     | the path to a file container a CA certificate to validate the upstream tls endpoint
|    --resources value                       | list of resources 'uri=/admin*\|methods=GET,PUT\|roles=role1,role2'
|    --headers value                         | custom headers to the upstream request, key=value
|    --preserve-host                         | preserve the host header of the proxied request in the upstream request | false |
|    --request-id-header value               | the http header name for request id | X-Request-ID | PROXY_REQUEST_ID_HEADER
|    --response-headers value                | custom headers to added to the http response key=value
|    --enable-self-signed-tls                | create self signed certificates for the proxy | false | PROXY_ENABLE_SELF_SIGNED_TLS
|    --self-signed-tls-hostnames value       | a list of hostnames to place on the self-signed certificate
|    --self-signed-tls-expiration value      | the expiration of the certificate before rotation | 3h0m0s |
|    --enable-request-id                     | indicates we should add a request id if none found | false | PROXY_ENABLE_REQUEST_ID |
|    --enable-logout-redirect                | indicates we should redirect to the identity provider for logging out | false |
|    --enable-default-deny                   | enables a default denial on all requests, you have to explicitly say what is permitted (recommended) | true |
|    --enable-encrypted-token                | enable encryption for the access tokens | false | |
|    --force-encrypted-cookie                | force encryption for the access tokens in cookies | false | |
|    --enable-logging                        | enable http logging of the requests | false | |
|    --enable-json-logging                   | switch on json logging rather than text | false | |
|    --enable-forwarding                     | enables the forwarding proxy mode, signing outbound request | false | |
|    --enable-security-filter                | enables the security filter handler | false | | PROXY_ENABLE_SECURITY_FILTER
|    --enable-refresh-tokens                 | enables the handling of the refresh tokens | false | | PROXY_ENABLE_REFRESH_TOKEN
|    --enable-session-cookies                | access and refresh tokens are session only i.e. removed browser close | true | |
|    --enable-login-handler                  | enables the handling of the refresh tokens | false | | PROXY_ENABLE_LOGIN_HANDLER
|    --enable-token-header                   | enables the token authentication header X-Auth-Token to upstream | true | |
|    --enable-authorization-header           | adds the authorization header to the proxy request | true | | | PROXY_ENABLE_AUTHORIZATION_HEADER
|    --enable-authorization-cookies          | adds the authorization cookies to the uptream proxy request | true | | | PROXY_ENABLE_AUTHORIZATION_COOKIES
|    --enable-https-redirection              | enable the http to https redirection on the http service | false | |
|    --enable-profiling                      | switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc | false | |
|    --enable-metrics                        | enable the prometheus metrics collector on /oauth/metrics | false | |
|    --filter-browser-xss                    | enable the adds the X-XSS-Protection header with mode=block | false | |
|    --filter-content-nosniff                | adds the X-Content-Type-Options header with the value nosniff | false | |
|    --filter-frame-deny                     | enable to the frame deny header | false | |
|    --content-security-policy value         | specify the content security policy
|    --localhost-metrics                     | enforces the metrics page can only been requested from 127.0.0.1 | false | |
|    --enable-compression                    | enable gzip compression for response | false | |
|    --access-token-duration value           | fallback cookie duration for the access token when using refresh tokens | 720h0m0s | |
|    --cookie-domain value                   | domain the access cookie is available to, defaults host header
|    --cookie-access-name value              | name of the cookie use to hold the access token | kc-access | |
|    --cookie-refresh-name value             | name of the cookie used to hold the encrypted refresh token | kc-state | |
|    --secure-cookie                         | enforces the cookie to be secure | true | |
|    --http-only-cookie                      | enforces the cookie is in http only mode | true | |
|    --same-site-cookie value                | enforces cookies to be send only to same site requests according to the policy (can be \| Strict\|Lax\|None) | Lax | |
|    --match-claims value                    | keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*
|    --add-claims value                      | extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name
|    --tls-cert value                        | path to ths TLS certificate
|    --tls-private-key value                 | path to the private key for TLS
|    --tls-ca-certificate value              | path to the ca certificate used for signing requests
|    --tls-ca-key value                      | path the ca private key, used by the forward signing proxy
|    --tls-client-certificate value          | path to the client certificate for outbound connections in reverse and forwarding proxy modes
|    --skip-upstream-tls-verify              | skip the verification of any upstream TLS | true | |
|    --tls-admin-cert value                  | path to ths TLS certificate | | PROXY_TLS_ADMIN_CERTIFICATE |
|    --tls-admin-private-key value           | path to the private key for TLS | | PROXY_TLS_ADMIN_PRIVATE_KEY |
|    --tls-admin-ca-certificate value        | path to the ca certificate used for signing requests | | PROXY_TLS_ADMIN_CA_CERTIFICATE |
|    --tls-admin-client-certificate value    | path to the client certificate for outbound connections in reverse and forwarding proxy modes | | PROXY_TLS_ADMIN_CLIENT_CERTIFICATE |
|    --cors-origins value                    | origins to add to the CORE origins control (Access-Control-Allow-Origin)
|    --cors-methods value                    | methods permitted in the access control (Access-Control-Allow-Methods)
|    --cors-headers value                    | set of headers to add to the CORS access control (Access-Control-Allow-Headers)
|    --cors-exposed-headers value            | expose cors headers access control (Access-Control-Expose-Headers)
|    --cors-credentials                      | credentials access control header (Access-Control-Allow-Credentials) | false | |
|    --cors-max-age value                    | max age applied to cors headers (Access-Control-Max-Age) | 0s | |
|    --hostnames value                       | list of hostnames the service will respond to
|    --store-url value                       | url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file
|    --encryption-key value                  | encryption key used to encryption the session state | | PROXY_ENCRYPTION_KEY
|    --no-redirects                          | do not have back redirects when no authentication is present, 401 them | false | |
|    --skip-token-verification               | TESTING ONLY; bypass token verification, only expiration and roles enforced | false | |
|    --skip-access-token-issuer-check        | according RFC issuer should not be checked on access token, this will be default true in future | | false | |
|    --skip-access-token-clientid-check      | according RFC client id should not be checked on access token, this will be default true in future | false | |
| --skip-authorization-header-identity | skip authorization header identity, means that we won't be extracting token from authorization header, only from cookie or fail if even no cookie present (e.g. if authorization header is used only by application behind gatekeeper)"` | false | |
|    --upstream-keepalives                    | enables or disables the keepalive connections for upstream endpoint | true | |
|    --upstream-timeout value                 | maximum amount of time a dial will wait for a connect to complete | 10s | |
|    --upstream-keepalive-timeout value       | specifies the keep-alive period for an active network connection | 10s | |
|    --upstream-tls-handshake-timeout value   | the timeout placed on the tls handshake for upstream | 10s | |
|    --upstream-response-header-timeout value | the timeout placed on the response header for upstream | 10s | |
|    --upstream-expect-continue-timeout value | the timeout placed on the expect continue for upstream | 10s | |
|    --verbose                                | switch on debug / verbose logging | false | |
|    --enabled-proxy-protocol                 | enable proxy protocol | false | |
|    --max-idle-connections value             | max idle upstream / keycloak connections to keep alive, ready for reuse | 0 |
|    --max-idle-connections-per-host value    | limits the number of idle connections maintained per host | 0 | |
|    --server-read-timeout value              | the server read timeout on the http server | 10s | |
|    --server-write-timeout value             | the server write timeout on the http server | 10s | |
|    --server-idle-timeout value              | the server idle timeout on the http server | 2m0s | |
|    --use-letsencrypt                        | use letsencrypt for certificates | false | |
|    --letsencrypt-cache-dir value            | path where cached letsencrypt certificates are stored | ./cache/
|    --sign-in-page value                     | path to custom template displayed for signin
|    --forbidden-page value                   | path to custom template used for access forbidden
|    --error-page value                       | path to custom template displayed for http.StatusBadRequest
|    --tags value                             | keypairs passed to the templates at render,e.g title=Page
|    --forwarding-grant-type value            | grant-type to use when logging into the openid provider, can be one of password, client_credentials | password | |
|    --forwarding-username value              | username to use when logging into the openid provider
|    --forwarding-password value              | password to use when logging into the openid provider
|    --forwarding-domains value               | list of domains which should be signed; everything else is relayed unsigned
|    --disable-all-logging                    | disables all logging to stdout and stderr | false | |
|    --help, -h                               | show help
|    --version, -v                            | print the version
|
