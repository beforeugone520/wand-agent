package main

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

type authConfig struct {
	token           string
	allowQueryToken bool
	allowedOrigins  []string
}

func newAuthConfig(token string, allowQueryToken bool, allowOrigins string) *authConfig {
	var origins []string
	for _, origin := range strings.Split(allowOrigins, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			origins = append(origins, origin)
		}
	}
	return &authConfig{
		token:           token,
		allowQueryToken: allowQueryToken,
		allowedOrigins:  origins,
	}
}

// authorize accepts `Authorization: Bearer <token>` first and, when enabled,
// falls back to the legacy `?token=` query parameter. Comparison is constant
// time so the token cannot be probed byte by byte.
func (a *authConfig) authorize(r *http.Request) bool {
	presented := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		presented = strings.TrimPrefix(h, "Bearer ")
	}
	if presented == "" && a.allowQueryToken {
		presented = r.URL.Query().Get("token")
	}
	if presented == "" || a.token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(a.token)) == 1
}

// originAllowed: the bearer token is the primary gate — a cross-site page
// cannot know it, so any Origin is accepted by default (native WebSocket
// stacks such as HarmonyOS do send an Origin header). Configuring
// --allow-origins switches to a strict allowlist for browser deployments;
// requests without an Origin header are always accepted.
func (a *authConfig) originAllowed(r *http.Request) bool {
	if len(a.allowedOrigins) == 0 {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, allowed := range a.allowedOrigins {
		if strings.EqualFold(origin, allowed) {
			return true
		}
	}
	return false
}
