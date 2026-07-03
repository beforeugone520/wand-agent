package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := flag.String("addr", "", "listen address host:port (overrides --host/--port)")
	host := flag.String("host", "127.0.0.1",
		"listen host; use the VM bridge IP (e.g. 172.16.100.2) to expose the agent to the host device")
	port := flag.Int("port", 8765, "listen port")
	token := flag.String("token", "", "auth token (auto-generated if empty)")
	maxSessions := flag.Int("max-sessions", 16, "maximum concurrent PTY sessions")
	allowQueryToken := flag.Bool("allow-query-token", true,
		"also accept ?token= query auth for legacy clients (Authorization: Bearer is always accepted)")
	allowOrigins := flag.String("allow-origins", "",
		"enable a strict comma-separated Origin allowlist (browser deployments); empty accepts any Origin since the bearer token is the auth gate")
	flag.Parse()

	authToken := *token
	if authToken == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			log.Fatalf("failed to generate auth token: %v", err)
		}
		authToken = hex.EncodeToString(buf)
		// Only print the token when we generated it ourselves; a token passed
		// on the command line stays out of the logs.
		log.Printf("auth token: %s", authToken)
	}

	listenAddr := *addr
	if listenAddr == "" {
		listenAddr = fmt.Sprintf("%s:%d", *host, *port)
	}

	auth := newAuthConfig(authToken, *allowQueryToken, *allowOrigins)
	sm := NewSessionManager(*maxSessions)

	log.Printf("login shell: %s", loginShell)
	if data, err := os.ReadFile("/etc/shells"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				log.Printf("available shell: %s", line)
			}
		}
	}

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !auth.authorize(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handleWS(sm, auth, w, r)
	})

	log.Printf("wand-agent listening on %s (max sessions: %d)", listenAddr, *maxSessions)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
