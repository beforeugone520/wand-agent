package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newTestServer(t *testing.T, maxSessions int) (*httptest.Server, string) {
	t.Helper()
	auth := newAuthConfig("secret", true, "")
	sm := NewSessionManager(maxSessions)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.authorize(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handleWS(sm, auth, w, r)
	}))
	t.Cleanup(server.Close)
	return server, "ws" + strings.TrimPrefix(server.URL, "http") + "?cols=80&rows=24"
}

func readUntil(t *testing.T, conn *websocket.Conn, want func(messageType int, msg []byte) bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if want(messageType, msg) {
			return
		}
	}
	t.Fatal("expected frame not observed before deadline")
}

func TestUnauthorizedRejected(t *testing.T) {
	_, wsURL := newTestServer(t, 4)
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("dial without token should fail")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %+v", resp)
	}
}

func TestBearerAuthShellRoundTrip(t *testing.T) {
	_, wsURL := newTestServer(t, 4)
	header := http.Header{"Authorization": []string{"Bearer secret"}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial with bearer: %v", err)
	}
	defer conn.Close()

	// First frame is the initial cwd control message.
	readUntil(t, conn, func(messageType int, msg []byte) bool {
		return messageType == websocket.TextMessage && strings.Contains(string(msg), `"cwd"`)
	})

	// Binary frames reach the shell.
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("echo wand-smoke-$((21+21))\n")); err != nil {
		t.Fatalf("write input: %v", err)
	}
	readUntil(t, conn, func(messageType int, msg []byte) bool {
		return messageType == websocket.BinaryMessage && strings.Contains(string(msg), "wand-smoke-42")
	})

	// JSON typed into the terminal as a binary frame must NOT be treated as
	// a control message: the shell echoes it back / reports command-not-found
	// instead of the agent answering with a shells list.
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("{\"type\":\"shells\"}\n")); err != nil {
		t.Fatalf("write json-looking input: %v", err)
	}
	readUntil(t, conn, func(messageType int, msg []byte) bool {
		if messageType == websocket.TextMessage && strings.Contains(string(msg), `"list"`) {
			t.Fatal("binary JSON input was treated as a control message")
		}
		return messageType == websocket.BinaryMessage && strings.Contains(string(msg), `{"type":"shells"}`)
	})

	// Text-frame JSON ping is answered with pong.
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"ping","ts":123}`)); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	readUntil(t, conn, func(messageType int, msg []byte) bool {
		if messageType != websocket.TextMessage {
			return false
		}
		var ctrl map[string]interface{}
		if json.Unmarshal(msg, &ctrl) != nil {
			return false
		}
		return ctrl["type"] == "pong"
	})

	// Shell exit produces an explicit exit event.
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("exit\n")); err != nil {
		t.Fatalf("write exit: %v", err)
	}
	readUntil(t, conn, func(messageType int, msg []byte) bool {
		return messageType == websocket.TextMessage && strings.Contains(string(msg), `"exit"`)
	})
}

func TestSessionLimit(t *testing.T) {
	_, wsURL := newTestServer(t, 1)
	header := http.Header{"Authorization": []string{"Bearer secret"}}

	first, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	defer first.Close()
	readUntil(t, first, func(messageType int, msg []byte) bool {
		return messageType == websocket.TextMessage && strings.Contains(string(msg), `"cwd"`)
	})

	second, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer second.Close()
	readUntil(t, second, func(messageType int, msg []byte) bool {
		return messageType == websocket.TextMessage && strings.Contains(string(msg), "session limit reached")
	})
}

func TestOriginAcceptedByDefault(t *testing.T) {
	_, wsURL := newTestServer(t, 4)
	header := http.Header{
		"Authorization": []string{"Bearer secret"},
		"Origin":        []string{"http://some-native-stack.local"},
	}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial with origin should succeed when no allowlist is set: %v", err)
	}
	conn.Close()
}

func TestOriginStrictAllowlist(t *testing.T) {
	auth := newAuthConfig("secret", true, "https://allowed.example")
	sm := NewSessionManager(4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.authorize(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handleWS(sm, auth, w, r)
	}))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?cols=80&rows=24"

	badHeader := http.Header{
		"Authorization": []string{"Bearer secret"},
		"Origin":        []string{"https://evil.example"},
	}
	if conn, _, err := websocket.DefaultDialer.Dial(wsURL, badHeader); err == nil {
		conn.Close()
		t.Fatal("disallowed origin must be rejected in strict mode")
	}

	goodHeader := http.Header{
		"Authorization": []string{"Bearer secret"},
		"Origin":        []string{"https://allowed.example"},
	}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, goodHeader)
	if err != nil {
		t.Fatalf("allowlisted origin should connect: %v", err)
	}
	conn.Close()
}

func TestForkUnsupported(t *testing.T) {
	_, wsURL := newTestServer(t, 4)
	header := http.Header{"Authorization": []string{"Bearer secret"}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"fork"}`)); err != nil {
		t.Fatalf("write fork: %v", err)
	}
	readUntil(t, conn, func(messageType int, msg []byte) bool {
		return messageType == websocket.TextMessage && strings.Contains(string(msg), "unsupported")
	})
}
