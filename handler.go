package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handleWS(sm *SessionManager, w http.ResponseWriter, r *http.Request) {
	cols, rows := 80, 24
	cwd := ""
	if err := r.ParseForm(); err == nil {
		if c := r.Form.Get("cols"); c != "" {
			if v, ok := parseInt(c); ok {
				cols = v
			}
		}
		if r := r.Form.Get("rows"); r != "" {
			if v, ok := parseInt(r); ok {
				rows = v
			}
		}
		cwd = r.Form.Get("cwd")
	}
	shell := r.Form.Get("shell")
	if shell == "" {
		shell = loginShell
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("upgrade: %v", err)
		return
	}
	defer conn.Close()

	session, err := sm.Create(cwd, cols, rows, shell)
	if err != nil {
		log.Printf("create session: %v", err)
		return
	}
	defer cleanupSession(sm, session)

	// Push initial CWD to frontend
	if initCwd, _ := json.Marshal(map[string]string{"type": "cwd", "dir": session.CWD}); initCwd != nil {
		conn.WriteMessage(websocket.TextMessage, initCwd)
	}

	done := make(chan struct{})

	// Start CWD polling goroutine
	go pollCwd(session, conn, done)

	go ptyToWS(session, conn, done)

	wsToPTY(sm, session, conn, done)
}

func pollCwd(session *Session, conn *websocket.Conn, done chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		if session.isClosed() {
			return
		}
		link := fmt.Sprintf("/proc/%d/cwd", session.Cmd.Process.Pid)
		if wd, err := os.Readlink(link); err == nil && wd != session.CWD {
			session.mu.Lock()
			session.CWD = wd
			session.mu.Unlock()
			if msg, err := json.Marshal(map[string]string{"type": "cwd", "dir": wd}); err == nil {
				conn.WriteMessage(websocket.TextMessage, msg)
			}
		}
	}
}

func ptyToWS(session *Session, conn *websocket.Conn, done chan struct{}) {
	buf := make([]byte, 4096)
	for {
		n, err := session.PTY.Read(buf)
		if err != nil {
			close(done)
			return
		}
		if session.isClosed() {
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
			close(done)
			return
		}
	}
}

func wsToPTY(sm *SessionManager, session *Session, conn *websocket.Conn, done chan struct{}) {
	cols, rows := 80, 24

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if session.isClosed() {
			return
		}

		if isJSONCtrl(msg) {
			if handled := handleCtrl(sm, session, conn, msg, &cols, &rows); handled {
				continue
			}
		}
		session.PTY.Write(msg)
	}
}

func isJSONCtrl(msg []byte) bool {
	return len(msg) > 0 && msg[0] == '{'
}

type ctrlMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
	CWD  string `json:"cwd,omitempty"`
}

func handleCtrl(sm *SessionManager, session *Session, conn *websocket.Conn, msg []byte, cols, rows *int) bool {
	var ctrl ctrlMsg
	if err := json.Unmarshal(msg, &ctrl); err != nil || ctrl.Type == "" {
		return false
	}

	switch ctrl.Type {
	case "resize":
		if ctrl.Cols > 0 && ctrl.Rows > 0 {
			*cols = ctrl.Cols
			*rows = ctrl.Rows
			pty.Setsize(session.PTY, &pty.Winsize{
				Rows: uint16(ctrl.Rows),
				Cols: uint16(ctrl.Cols),
			})
		}
		return true
	case "ping":
		return true
	case "shells":
		data, _ := os.ReadFile("/etc/shells")
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		var shells []string
		for _, line := range lines {
			if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				shells = append(shells, trimmed)
			}
		}
		resp, _ := json.Marshal(map[string]interface{}{"type": "shells", "list": shells})
		conn.WriteMessage(websocket.TextMessage, resp)
		return true
	case "cwd":
		resp, _ := json.Marshal(map[string]string{"type": "cwd", "dir": session.CWD})
		conn.WriteMessage(websocket.TextMessage, resp)
		return true
	case "fork":
		cwd := session.CWD
		if ctrl.CWD != "" {
			cwd = ctrl.CWD
		}
		forked, err := sm.Create(cwd, *cols, *rows, session.Shell)
		if err != nil {
			resp, _ := json.Marshal(map[string]string{"type": "error", "error": err.Error()})
			conn.WriteMessage(websocket.TextMessage, resp)
			return true
		}
		resp, _ := json.Marshal(map[string]string{"type": "forked", "id": forked.ID})
		conn.WriteMessage(websocket.TextMessage, resp)
		return true
	}
	return false
}

func cleanupSession(sm *SessionManager, session *Session) {
	session.Close()
	session.Cmd.Process.Kill()
	session.Cmd.Wait()
	sm.Remove(session.ID)
}

func parseInt(s string) (int, bool) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
