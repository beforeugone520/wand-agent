package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

const (
	// writeWait bounds how long a single WebSocket write may block.
	writeWait = 10 * time.Second
	// pongWait is the read deadline; any inbound frame (data or pong) resets it.
	pongWait = 90 * time.Second
	// pingPeriod is how often protocol-level pings are sent (must be < pongWait).
	pingPeriod = 30 * time.Second
	// ptyChunkSize keeps single PTY writes below the kernel buffer size.
	ptyChunkSize = 16384
)

// wsWriter serializes all writes to one WebSocket connection. gorilla/websocket
// supports at most one concurrent writer; PTY output, cwd polling, control
// replies, and heartbeat pings all funnel through this mutex.
type wsWriter struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (w *wsWriter) write(messageType int, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return w.conn.WriteMessage(messageType, data)
}

func (w *wsWriter) writeBinary(data []byte) error {
	return w.write(websocket.BinaryMessage, data)
}

func (w *wsWriter) writeJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return w.write(websocket.TextMessage, data)
}

func (w *wsWriter) writePing() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait))
}

func handleWS(sm *SessionManager, auth *authConfig, w http.ResponseWriter, r *http.Request) {
	cols, rows := 80, 24
	cwd := ""
	if err := r.ParseForm(); err == nil {
		if c := r.Form.Get("cols"); c != "" {
			if v, ok := parseInt(c); ok {
				cols = v
			}
		}
		if rv := r.Form.Get("rows"); rv != "" {
			if v, ok := parseInt(rv); ok {
				rows = v
			}
		}
		cwd = r.Form.Get("cwd")
	}
	shell := r.Form.Get("shell")
	if shell == "" {
		shell = loginShell
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 65536,
		CheckOrigin:     auth.originAllowed,
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("upgrade: %v", err)
		return
	}
	defer conn.Close()

	writer := &wsWriter{conn: conn}

	session, err := sm.Create(cwd, cols, rows, shell)
	if err != nil {
		log.Printf("create session: %v", err)
		writer.writeJSON(map[string]string{"type": "error", "error": err.Error()})
		return
	}
	defer cleanupSession(sm, session)

	writer.writeJSON(map[string]string{"type": "cwd", "dir": session.currentCwd()})

	done := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(done) }) }
	defer closeDone()

	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	go heartbeat(writer, done, closeDone)
	go pollCwd(session, writer, done)
	go ptyToWS(session, writer, closeDone)

	wsToPTY(session, writer, conn)
}

// heartbeat emits protocol-level pings; a dead peer trips the read deadline.
func heartbeat(writer *wsWriter, done chan struct{}, closeDone func()) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		if err := writer.writePing(); err != nil {
			closeDone()
			return
		}
	}
}

func pollCwd(session *Session, writer *wsWriter, done chan struct{}) {
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
		if wd, err := os.Readlink(link); err == nil && wd != session.currentCwd() {
			session.setCwd(wd)
			writer.writeJSON(map[string]string{"type": "cwd", "dir": wd})
		}
	}
}

// ptyToWS streams shell output to the client and reports shell exit as an
// explicit control event instead of silently dropping the connection.
func ptyToWS(session *Session, writer *wsWriter, closeDone func()) {
	buf := make([]byte, 65536)
	for {
		n, err := session.PTY.Read(buf)
		if n > 0 {
			if werr := writer.writeBinary(buf[:n]); werr != nil {
				closeDone()
				return
			}
		}
		if err != nil {
			if !session.isClosed() {
				writer.writeJSON(map[string]string{"type": "exit", "message": "shell exited"})
			}
			closeDone()
			return
		}
	}
}

// wsToPTY routes frames by their WebSocket type: text frames are protocol
// control messages, binary frames are raw terminal input. Terminal input that
// happens to look like JSON (e.g. typing `{"type":"cwd"}`) is never
// misinterpreted, and the agent no longer injects bracketed-paste markers —
// paste encoding belongs to the client.
func wsToPTY(session *Session, writer *wsWriter, conn *websocket.Conn) {
	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(pongWait))
		if session.isClosed() {
			return
		}

		switch messageType {
		case websocket.TextMessage:
			handleCtrl(session, writer, msg)
		case websocket.BinaryMessage:
			writePTY(session, msg)
		default:
		}
	}
}

func writePTY(session *Session, msg []byte) {
	for off := 0; off < len(msg); off += ptyChunkSize {
		end := off + ptyChunkSize
		if end > len(msg) {
			end = len(msg)
		}
		chunk := msg[off:end]
		n, err := session.PTY.Write(chunk)
		if err != nil {
			log.Printf("pty write error at offset %d: %v", off, err)
			return
		}
		if n < len(chunk) {
			log.Printf("pty partial write: %d < %d at offset %d", n, len(chunk), off)
			time.Sleep(5 * time.Millisecond)
		}
	}
}

type ctrlMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
	CWD  string `json:"cwd,omitempty"`
	Ts   int64  `json:"ts,omitempty"`
}

func handleCtrl(session *Session, writer *wsWriter, msg []byte) {
	var ctrl ctrlMsg
	if err := json.Unmarshal(msg, &ctrl); err != nil || ctrl.Type == "" {
		writer.writeJSON(map[string]string{
			"type":  "error",
			"code":  "invalid-message",
			"error": "text frames must carry a JSON control message with a type",
		})
		return
	}

	switch ctrl.Type {
	case "resize":
		if ctrl.Cols > 0 && ctrl.Rows > 0 {
			pty.Setsize(session.PTY, &pty.Winsize{
				Rows: uint16(ctrl.Rows),
				Cols: uint16(ctrl.Cols),
			})
		}
	case "ping":
		writer.writeJSON(map[string]interface{}{"type": "pong", "ts": ctrl.Ts})
	case "pong":
		// no-op: reply to our JSON ping (legacy clients)
	case "shells":
		data, _ := os.ReadFile("/etc/shells")
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		var shells []string
		for _, line := range lines {
			if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				shells = append(shells, trimmed)
			}
		}
		writer.writeJSON(map[string]interface{}{"type": "shells", "list": shells})
	case "cwd":
		writer.writeJSON(map[string]string{"type": "cwd", "dir": session.currentCwd()})
	case "fork":
		// Upstream fork created an orphan session nothing could attach to.
		// One terminal = one WebSocket connection.
		writer.writeJSON(map[string]string{
			"type":  "error",
			"code":  "unsupported",
			"error": "fork is not supported; open a new websocket connection per terminal",
		})
	default:
		log.Printf("ignoring unknown control message type %q", ctrl.Type)
	}
}

func cleanupSession(sm *SessionManager, session *Session) {
	session.Terminate(3 * time.Second)
	sm.Remove(session.ID)
}

func parseInt(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
