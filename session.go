package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

type Session struct {
	ID    string
	PTY   *os.File
	Cmd   *exec.Cmd
	Shell string

	mu     sync.Mutex
	cwd    string
	closed bool
}

type SessionManager struct {
	mu          sync.Mutex
	sessions    map[string]*Session
	maxSessions int
}

func NewSessionManager(maxSessions int) *SessionManager {
	if maxSessions <= 0 {
		maxSessions = 16
	}
	return &SessionManager{
		sessions:    make(map[string]*Session),
		maxSessions: maxSessions,
	}
}

var loginShell string

func init() {
	loginShell = os.Getenv("SHELL")
	if loginShell == "" {
		loginShell = "/bin/bash"
	}
}

func (sm *SessionManager) Create(cwd string, cols, rows int, shell ...string) (*Session, error) {
	sm.mu.Lock()
	if len(sm.sessions) >= sm.maxSessions {
		count := len(sm.sessions)
		sm.mu.Unlock()
		return nil, fmt.Errorf("session limit reached (%d/%d)", count, sm.maxSessions)
	}
	sm.mu.Unlock()

	shellPath := loginShell
	if len(shell) > 0 && shell[0] != "" {
		shellPath = shell[0]
	}
	cmd := exec.Command(shellPath, "-l")
	if cwd != "" {
		cmd.Dir = cwd
	} else if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	env := os.Environ()
	if os.Getenv("LANG") == "" {
		env = append(env, "LANG=C.UTF-8")
	}
	cmd.Env = append(env,
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"TERM_PROGRAM=wand",
		"TERM_PROGRAM_VERSION=0.1.0",
	)

	// pty.StartWithSize sets Setsid+Setctty, so the shell leads its own
	// session/process group and Terminate can signal the whole group.
	fd, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	if err != nil {
		return nil, fmt.Errorf("pty start: %w", err)
	}

	session := &Session{ID: newID(), PTY: fd, Cmd: cmd, cwd: cwd, Shell: shellPath}

	if cwd == "" {
		link := fmt.Sprintf("/proc/%d/cwd", cmd.Process.Pid)
		if wd, err := os.Readlink(link); err == nil {
			session.setCwd(wd)
		}
	}

	sm.mu.Lock()
	if len(sm.sessions) >= sm.maxSessions {
		count := len(sm.sessions)
		sm.mu.Unlock()
		session.Terminate(time.Second)
		return nil, fmt.Errorf("session limit reached (%d/%d)", count, sm.maxSessions)
	}
	sm.sessions[session.ID] = session
	sm.mu.Unlock()

	return session, nil
}

func (sm *SessionManager) Get(id string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.sessions[id]
}

func (sm *SessionManager) Remove(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, id)
}

func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.PTY.Close()
}

func (s *Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) currentCwd() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cwd
}

func (s *Session) setCwd(cwd string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cwd = cwd
}

// Terminate closes the PTY, asks the whole process group to hang up, and
// escalates to SIGKILL after the timeout so background children of the shell
// cannot linger after the client disconnects.
func (s *Session) Terminate(timeout time.Duration) {
	s.Close()

	if s.Cmd == nil || s.Cmd.Process == nil {
		return
	}
	pid := s.Cmd.Process.Pid

	// Negative pid signals the process group led by the shell.
	syscall.Kill(-pid, syscall.SIGHUP)

	waited := make(chan struct{})
	go func() {
		s.Cmd.Wait()
		close(waited)
	}()

	select {
	case <-waited:
	case <-time.After(timeout):
		syscall.Kill(-pid, syscall.SIGKILL)
		<-waited
	}
}

func newID() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}
