// Package ipc implements the typed agent IPC: newline-delimited JSON
// requests over a Unix socket with strict peer-credential checks
// (docs/SECURITY.md). There is no shell, no exec and no arbitrary path
// operations — only the method table below.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Request is one IPC call. Params shape is method-specific.
type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is one IPC reply. Exactly one of Result/Error is set.
type Response struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *IpcError       `json:"error,omitempty"`
}

// IpcError mirrors schema.Error over the wire.
type IpcError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Params    map[string]any `json:"params,omitempty"`
}

// Handler serves one method. Implementations must be safe for concurrent
// use; the server serializes nothing.
type Handler func(ctx context.Context, params json.RawMessage) (any, *IpcError)

// Server is the agent's Unix-socket RPC endpoint.
type Server struct {
	sockPath string
	methods  map[string]Handler
	ln       net.Listener
	mu       sync.Mutex
	closed   bool
}

// NewServer binds a private Unix socket. The socket directory must already
// exist with 0700 permissions; the socket itself gets 0600 so only the
// owning user can connect, and on Linux the peer UID/GID are additionally
// verified with SO_PEERCRED (peercred_linux.go).
func NewServer(sockPath string, methods map[string]Handler) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(sockPath) // stale socket from a crashed agent
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return &Server{sockPath: sockPath, methods: methods, ln: ln}, nil
}

// Serve accepts connections until Close. Each connection is one or more
// sequential requests (one JSON object per line).
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		if err := s.checkPeer(conn); err != nil {
			// peer credential mismatch: drop before any parsing
			conn.Close()
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.ln.Close()
	os.Remove(s.sockPath)
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	for {
		line, err := rw.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			return
		}
		var req Request
		if jerr := json.Unmarshal(trimLine(line), &req); jerr != nil || req.Method == "" {
			writeResp(rw, Response{ID: req.ID, Error: &IpcError{Code: "VALIDATION_FAILED", Message: "malformed request"}})
			return
		}
		h, ok := s.methods[req.Method]
		if !ok {
			writeResp(rw, Response{ID: req.ID, Error: &IpcError{Code: "UNSUPPORTED_CAPABILITY", Message: "unknown method " + req.Method}})
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		res, ierr := h(ctx, req.Params)
		cancel()
		if ierr != nil {
			writeResp(rw, Response{ID: req.ID, Error: ierr})
			continue
		}
		b, merr := json.Marshal(res)
		if merr != nil {
			writeResp(rw, Response{ID: req.ID, Error: &IpcError{Code: "INTERNAL", Message: merr.Error()}})
			continue
		}
		writeResp(rw, Response{ID: req.ID, Result: b})
	}
}

func writeResp(rw *bufio.ReadWriter, resp Response) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	rw.Write(append(b, '\n'))
	rw.Flush()
}

func trimLine(line []byte) []byte {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}

// Client is the CLI-side connector.
type Client struct {
	conn net.Conn
	rw   *bufio.ReadWriter
}

// Dial connects to the agent socket. Unix sockets of mode 0600 enforce the
// same-user check at the filesystem level; the server additionally verifies
// peer credentials on Linux.
func Dial(sockPath string) (*Client, error) {
	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, rw: bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))}, nil
}

// Call performs one request/response exchange.
func (c *Client) Call(method string, params any) (json.RawMessage, *IpcError, error) {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, nil, err
		}
		raw = b
	}
	req := Request{ID: fmt.Sprintf("%d", time.Now().UnixNano()), Method: method, Params: raw}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.rw.Write(append(b, '\n')); err != nil {
		return nil, nil, err
	}
	if err := c.rw.Flush(); err != nil {
		return nil, nil, err
	}
	line, err := c.rw.ReadBytes('\n')
	if err != nil {
		return nil, nil, err
	}
	var resp Response
	if err := json.Unmarshal(trimLine(line), &resp); err != nil {
		return nil, nil, err
	}
	return resp.Result, resp.Error, nil
}

func (c *Client) Close() error { return c.conn.Close() }
