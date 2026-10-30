// Package admin is the root-only control socket of omapasskeyd: one JSON
// request and one JSON response per connection.
package admin

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"time"
)

// SocketPath is where the daemon listens.
const SocketPath = "/run/omapasskey/admin.sock"

// StatusSocketPath is the read-only event stream for the desktop.
const StatusSocketPath = "/run/omapasskey/status.sock"

// Request is one command.
type Request struct {
	Cmd    string `json:"cmd"`
	PIN    string `json:"pin,omitempty"`
	NewPIN string `json:"newPin,omitempty"`
	ID     []byte `json:"id,omitempty"`
	Code   string `json:"code,omitempty"`
}

// Response is the answer.
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Call sends one request to the daemon.
func Call(path string, req Request, timeout time.Duration) (*Response, error) {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return &resp, errors.New(resp.Error)
	}
	return &resp, nil
}
