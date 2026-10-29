// Package status tells the desktop what the authenticator is doing: a
// read-only stream of JSON lines on a Unix socket. Nothing a client sends is
// ever read, so a client — or anything impersonating one — can show prompts
// but never answer them.
package status

import (
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Prompt is a confirmation the user is being asked for.
type Prompt struct {
	ID        uint64   `json:"id"`
	Op        string   `json:"op"`
	RPID      string   `json:"rp,omitempty"`
	TimeoutMs int64    `json:"timeoutMs"`
	Keyboards []string `json:"keyboards"`
}

// Snapshot is the state a new client starts from.
type Snapshot struct {
	Version    string  `json:"version"`
	PINSet     bool    `json:"pinSet"`
	PINRetries int     `json:"pinRetries"`
	Device     string  `json:"device,omitempty"`
	Keyboards  int     `json:"keyboards"`
	Prompt     *Prompt `json:"prompt,omitempty"`
}

// Hub fans events out to connected clients.
type Hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}
	// Allowed decides which peer UIDs may listen.
	Allowed  func(uid uint32) bool
	snapshot func() Snapshot
}

type client struct {
	conn net.Conn
	out  chan []byte
}

// NewHub returns a hub; snapshot builds the hello message.
func NewHub(allowed func(uint32) bool, snapshot func() Snapshot) *Hub {
	return &Hub{clients: map[*client]struct{}{}, Allowed: allowed, snapshot: snapshot}
}

// Listen creates the socket at path, world-connectable; access is decided
// per connection from the peer's credentials.
func (h *Hub) Listen(path string) (net.Listener, error) {
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	go h.serve(l)
	return l, nil
}

func (h *Hub) serve(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		uid, ok := PeerUID(conn)
		if !ok || (uid != 0 && (h.Allowed == nil || !h.Allowed(uid))) {
			conn.Close()
			continue
		}
		c := &client{conn: conn, out: make(chan []byte, 32)}
		h.mu.Lock()
		h.clients[c] = struct{}{}
		h.mu.Unlock()
		go h.write(c)
		go h.discard(c)
		h.sendTo(c, map[string]any{"type": "hello", "state": h.snapshot()})
	}
}

// PeerUID returns the UID of the process on the other end of a Unix socket.
func PeerUID(conn net.Conn) (uint32, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *unix.Ucred
	var cerr error
	raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cerr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

func (h *Hub) write(c *client) {
	for line := range c.out {
		c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.conn.Write(line); err != nil {
			h.drop(c)
			return
		}
	}
}

// discard reads and throws away whatever the client sends, and notices when
// it goes away.
func (h *Hub) discard(c *client) {
	buf := make([]byte, 512)
	for {
		if _, err := c.conn.Read(buf); err != nil {
			h.drop(c)
			return
		}
	}
}

func (h *Hub) drop(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; !ok {
		return
	}
	delete(h.clients, c)
	close(c.out)
	c.conn.Close()
}

func (h *Hub) sendTo(c *client, v any) {
	line, err := json.Marshal(v)
	if err != nil {
		return
	}
	line = append(line, '\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; !ok {
		return
	}
	select {
	case c.out <- line:
	default:
		// A client that does not keep up is dropped rather than waited for.
		delete(h.clients, c)
		close(c.out)
		c.conn.Close()
	}
}

// Publish sends an event to every client.
func (h *Hub) Publish(v any) {
	h.mu.Lock()
	clients := make([]*client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	for _, c := range clients {
		h.sendTo(c, v)
	}
}
