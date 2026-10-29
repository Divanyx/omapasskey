package ctaphid

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu      sync.Mutex
	reports [][]byte
	notify  chan struct{}
}

func newRecorder() *recorder { return &recorder{notify: make(chan struct{}, 1024)} }

func (r *recorder) Input(report []byte) error {
	r.mu.Lock()
	r.reports = append(r.reports, append([]byte(nil), report...))
	r.mu.Unlock()
	r.notify <- struct{}{}
	return nil
}

// message reassembles the next non-keepalive message for cid.
func (r *recorder) message(t *testing.T, cid uint32) (byte, []byte) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		r.mu.Lock()
		for i, rep := range r.reports {
			if binary.BigEndian.Uint32(rep) != cid || rep[4]&0x80 == 0 || rep[4] == CmdKeepalive {
				continue
			}
			cmd := rep[4]
			n := int(binary.BigEndian.Uint16(rep[5:7]))
			data := append([]byte(nil), rep[7:]...)
			used := []int{i}
			for j := i + 1; len(data) < n && j < len(r.reports); j++ {
				if binary.BigEndian.Uint32(r.reports[j]) == cid && r.reports[j][4]&0x80 == 0 {
					data = append(data, r.reports[j][5:]...)
					used = append(used, j)
				}
			}
			if len(data) >= n {
				for k := len(used) - 1; k >= 0; k-- {
					r.reports = append(r.reports[:used[k]], r.reports[used[k]+1:]...)
				}
				r.mu.Unlock()
				return cmd, data[:n]
			}
		}
		r.mu.Unlock()
		select {
		case <-r.notify:
		case <-deadline:
			t.Fatal("no message")
		}
	}
}

type echoHandler struct {
	block chan struct{}
}

func (h *echoHandler) CBOR(ctx context.Context, req []byte, status func(byte)) []byte {
	if h.block != nil {
		status(StatusUPNeeded)
		select {
		case <-ctx.Done():
			return []byte{0x2D}
		case <-h.block:
		}
	}
	return append([]byte{0}, req...)
}

func (h *echoHandler) Wink() {}

func packet(cid uint32, cmd byte, data []byte) [][]byte {
	var out [][]byte
	p := make([]byte, ReportSize)
	binary.BigEndian.PutUint32(p, cid)
	p[4] = cmd
	binary.BigEndian.PutUint16(p[5:], uint16(len(data)))
	n := copy(p[7:], data)
	out = append(out, p)
	data = data[n:]
	for seq := byte(0); len(data) > 0; seq++ {
		p = make([]byte, ReportSize)
		binary.BigEndian.PutUint32(p, cid)
		p[4] = seq
		n = copy(p[5:], data)
		data = data[n:]
		out = append(out, p)
	}
	return out
}

func send(s *Server, cid uint32, cmd byte, data []byte) {
	for _, p := range packet(cid, cmd, data) {
		s.HandleReport(append([]byte{0}, p...)) // with the report-ID byte
	}
}

func initChannel(t *testing.T, s *Server, r *recorder) uint32 {
	t.Helper()
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	send(s, broadcastCID, CmdInit, nonce)
	cmd, data := r.message(t, broadcastCID)
	if cmd != CmdInit || len(data) != 17 || !bytes.Equal(data[:8], nonce) {
		t.Fatalf("INIT response %x %x", cmd, data)
	}
	if data[16] != capWink|capCBOR|capNMsg {
		t.Fatalf("capabilities %x", data[16])
	}
	return binary.BigEndian.Uint32(data[8:12])
}

func TestLargeMessageRoundTrip(t *testing.T) {
	r := newRecorder()
	s := NewServer(r, &echoHandler{}, Version{1, 0, 0})
	cid := initChannel(t, s, r)
	big := bytes.Repeat([]byte("passkey!"), 900) // 7200 bytes, 122 continuation packets
	send(s, cid, CmdCBOR, big)
	cmd, data := r.message(t, cid)
	if cmd != CmdCBOR || data[0] != 0 || !bytes.Equal(data[1:], big) {
		t.Fatalf("echo mismatch: cmd %x len %d", cmd, len(data))
	}
	send(s, cid, CmdPing, []byte("ping"))
	if cmd, data := r.message(t, cid); cmd != CmdPing || string(data) != "ping" {
		t.Fatal("ping")
	}
}

func TestErrors(t *testing.T) {
	r := newRecorder()
	s := NewServer(r, &echoHandler{}, Version{1, 0, 0})
	cid := initChannel(t, s, r)
	send(s, cid, CmdMsg, []byte{0})
	if cmd, data := r.message(t, cid); cmd != CmdError || data[0] != ErrInvalidCmd {
		t.Fatal("CTAP1 MSG must be refused (NMSG)")
	}
	send(s, 0x12345678, CmdCBOR, []byte{4})
	if cmd, data := r.message(t, 0x12345678); cmd != CmdError || data[0] != ErrInvalidChannel {
		t.Fatal("unknown channel")
	}
	// A message whose continuation never comes times out.
	p := packet(cid, CmdCBOR, bytes.Repeat([]byte{1}, 100))
	s.HandleReport(p[0])
	if cmd, data := r.message(t, cid); cmd != CmdError || data[0] != ErrMsgTimeout {
		t.Fatal("assembly timeout")
	}
	// Out-of-sequence continuation.
	p = packet(cid, CmdCBOR, bytes.Repeat([]byte{1}, 200))
	s.HandleReport(p[0])
	s.HandleReport(p[2])
	if cmd, data := r.message(t, cid); cmd != CmdError || data[0] != ErrInvalidSeq {
		t.Fatal("bad sequence")
	}
}

func TestBusyKeepaliveAndCancel(t *testing.T) {
	r := newRecorder()
	h := &echoHandler{block: make(chan struct{})}
	s := NewServer(r, h, Version{1, 0, 0})
	a := initChannel(t, s, r)
	b := initChannel(t, s, r)
	send(s, a, CmdCBOR, []byte{2})
	time.Sleep(250 * time.Millisecond)
	// Keepalives with "user presence needed" were sent meanwhile.
	r.mu.Lock()
	keepalives := 0
	for _, rep := range r.reports {
		if binary.BigEndian.Uint32(rep) == a && rep[4] == CmdKeepalive && rep[7] == StatusUPNeeded {
			keepalives++
		}
	}
	r.mu.Unlock()
	if keepalives < 2 {
		t.Fatalf("only %d keepalives", keepalives)
	}
	// Another channel is told the device is busy.
	send(s, b, CmdCBOR, []byte{4})
	if cmd, data := r.message(t, b); cmd != CmdError || data[0] != ErrChannelBusy {
		t.Fatal("busy")
	}
	// CANCEL ends the command with KEEPALIVE_CANCEL.
	send(s, a, CmdCancel, nil)
	if cmd, data := r.message(t, a); cmd != CmdCBOR || data[0] != 0x2D {
		t.Fatalf("cancel: %x %x", cmd, data)
	}
	if s.Busy() {
		t.Fatal("still busy after cancel")
	}
}
