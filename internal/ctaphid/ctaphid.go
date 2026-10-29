// Package ctaphid implements the FIDO CTAPHID transport: 64-byte HID reports,
// channel allocation, message fragmentation, keepalives and cancellation.
package ctaphid

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

// Commands (with the 0x80 initialization-packet bit set).
const (
	CmdPing      = 0x81
	CmdMsg       = 0x83
	CmdLock      = 0x84
	CmdInit      = 0x86
	CmdWink      = 0x88
	CmdCBOR      = 0x90
	CmdCancel    = 0x91
	CmdKeepalive = 0xBB
	CmdError     = 0xBF
)

// Error codes carried by CmdError.
const (
	ErrInvalidCmd     = 0x01
	ErrInvalidPar     = 0x02
	ErrInvalidLen     = 0x03
	ErrInvalidSeq     = 0x04
	ErrMsgTimeout     = 0x05
	ErrChannelBusy    = 0x06
	ErrInvalidChannel = 0x0B
	ErrOther          = 0x7F
)

// Keepalive status bytes.
const (
	StatusProcessing = 0x01
	StatusUPNeeded   = 0x02
)

const (
	ReportSize   = 64
	initPayload  = ReportSize - 7
	contPayload  = ReportSize - 5
	MaxMessage   = initPayload + 128*contPayload // 7609
	broadcastCID = 0xFFFFFFFF

	capWink = 0x01
	capCBOR = 0x04
	capNMsg = 0x08

	// How long the host may take between the packets of one message.
	assemblyTimeout = 500 * time.Millisecond
	// The spec asks for a keepalive at least every 100 ms while busy.
	keepaliveInterval = 80 * time.Millisecond
	// Channels allocated by INIT; the oldest are recycled beyond this.
	maxChannels = 32
)

// Handler executes CTAP2 requests.
type Handler interface {
	// CBOR runs one authenticator command (command byte followed by its CBOR
	// parameters) and returns the response (status byte plus CBOR). It must
	// return promptly once ctx is cancelled. status updates the keepalive
	// status the host sees while the command runs.
	CBOR(ctx context.Context, request []byte, status func(byte)) []byte
	// Wink asks the device to identify itself to the user.
	Wink()
}

// Sender delivers input reports to the host.
type Sender interface {
	Input(report []byte) error
}

// Version information reported in the INIT response.
type Version struct {
	Major, Minor, Build byte
}

// Server is the device side of CTAPHID.
type Server struct {
	out     Sender
	handler Handler
	version Version

	mu       sync.Mutex
	channels map[uint32]time.Time
	asm      *assembly
	busy     *transaction
}

type assembly struct {
	cid      uint32
	cmd      byte
	total    int
	data     []byte
	seq      byte
	deadline *time.Timer
}

type transaction struct {
	cid    uint32
	cancel context.CancelFunc
	done   chan struct{}
}

// NewServer returns a server that answers through out.
func NewServer(out Sender, h Handler, v Version) *Server {
	return &Server{out: out, handler: h, version: v, channels: map[uint32]time.Time{}}
}

// HandleReport processes one output report from the host. Reports with a
// leading zero report-ID byte (65 bytes) are accepted too.
func (s *Server) HandleReport(r []byte) {
	if len(r) == ReportSize+1 && r[0] == 0 {
		r = r[1:]
	}
	if len(r) < ReportSize {
		return
	}
	r = r[:ReportSize]
	cid := binary.BigEndian.Uint32(r[0:4])

	s.mu.Lock()
	defer s.mu.Unlock()

	if r[4]&0x80 == 0 {
		s.continuation(cid, r[4], r[5:])
		return
	}
	cmd := r[4]
	bcnt := int(binary.BigEndian.Uint16(r[5:7]))
	payload := r[7:]

	if cid == 0 {
		s.sendError(cid, ErrInvalidChannel)
		return
	}
	if cmd == CmdInit {
		s.init(cid, bcnt, payload)
		return
	}
	if cid == broadcastCID {
		s.sendError(cid, ErrInvalidChannel)
		return
	}
	if _, ok := s.channels[cid]; !ok {
		s.sendError(cid, ErrInvalidChannel)
		return
	}
	s.channels[cid] = time.Now()

	if s.busy != nil {
		if cmd == CmdCancel && s.busy.cid == cid {
			s.busy.cancel()
			return
		}
		if cmd == CmdCancel {
			return
		}
		s.sendError(cid, ErrChannelBusy)
		return
	}
	if cmd == CmdCancel {
		// Nothing to cancel; CANCEL never gets a response.
		return
	}
	if s.asm != nil {
		if s.asm.cid != cid {
			s.sendError(cid, ErrChannelBusy)
			return
		}
		// A new initialization packet on the same channel abandons the
		// half-received message.
		s.dropAssembly()
	}
	if bcnt > MaxMessage {
		s.sendError(cid, ErrInvalidLen)
		return
	}
	if bcnt <= initPayload {
		s.dispatch(cid, cmd, append([]byte(nil), payload[:bcnt]...))
		return
	}
	a := &assembly{cid: cid, cmd: cmd, total: bcnt, data: make([]byte, 0, bcnt)}
	a.data = append(a.data, payload...)
	a.deadline = time.AfterFunc(assemblyTimeout, func() { s.assemblyTimedOut(a) })
	s.asm = a
}

func (s *Server) continuation(cid uint32, seq byte, payload []byte) {
	a := s.asm
	if a == nil || a.cid != cid {
		// Spurious continuation packets are ignored.
		return
	}
	if seq != a.seq {
		s.dropAssembly()
		s.sendError(cid, ErrInvalidSeq)
		return
	}
	a.seq++
	need := a.total - len(a.data)
	if need > len(payload) {
		need = len(payload)
	}
	a.data = append(a.data, payload[:need]...)
	if len(a.data) < a.total {
		if a.seq > 127 {
			s.dropAssembly()
			s.sendError(cid, ErrInvalidSeq)
		}
		return
	}
	s.dropAssembly()
	s.dispatch(cid, a.cmd, a.data)
}

func (s *Server) assemblyTimedOut(a *assembly) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.asm != a {
		return
	}
	s.asm = nil
	s.sendError(a.cid, ErrMsgTimeout)
}

func (s *Server) dropAssembly() {
	if s.asm != nil {
		s.asm.deadline.Stop()
		s.asm = nil
	}
}

func (s *Server) init(cid uint32, bcnt int, payload []byte) {
	if bcnt != 8 {
		s.sendError(cid, ErrInvalidLen)
		return
	}
	newCID := cid
	if cid == broadcastCID {
		newCID = s.allocateChannel()
	} else {
		if _, ok := s.channels[cid]; !ok {
			s.sendError(cid, ErrInvalidChannel)
			return
		}
		// INIT on an existing channel resynchronises it: whatever it was
		// doing is abandoned.
		if s.asm != nil && s.asm.cid == cid {
			s.dropAssembly()
		}
		if s.busy != nil && s.busy.cid == cid {
			// The abandoned command still unwinds, but its answer is dropped.
			s.busy.cancel()
			s.busy = nil
		}
		s.channels[cid] = time.Now()
	}
	resp := make([]byte, 17)
	copy(resp[0:8], payload[:8])
	binary.BigEndian.PutUint32(resp[8:12], newCID)
	resp[12] = 2 // CTAPHID protocol version
	resp[13] = s.version.Major
	resp[14] = s.version.Minor
	resp[15] = s.version.Build
	resp[16] = capWink | capCBOR | capNMsg
	s.send(cid, CmdInit, resp)
}

func (s *Server) allocateChannel() uint32 {
	if len(s.channels) >= maxChannels {
		var oldest uint32
		var oldestAt time.Time
		for c, at := range s.channels {
			if s.busy != nil && s.busy.cid == c {
				continue
			}
			if oldest == 0 || at.Before(oldestAt) {
				oldest, oldestAt = c, at
			}
		}
		delete(s.channels, oldest)
	}
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		c := binary.BigEndian.Uint32(b[:])
		if c == 0 || c == broadcastCID {
			continue
		}
		if _, used := s.channels[c]; used {
			continue
		}
		s.channels[c] = time.Now()
		return c
	}
}

func (s *Server) dispatch(cid uint32, cmd byte, data []byte) {
	switch cmd {
	case CmdPing:
		s.send(cid, CmdPing, data)
	case CmdWink:
		if len(data) != 0 {
			s.sendError(cid, ErrInvalidLen)
			return
		}
		s.send(cid, CmdWink, nil)
		go s.handler.Wink()
	case CmdCBOR:
		if len(data) == 0 {
			s.sendError(cid, ErrInvalidLen)
			return
		}
		s.startTransaction(cid, data)
	default:
		// CTAP1/U2F (MSG) and LOCK are not offered; NMSG says so in INIT.
		s.sendError(cid, ErrInvalidCmd)
	}
}

func (s *Server) startTransaction(cid uint32, request []byte) {
	ctx, cancel := context.WithCancel(context.Background())
	t := &transaction{cid: cid, cancel: cancel, done: make(chan struct{})}
	s.busy = t

	var statusMu sync.Mutex
	status := byte(StatusProcessing)
	setStatus := func(b byte) {
		statusMu.Lock()
		status = b
		statusMu.Unlock()
	}

	go func() {
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-t.done:
				return
			case <-ticker.C:
				statusMu.Lock()
				b := status
				statusMu.Unlock()
				s.mu.Lock()
				if s.busy == t {
					s.send(cid, CmdKeepalive, []byte{b})
				}
				s.mu.Unlock()
			}
		}
	}()

	go func() {
		resp := s.handler.CBOR(ctx, request, setStatus)
		cancel()
		s.mu.Lock()
		close(t.done)
		if s.busy == t {
			s.busy = nil
			s.send(cid, CmdCBOR, resp)
		}
		s.mu.Unlock()
	}()
}

// Busy reports whether a command is running.
func (s *Server) Busy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.busy != nil
}

// Reset abandons every channel and the running command, as a power cycle would.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropAssembly()
	if s.busy != nil {
		s.busy.cancel()
		s.busy = nil
	}
	clear(s.channels)
}

func (s *Server) sendError(cid uint32, code byte) {
	s.send(cid, CmdError, []byte{code})
}

// send fragments one message into reports. Callers hold s.mu.
func (s *Server) send(cid uint32, cmd byte, data []byte) {
	report := make([]byte, ReportSize)
	binary.BigEndian.PutUint32(report[0:4], cid)
	report[4] = cmd
	binary.BigEndian.PutUint16(report[5:7], uint16(len(data)))
	n := copy(report[7:], data)
	if s.out.Input(report) != nil {
		return
	}
	data = data[n:]
	for seq := byte(0); len(data) > 0; seq++ {
		report = make([]byte, ReportSize)
		binary.BigEndian.PutUint32(report[0:4], cid)
		report[4] = seq
		n = copy(report[5:], data)
		data = data[n:]
		if s.out.Input(report) != nil {
			return
		}
	}
}
