// Command omapasskeyd is the Omapasskey system service: a FIDO2 authenticator
// that browsers see as a USB security key, whose keys live in the TPM and
// whose every use takes the PIN and a key press on a physical keyboard.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Divanyx/omapasskey/internal/admin"
	"github.com/Divanyx/omapasskey/internal/ctap2"
	"github.com/Divanyx/omapasskey/internal/ctaphid"
	"github.com/Divanyx/omapasskey/internal/presence"
	"github.com/Divanyx/omapasskey/internal/status"
	"github.com/Divanyx/omapasskey/internal/tpm"
	"github.com/Divanyx/omapasskey/internal/uhid"
	"github.com/Divanyx/omapasskey/internal/vault"
)

// Set at build time.
var version = "dev"

// AAGUID 2bfb6aa2-0b2f-4a8c-9e2a-6f6d61706b79 identifies Omapasskey
// authenticators (the last bytes spell "mapky").
var aaguid = [16]byte{0x2b, 0xfb, 0x6a, 0xa2, 0x0b, 0x2f, 0x4a, 0x8c, 0x9e, 0x2a, 0x6f, 0x6d, 0x61, 0x70, 0x6b, 0x79}

const (
	hidName    = "Omapasskey TPM Passkeys"
	hidPhys    = "omapasskey"
	hidVendor  = 0x4F4D // "OM"
	hidProduct = 0x504B // "PK"
)

type config struct {
	users           map[uint32]bool
	minPINLength    int
	presenceTimeout time.Duration
}

func main() {
	var (
		configPath = flag.String("config", "/etc/omapasskey/omapasskey.conf", "configuration file")
		statePath  = flag.String("state", "/var/lib/omapasskey/state.json", "state file")
		tpmPath    = flag.String("tpm", "/dev/tpmrm0", "TPM resource manager device")
		uhidPath   = flag.String("uhid", "/dev/uhid", "uhid device, unless passed in by systemd")
		runDir     = flag.String("run", "/run/omapasskey", "runtime directory for the sockets")
		showVer    = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err := run(*configPath, *statePath, *tpmPath, *uhidPath, *runDir); err != nil {
		slog.Error("omapasskeyd stopped", "err", err)
		os.Exit(1)
	}
}

func run(configPath, statePath, tpmPath, uhidPath, runDir string) error {
	// Nobody may ptrace this process or read its memory through /proc, and
	// it never writes core dumps: it holds unlocked secrets for seconds.
	unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
	unix.Umask(0o077)

	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	t, err := tpm.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("opening the TPM: %w", err)
	}
	defer t.Close()

	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return err
	}
	v, err := vault.Open(statePath, t)
	if err != nil {
		return err
	}

	watcher := presence.New(cfg.presenceTimeout)
	var hub *status.Hub
	var device atomic.Value
	device.Store("")
	pres := newPresence(watcher, func(ev any) { hub.Publish(ev) })

	var auth *ctap2.Authenticator
	hub = status.NewHub(func(uid uint32) bool { return cfg.users[uid] }, func() status.Snapshot {
		s := auth.AdminStatus()
		return status.Snapshot{
			Version: version, PINSet: s.PINSet, PINRetries: s.PINRetries,
			Device: device.Load().(string), Keyboards: len(watcher.Keyboards()),
			Prompt: pres.Current(),
		}
	})
	events := &eventBridge{hub: hub, snapshot: func() any {
		s := auth.AdminStatus()
		return map[string]any{"pinSet": s.PINSet, "pinRetries": s.PINRetries}
	}}
	auth, err = ctap2.New(ctap2.Config{
		AAGUID: aaguid, MinPINLength: cfg.minPINLength, Firmware: firmware(),
	}, v, pres, events)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return err
	}
	statusL, err := hub.Listen(filepath.Join(runDir, "status.sock"))
	if err != nil {
		return err
	}
	defer statusL.Close()
	adminL, err := listenAdmin(filepath.Join(runDir, "admin.sock"), auth, t, watcher, &device)
	if err != nil {
		return err
	}
	defer adminL.Close()

	dev, err := openUHID(uhidPath)
	if err != nil {
		return fmt.Errorf("opening uhid: %w", err)
	}
	defer dev.Close()
	uniq := make([]byte, 8)
	rand.Read(uniq)
	if err := dev.Create(uhid.Config{
		Name: hidName, Phys: hidPhys, Uniq: fmt.Sprintf("%x", uniq),
		Bus: uhid.BusUSB, Vendor: hidVendor, Product: hidProduct, Version: 0x0100,
		Descriptor: uhid.FIDODescriptor,
	}); err != nil {
		return fmt.Errorf("creating the HID device: %w", err)
	}
	defer dev.Destroy()
	server := ctaphid.NewServer(dev, auth, ctaphid.Version{Major: 1, Minor: 0, Build: 0})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- pump(dev, server) }()
	go func() {
		// The hidraw node appears asynchronously; tell the desktop which.
		for i := 0; i < 50; i++ {
			if n := findHidraw(); n != "" {
				device.Store(n)
				events.StateChanged()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	sdNotify("READY=1\nSTATUS=Omapasskey ready")
	slog.Info("omapasskeyd ready", "version", version, "pinSet", v.PINSet(), "keyboards", len(watcher.Keyboards()))

	select {
	case <-ctx.Done():
		sdNotify("STOPPING=1")
		return nil
	case err := <-errc:
		return err
	}
}

func firmware() uint64 {
	// "1.2.3" -> 10203
	var out uint64
	for _, part := range strings.SplitN(strings.TrimPrefix(version, "v"), ".", 3) {
		n, _ := strconv.Atoi(strings.TrimFunc(part, func(r rune) bool { return r < '0' || r > '9' }))
		out = out*100 + uint64(n)
	}
	return out
}

// pump moves reports from the kernel to the CTAPHID server.
func pump(dev *uhid.Device, server *ctaphid.Server) error {
	for {
		ev, err := dev.ReadEvent()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}
		switch ev.Type {
		case uhid.EventOutput:
			server.HandleReport(ev.Data)
		case uhid.EventGetReport:
			dev.ReplyGetReport(ev.ID, unix.EIO)
		case uhid.EventSetReport:
			dev.ReplySetReport(ev.ID, unix.EIO)
		}
	}
}

// openUHID takes the descriptor systemd opened for us (OpenFile=/dev/uhid:uhid),
// or opens the device itself.
func openUHID(path string) (*uhid.Device, error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) {
		n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
		names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
		for i := 0; i < n; i++ {
			if i < len(names) && names[i] == "uhid" {
				return uhid.FromFD(3+i, "uhid")
			}
		}
	}
	return uhid.Open(path)
}

// findHidraw returns the hidraw node of our device, e.g. "hidraw7".
func findHidraw() string {
	entries, _ := os.ReadDir("/sys/class/hidraw")
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join("/sys/class/hidraw", e.Name(), "device", "uevent"))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "HID_PHYS="+hidPhys+"\n") {
			return e.Name()
		}
	}
	return ""
}

func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte(state))
}

func loadConfig(path string) (*config, error) {
	cfg := &config{users: map[uint32]bool{}, minPINLength: 6, presenceTimeout: 30 * time.Second}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, line)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "users":
			for _, u := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
				id, err := strconv.ParseUint(u, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("%s:%d: users takes numeric UIDs", path, line)
				}
				cfg.users[uint32(id)] = true
			}
		case "min_pin_length":
			n, err := strconv.Atoi(value)
			if err != nil || n < 4 || n > 63 {
				return nil, fmt.Errorf("%s:%d: min_pin_length must be 4..63", path, line)
			}
			cfg.minPINLength = n
		case "presence_timeout":
			n, err := strconv.Atoi(value)
			if err != nil || n < 5 || n > 120 {
				return nil, fmt.Errorf("%s:%d: presence_timeout must be 5..120 seconds", path, line)
			}
			cfg.presenceTimeout = time.Duration(n) * time.Second
		default:
			return nil, fmt.Errorf("%s:%d: unknown setting %q", path, line, key)
		}
	}
	return cfg, sc.Err()
}

// eventBridge turns authenticator events into status messages.
type eventBridge struct {
	hub      *status.Hub
	snapshot func() any
}

func (e *eventBridge) Done(op, rpID string, ok bool) {
	e.hub.Publish(map[string]any{"type": "done", "op": op, "rp": rpID, "ok": ok})
}

func (e *eventBridge) Wink() { e.hub.Publish(map[string]any{"type": "wink"}) }

func (e *eventBridge) StateChanged() {
	e.hub.Publish(map[string]any{"type": "state", "state": e.snapshot()})
}

// promptPresence is a ctap2.Presence that also reports the open prompt.
type promptPresence interface {
	ctap2.Presence
	Current() *status.Prompt
}

// presenceBridge shows prompts on the desktop and waits for the keyboard.
type presenceBridge struct {
	watcher *presence.Watcher
	publish func(any)
	next    atomic.Uint64
	mu      sync.Mutex
	current *status.Prompt
}

func (p *presenceBridge) Current() *status.Prompt {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current
}

func (p *presenceBridge) Confirm(ctx context.Context, pr ctap2.Prompt) error {
	var names []string
	for _, kb := range p.watcher.Keyboards() {
		names = append(names, kb.Name)
	}
	prompt := &status.Prompt{
		ID: p.next.Add(1), Op: pr.Op, RPID: pr.RPID,
		TimeoutMs: p.watcher.Timeout.Milliseconds(), Keyboards: names,
	}
	p.mu.Lock()
	p.current = prompt
	p.mu.Unlock()
	p.publish(map[string]any{"type": "prompt", "prompt": prompt})

	err := p.watcher.Wait(ctx)

	p.mu.Lock()
	p.current = nil
	p.mu.Unlock()
	result := "confirmed"
	switch {
	case err == nil:
	case ctx.Err() != nil:
		result = "cancelled"
	case errors.Is(err, presence.ErrTimeout):
		result = "timeout"
	case errors.Is(err, presence.ErrDenied):
		result = "denied"
	case errors.Is(err, presence.ErrNoKeyboard):
		result = "no-keyboard"
	default:
		result = "error"
		slog.Warn("presence check failed", "err", err)
	}
	p.publish(map[string]any{"type": "prompt-end", "id": prompt.ID, "result": result})
	slog.Info("confirmation", "op", pr.Op, "result", result)
	switch result {
	case "confirmed":
		return nil
	case "timeout":
		return ctap2.ErrPresenceTimeout
	}
	return ctap2.ErrPresenceDenied
}

// listenAdmin serves the root-only control socket.
func listenAdmin(path string, auth *ctap2.Authenticator, t *tpm.TPM, w *presence.Watcher, device *atomic.Value) (net.Listener, error) {
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveAdmin(conn, auth, t, w, device)
		}
	}()
	return l, nil
}

func serveAdmin(conn net.Conn, auth *ctap2.Authenticator, t *tpm.TPM, w *presence.Watcher, device *atomic.Value) {
	defer conn.Close()
	if uid, ok := status.PeerUID(conn); !ok || uid != 0 {
		return
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadBytes('\n')
	if err != nil {
		return
	}
	var req admin.Request
	reply := func(data any, err error) {
		resp := admin.Response{OK: err == nil}
		if err != nil {
			resp.Error = err.Error()
		} else if data != nil {
			resp.Data, _ = json.Marshal(data)
		}
		json.NewEncoder(conn).Encode(resp)
	}
	if err := json.Unmarshal(line, &req); err != nil {
		reply(nil, errors.New("bad request"))
		return
	}
	switch req.Cmd {
	case "status":
		info, terr := t.Info()
		out := map[string]any{
			"version": version, "authenticator": auth.AdminStatus(),
			"device": device.Load().(string), "keyboards": w.Keyboards(),
			"aaguid": fmt.Sprintf("%x-%x-%x-%x-%x", aaguid[0:4], aaguid[4:6], aaguid[6:8], aaguid[8:10], aaguid[10:16]),
		}
		if terr == nil {
			out["tpm"] = info
		}
		reply(out, nil)
	case "set-pin":
		reply(nil, auth.AdminSetPIN(req.PIN))
	case "change-pin":
		reply(nil, auth.AdminChangePIN(req.PIN, req.NewPIN))
	case "list":
		reply(auth.AdminList(req.PIN))
	case "delete":
		reply(nil, auth.AdminDelete(req.PIN, req.ID))
	case "reset":
		reply(nil, auth.AdminReset())
	default:
		reply(nil, errors.New("unknown command"))
	}
}
