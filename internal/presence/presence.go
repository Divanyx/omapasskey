// Package presence collects the FIDO "test of user presence" from a physical
// keyboard: the user holds Left Shift and Right Shift together.
//
// Only devices attached to real hardware count. Everything software can
// create — uinput devices (ydotool, xdotool's uinput backend, remote-desktop
// injectors), Wayland virtual keyboards (wtype, compositor IPC), uhid devices
// — lives under /sys/devices/virtual or never reaches evdev at all, so no
// program, however privileged it is inside the user's session, can produce
// this gesture. Bluetooth LE keyboards are also uhid devices and are not
// accepted; a wired, built-in or classic-Bluetooth keyboard is.
package presence

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux input constants.
const (
	evSyn         = 0x00
	evKey         = 0x01
	synDropped    = 3
	keyEsc        = 1
	keyLeftShift  = 42
	keyRightShift = 54
	keyMax        = 0x2ff
	eventSize     = 24 // struct input_event on 64-bit
)

var (
	// ErrTimeout means nobody confirmed in time.
	ErrTimeout = errors.New("presence: timed out")
	// ErrDenied means the user pressed Escape.
	ErrDenied = errors.New("presence: denied")
	// ErrNoKeyboard means there is no physical keyboard to confirm with.
	ErrNoKeyboard = errors.New("presence: no physical keyboard")
)

// Keyboard is one physical keyboard that can confirm.
type Keyboard struct {
	Node string `json:"node"`
	Name string `json:"name"`
}

// Watcher waits for the gesture.
type Watcher struct {
	SysDir  string // /sys/class/input
	DevDir  string // /dev/input
	Timeout time.Duration
	// Combo is the key combination that confirms; DefaultCombo if unset.
	Combo *Combo
	// allowVirtual accepts software keyboards too. Only test builds set it,
	// to exercise the event handling with a uinput device.
	allowVirtual bool
}

// New returns a watcher for the live system.
func New(timeout time.Duration) *Watcher {
	return &Watcher{SysDir: "/sys/class/input", DevDir: "/dev/input", Timeout: timeout}
}

func (w *Watcher) combo() *Combo {
	if w.Combo != nil {
		return w.Combo
	}
	return DefaultCombo()
}

// Keyboards lists the physical keyboards that have every key of the combo.
func (w *Watcher) Keyboards() []Keyboard {
	entries, err := os.ReadDir(w.SysDir)
	if err != nil {
		return nil
	}
	var out []Keyboard
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "event") {
			continue
		}
		if kb, ok := w.inspect(name); ok {
			out = append(out, kb)
		}
	}
	return out
}

func (w *Watcher) inspect(event string) (Keyboard, bool) {
	base := filepath.Join(w.SysDir, event)
	real, err := filepath.EvalSymlinks(filepath.Join(base, "device"))
	if err != nil || (IsVirtual(real) && !w.allowVirtual) {
		return Keyboard{}, false
	}
	caps, err := os.ReadFile(filepath.Join(base, "device", "capabilities", "key"))
	if err != nil || !hasKeys(string(caps), w.combo().Codes...) {
		return Keyboard{}, false
	}
	name, _ := os.ReadFile(filepath.Join(base, "device", "name"))
	return Keyboard{Node: event, Name: strings.TrimSpace(string(name))}, true
}

// IsVirtual reports whether a resolved sysfs device path belongs to a device
// that software created rather than hardware.
func IsVirtual(sysPath string) bool {
	return strings.Contains(sysPath, "/devices/virtual/") || !strings.HasPrefix(sysPath, "/sys/devices/")
}

// hasKeys parses a sysfs key bitmap: hex words, most significant first.
func hasKeys(bitmap string, codes ...int) bool {
	words := strings.Fields(bitmap)
	for _, code := range codes {
		idx := len(words) - 1 - code/64
		if idx < 0 {
			return false
		}
		v, err := strconv.ParseUint(words[idx], 16, 64)
		if err != nil || v&(1<<(code%64)) == 0 {
			return false
		}
	}
	return true
}

type device struct {
	fd       int
	keys     []int
	down     map[int]bool
	armed    bool // every combo key was up at some point since the prompt began
	keyboard Keyboard
}

func (d *device) allDown() bool {
	for _, k := range d.keys {
		if !d.down[k] {
			return false
		}
	}
	return true
}

func (d *device) noneDown() bool {
	for _, k := range d.keys {
		if d.down[k] {
			return false
		}
	}
	return true
}

// Wait blocks until every key of the combination is held on one physical
// keyboard, Escape is pressed, ctx ends, or the timeout passes. Presses that
// began before the call do not count: the keys must be released and pressed
// again.
func (w *Watcher) Wait(ctx context.Context) error {
	devs, err := w.open()
	if err != nil {
		return err
	}
	defer func() {
		for _, d := range devs {
			unix.Close(d.fd)
		}
	}()

	deadline := time.Now().Add(w.Timeout)
	fds := make([]unix.PollFd, len(devs))
	for i, d := range devs {
		fds[i] = unix.PollFd{Fd: int32(d.fd), Events: unix.POLLIN}
	}
	buf := make([]byte, eventSize*64)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return ErrTimeout
		}
		wait := 100 * time.Millisecond
		if left < wait {
			wait = left
		}
		for i := range fds {
			fds[i].Revents = 0
		}
		if _, err := unix.Poll(fds, int(wait/time.Millisecond)+1); err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		for i, d := range devs {
			if fds[i].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				// Unplugged; the others keep working.
				fds[i].Fd = -1
				continue
			}
			if fds[i].Revents&unix.POLLIN == 0 {
				continue
			}
			result, err := d.drain(buf)
			if err != nil {
				fds[i].Fd = -1
				continue
			}
			if result != nil {
				return result
			}
			if d.armed && d.allDown() {
				return nil
			}
		}
	}
}

func (w *Watcher) open() ([]*device, error) {
	kbs := w.Keyboards()
	var devs []*device
	for _, kb := range kbs {
		fd, err := unix.Open(filepath.Join(w.DevDir, kb.Node), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		if !w.sameDevice(fd, kb.Node) {
			unix.Close(fd)
			continue
		}
		d := &device{fd: fd, keyboard: kb, keys: w.combo().Codes, down: map[int]bool{}}
		if err := d.sync(); err != nil {
			unix.Close(fd)
			continue
		}
		// Throw away whatever was queued before the prompt.
		var buf [eventSize * 64]byte
		for {
			n, err := unix.Read(fd, buf[:])
			if n <= 0 || err != nil {
				break
			}
		}
		devs = append(devs, d)
	}
	if len(devs) == 0 {
		return nil, ErrNoKeyboard
	}
	return devs, nil
}

// sameDevice checks that the node we opened is the device sysfs vetted.
func (w *Watcher) sameDevice(fd int, event string) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return false
	}
	want, err := os.ReadFile(filepath.Join(w.SysDir, event, "dev"))
	if err != nil {
		return false
	}
	got := fmt.Sprintf("%d:%d", unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)))
	return strings.TrimSpace(string(want)) == got
}

// sync reads the current key state, after a start or a dropped buffer.
func (d *device) sync() error {
	var keys [(keyMax + 7) / 8]byte
	req := uint(2)<<30 | uint(len(keys))<<16 | uint('E')<<8 | 0x18 // EVIOCGKEY(len)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(d.fd), uintptr(req), uintptr(unsafe.Pointer(&keys[0]))); errno != 0 {
		return errno
	}
	for _, k := range d.keys {
		d.down[k] = keys[k/8]&(1<<(k%8)) != 0
	}
	if d.noneDown() {
		d.armed = true
	}
	return nil
}

// drain consumes queued events. It returns ErrDenied on Escape.
func (d *device) drain(buf []byte) (error, error) {
	for {
		n, err := unix.Read(d.fd, buf)
		if errors.Is(err, unix.EAGAIN) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return nil, nil
		}
		for off := 0; off+eventSize <= n; off += eventSize {
			ev := buf[off : off+eventSize]
			typ := binary.NativeEndian.Uint16(ev[16:])
			code := int(binary.NativeEndian.Uint16(ev[18:]))
			value := int32(binary.NativeEndian.Uint32(ev[20:]))
			switch {
			case typ == evSyn && code == synDropped:
				if err := d.sync(); err != nil {
					return nil, err
				}
			case typ == evKey && code == keyEsc && value == 1:
				return ErrDenied, nil
			case typ == evKey:
				if _, ours := d.down[code]; !ours {
					continue
				}
				d.down[code] = value != 0 // 1 press, 2 autorepeat
				if d.noneDown() {
					d.armed = true
				}
				if d.armed && d.allDown() {
					return nil, nil
				}
			}
		}
	}
}
