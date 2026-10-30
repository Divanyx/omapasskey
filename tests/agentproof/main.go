// Command agentproof plays the attacker: it creates a virtual keyboard the way
// ydotool and remote-desktop tools do (/dev/uinput, which the logged-in user
// may open on most desktops) and holds the confirm keys (Left Ctrl + Right
// Ctrl by default, -shift for both Shift keys). Omapasskey must not accept
// that as a confirmation.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	evSyn = 0x00
	evKey = 0x01
	// ioctls from <linux/uinput.h>
	uiDevCreate  = 0x5501
	uiDevDestroy = 0x5502
	uiSetEvBit   = 0x40045564
	uiSetKeyBit  = 0x40045565
	uiDevSetup   = 0x405c5503
	keyLeftShift = 42
	keyRightShft = 54
	keyLeftCtrl  = 29
	keyRightCtrl = 97
	keyEsc       = 1
)

type uinputSetup struct {
	ID struct {
		Bustype, Vendor, Product, Version uint16
	}
	Name         [80]byte
	FFEffectsMax uint32
}

func ioctl(fd int, req, arg uintptr) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, arg); e != 0 {
		return e
	}
	return nil
}

func emit(fd int, typ, code uint16, value int32) {
	ev := make([]byte, 24)
	binary.NativeEndian.PutUint16(ev[16:], typ)
	binary.NativeEndian.PutUint16(ev[18:], code)
	binary.NativeEndian.PutUint32(ev[20:], uint32(value))
	unix.Write(fd, ev)
}

func main() {
	delay := flag.Duration("delay", 2*time.Second, "wait before pressing")
	hold := flag.Duration("hold", 3*time.Second, "how long to hold the keys")
	shift := flag.Bool("shift", false, "press both Shift keys instead of both Ctrl keys")
	flag.Parse()
	fd, err := unix.Open("/dev/uinput", unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open /dev/uinput:", err)
		os.Exit(1)
	}
	defer unix.Close(fd)
	must := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	must(ioctl(fd, uiSetEvBit, evKey))
	for _, k := range []uintptr{keyLeftShift, keyRightShft, keyLeftCtrl, keyRightCtrl, keyEsc} {
		must(ioctl(fd, uiSetKeyBit, k))
	}
	var setup uinputSetup
	// Pretend to be a real USB keyboard as far as the fields go.
	setup.ID.Bustype, setup.ID.Vendor, setup.ID.Product = 0x03, 0x046d, 0xc31c
	copy(setup.Name[:], "Logitech USB Keyboard")
	must(ioctl(fd, uiDevSetup, uintptr(unsafe.Pointer(&setup))))
	must(ioctl(fd, uiDevCreate, 0))
	defer ioctl(fd, uiDevDestroy, 0)
	left, right, name := uint16(keyLeftCtrl), uint16(keyRightCtrl), "Ctrl"
	if *shift {
		left, right, name = keyLeftShift, keyRightShft, "Shift"
	}
	fmt.Println("virtual keyboard created; pressing both", name, "keys in", *delay)
	time.Sleep(*delay)
	emit(fd, evKey, left, 1)
	emit(fd, evKey, right, 1)
	emit(fd, evSyn, 0, 0)
	time.Sleep(*hold)
	emit(fd, evKey, left, 0)
	emit(fd, evKey, right, 0)
	emit(fd, evSyn, 0, 0)
	fmt.Println("released")
}
