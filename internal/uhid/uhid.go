// Package uhid creates a virtual HID device through the kernel's /dev/uhid
// interface, so that browsers find the authenticator exactly like a USB key.
package uhid

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
)

// Event types from <linux/uhid.h>.
const (
	EventDestroy        = 1
	EventStart          = 2
	EventStop           = 3
	EventOpen           = 4
	EventClose          = 5
	EventOutput         = 6
	EventGetReport      = 9
	EventGetReportReply = 10
	EventCreate2        = 11
	EventInput2         = 12
	EventSetReport      = 13
	EventSetReportReply = 14
)

const (
	dataMax = 4096
	// sizeof(struct uhid_event): the type word plus the largest union member,
	// struct uhid_create2_req.
	eventSize = 4 + 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4 + 4 + dataMax

	// BusUSB is BUS_USB from <linux/input.h>.
	BusUSB = 0x03
)

// Config describes the device the kernel announces.
type Config struct {
	Name       string
	Phys       string
	Uniq       string
	Bus        uint16
	Vendor     uint32
	Product    uint32
	Version    uint32
	Descriptor []byte
}

// ErrBadEvent is a malformed event; the device keeps working.
var ErrBadEvent = errors.New("uhid: malformed event")

// Event is one message from the kernel.
type Event struct {
	Type uint32
	// Data holds the report of an EventOutput.
	Data []byte
	// ID identifies a GET_REPORT or SET_REPORT request that needs a reply.
	ID uint32
}

// Device is an open /dev/uhid handle.
type Device struct {
	f       *os.File
	writeMu sync.Mutex
	readBuf []byte
}

// Open opens /dev/uhid.
func Open(path string) (*Device, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &Device{f: f, readBuf: make([]byte, eventSize)}, nil
}

// FromFD adopts a descriptor that was opened elsewhere, typically one passed
// in by systemd's OpenFile=.
func FromFD(fd int, name string) (*Device, error) {
	// A non-blocking descriptor lets the Go poller wake a blocked Read on Close.
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, errors.New("uhid: invalid descriptor")
	}
	return &Device{f: f, readBuf: make([]byte, eventSize)}, nil
}

// Create announces the device to the kernel.
func (d *Device) Create(c Config) error {
	if len(c.Descriptor) == 0 || len(c.Descriptor) > dataMax {
		return errors.New("uhid: bad report descriptor size")
	}
	ev := make([]byte, eventSize)
	binary.NativeEndian.PutUint32(ev[0:], EventCreate2)
	p := ev[4:]
	copy(p[0:127], c.Name)
	copy(p[128:128+63], c.Phys)
	copy(p[192:192+63], c.Uniq)
	binary.NativeEndian.PutUint16(p[256:], uint16(len(c.Descriptor)))
	binary.NativeEndian.PutUint16(p[258:], c.Bus)
	binary.NativeEndian.PutUint32(p[260:], c.Vendor)
	binary.NativeEndian.PutUint32(p[264:], c.Product)
	binary.NativeEndian.PutUint32(p[268:], c.Version)
	binary.NativeEndian.PutUint32(p[272:], 0) // country
	copy(p[276:], c.Descriptor)
	return d.write(ev)
}

// Destroy removes the device. The handle stays usable for another Create.
func (d *Device) Destroy() error {
	ev := make([]byte, 4)
	binary.NativeEndian.PutUint32(ev, EventDestroy)
	return d.write(ev)
}

// Input delivers one input report from the device to the host.
func (d *Device) Input(report []byte) error {
	if len(report) > dataMax {
		return errors.New("uhid: report too large")
	}
	ev := make([]byte, 4+2+len(report))
	binary.NativeEndian.PutUint32(ev[0:], EventInput2)
	binary.NativeEndian.PutUint16(ev[4:], uint16(len(report)))
	copy(ev[6:], report)
	return d.write(ev)
}

// ReplyGetReport refuses a GET_REPORT request; FIDO devices have no feature
// reports, and an unanswered request stalls the kernel for seconds.
func (d *Device) ReplyGetReport(id uint32, errno syscall.Errno) error {
	ev := make([]byte, 4+4+2+2)
	binary.NativeEndian.PutUint32(ev[0:], EventGetReportReply)
	binary.NativeEndian.PutUint32(ev[4:], id)
	binary.NativeEndian.PutUint16(ev[8:], uint16(errno))
	return d.write(ev)
}

// ReplySetReport refuses a SET_REPORT request.
func (d *Device) ReplySetReport(id uint32, errno syscall.Errno) error {
	ev := make([]byte, 4+4+2)
	binary.NativeEndian.PutUint32(ev[0:], EventSetReportReply)
	binary.NativeEndian.PutUint32(ev[4:], id)
	binary.NativeEndian.PutUint16(ev[8:], uint16(errno))
	return d.write(ev)
}

// ReadEvent blocks until the kernel sends the next event. It must only be
// called from one goroutine.
func (d *Device) ReadEvent() (Event, error) {
	clear(d.readBuf)
	n, err := d.f.Read(d.readBuf)
	if err != nil {
		return Event{}, err
	}
	if n < 4 {
		return Event{}, fmt.Errorf("%w: short event (%d bytes)", ErrBadEvent, n)
	}
	b := d.readBuf
	ev := Event{Type: binary.NativeEndian.Uint32(b[0:])}
	switch ev.Type {
	case EventOutput:
		// struct uhid_output_req { data[4096]; u16 size; u8 rtype; }
		size := int(binary.NativeEndian.Uint16(b[4+dataMax:]))
		if size > dataMax {
			return Event{}, fmt.Errorf("%w: output size %d", ErrBadEvent, size)
		}
		ev.Data = append([]byte(nil), b[4:4+size]...)
	case EventGetReport, EventSetReport:
		ev.ID = binary.NativeEndian.Uint32(b[4:])
	}
	return ev, nil
}

// Close releases the handle; the kernel removes the device with it.
func (d *Device) Close() error { return d.f.Close() }

func (d *Device) write(ev []byte) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	n, err := d.f.Write(ev)
	if err != nil {
		return err
	}
	if n != len(ev) {
		return fmt.Errorf("uhid: short write (%d of %d bytes)", n, len(ev))
	}
	return nil
}

// FIDODescriptor is the standard FIDO HID report descriptor: usage page
// 0xF1D0, 64-byte input and output reports, no report IDs. udev's fido_id
// builtin recognises it and hands the hidraw node to the logged-in user.
var FIDODescriptor = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
	0x09, 0x01, // Usage (U2F Authenticator Device)
	0xA1, 0x01, // Collection (Application)
	0x09, 0x20, //   Usage (Input Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x81, 0x02, //   Input (Data, Var, Abs)
	0x09, 0x21, //   Usage (Output Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x91, 0x02, //   Output (Data, Var, Abs)
	0xC0, // End Collection
}
