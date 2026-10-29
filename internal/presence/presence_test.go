package presence

import "testing"

func TestHasKeys(t *testing.T) {
	// A real laptop keyboard bitmap (AT Translated Set 2).
	kb := "402000007 ff803078f800d001 feffffdfffcfffff fffffffffffffffe"
	if !hasKeys(kb, keyLeftShift, keyRightShift, keyEsc) {
		t.Fatal("laptop keyboard not recognised")
	}
	// A mouse: only buttons in the third word.
	mouse := "1f0000 0 0 0 0"
	if hasKeys(mouse, keyLeftShift, keyRightShift) {
		t.Fatal("mouse recognised as keyboard")
	}
	if hasKeys("", keyLeftShift) {
		t.Fatal("empty bitmap")
	}
}

func TestIsVirtual(t *testing.T) {
	cases := map[string]bool{
		"/sys/devices/platform/i8042/serio0/input/input4":                                 false,
		"/sys/devices/pci0000:00/0000:00:08.1/usb3/3-3/3-3:1.0/0003:258A:0150.0001/input": false,
		"/sys/devices/virtual/input/input99":                                              true, // uinput
		"/sys/devices/virtual/misc/uhid/0005:046D:B02D.0006/input/input35":                true, // BLE/uhid
		"/tmp/fake": true,
	}
	for path, want := range cases {
		if got := IsVirtual(path); got != want {
			t.Errorf("IsVirtual(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestKeyboardsOnThisMachine(t *testing.T) {
	for _, kb := range New(0).Keyboards() {
		t.Logf("physical keyboard: %s (%s)", kb.Node, kb.Name)
	}
}
