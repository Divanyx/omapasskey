package presence

import (
	"fmt"
	"strings"
)

// Combo is the key combination that counts as a "touch".
type Combo struct {
	Spec   string   // canonical form, e.g. "leftshift+rightshift"
	Codes  []int    // evdev key codes
	Labels []string // for the prompt, e.g. "Left Shift"
}

type keyName struct {
	code  int
	label string
}

var keyNames = map[string]keyName{
	"leftshift": {42, "Left Shift"}, "rightshift": {54, "Right Shift"},
	"leftctrl": {29, "Left Ctrl"}, "rightctrl": {97, "Right Ctrl"},
	"leftalt": {56, "Left Alt"}, "rightalt": {100, "Right Alt"},
	"leftmeta": {125, "Left Super"}, "rightmeta": {126, "Right Super"},
	"space": {57, "Space"}, "enter": {28, "Enter"}, "tab": {15, "Tab"},
	"backspace": {14, "Backspace"}, "capslock": {58, "Caps Lock"},
	"insert": {110, "Insert"}, "delete": {111, "Delete"}, "home": {102, "Home"},
	"end": {107, "End"}, "pageup": {104, "Page Up"}, "pagedown": {109, "Page Down"},
	"up": {103, "Up"}, "down": {108, "Down"}, "left": {105, "Left"}, "right": {106, "Right"},
	"scrolllock": {70, "Scroll Lock"}, "pause": {119, "Pause"}, "print": {99, "Print"},
	"f1": {59, "F1"}, "f2": {60, "F2"}, "f3": {61, "F3"}, "f4": {62, "F4"},
	"f5": {63, "F5"}, "f6": {64, "F6"}, "f7": {65, "F7"}, "f8": {66, "F8"},
	"f9": {67, "F9"}, "f10": {68, "F10"}, "f11": {87, "F11"}, "f12": {88, "F12"},
	"1": {2, "1"}, "2": {3, "2"}, "3": {4, "3"}, "4": {5, "4"}, "5": {6, "5"},
	"6": {7, "6"}, "7": {8, "7"}, "8": {9, "8"}, "9": {10, "9"}, "0": {11, "0"},
	"q": {16, "Q"}, "w": {17, "W"}, "e": {18, "E"}, "r": {19, "R"}, "t": {20, "T"},
	"y": {21, "Y"}, "u": {22, "U"}, "i": {23, "I"}, "o": {24, "O"}, "p": {25, "P"},
	"a": {30, "A"}, "s": {31, "S"}, "d": {32, "D"}, "f": {33, "F"}, "g": {34, "G"},
	"h": {35, "H"}, "j": {36, "J"}, "k": {37, "K"}, "l": {38, "L"},
	"z": {44, "Z"}, "x": {45, "X"}, "c": {46, "C"}, "v": {47, "V"}, "b": {48, "B"},
	"n": {49, "N"}, "m": {50, "M"},
}

// DefaultCombo is both Shift keys.
func DefaultCombo() *Combo {
	c, _ := ParseCombo("leftshift+rightshift")
	return c
}

// ParseCombo reads "leftctrl+rightctrl" style specs: two to four distinct
// keys, Escape excluded because it cancels.
func ParseCombo(spec string) (*Combo, error) {
	parts := strings.FieldsFunc(strings.ToLower(spec), func(r rune) bool { return r == '+' || r == ' ' || r == ',' })
	if len(parts) < 2 || len(parts) > 4 {
		return nil, fmt.Errorf("a combination needs 2 to 4 keys, e.g. leftshift+rightshift")
	}
	c := &Combo{}
	seen := map[int]bool{}
	for _, p := range parts {
		k, ok := keyNames[p]
		if !ok {
			return nil, fmt.Errorf("unknown key %q (names like leftshift, rightctrl, leftalt, space, f12, a)", p)
		}
		if seen[k.code] {
			return nil, fmt.Errorf("key %q appears twice", p)
		}
		seen[k.code] = true
		c.Codes = append(c.Codes, k.code)
		c.Labels = append(c.Labels, k.label)
	}
	c.Spec = strings.Join(parts, "+")
	return c, nil
}

// KeyNames lists the accepted key names.
func KeyNames() []string {
	out := make([]string, 0, len(keyNames))
	for n := range keyNames {
		out = append(out, n)
	}
	return out
}
