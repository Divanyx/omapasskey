package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// termSafe makes a string chosen by someone else (a website's account name or
// RP ID, a Bluetooth keyboard's name) safe to print to a terminal. Control
// characters (C0, DEL, C1), direction overrides and invalid UTF-8 are shown as
// \xNN or \uNNNN instead of being written, so no escape sequence such as
// OSC 52 (clipboard write) can reach the terminal and no line can be faked.
func termSafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r < 0x80 && unicode.IsControl(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}
