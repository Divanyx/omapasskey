package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Divanyx/omapasskey/internal/ctap2"
)

func TestTermSafe(t *testing.T) {
	for in, want := range map[string]string{
		"alice@example.com":       "alice@example.com",
		"Ünïcödé 名前 🙂":            "Ünïcödé 名前 🙂",
		"a\x1b]52;c;aGk=\x07b":    `a\x1b]52;c;aGk=\x07b`,
		"line\nfake\tcol\r":       `line\x0afake\x09col\x0d`,
		"del\x7f c1\u009b31m":     `del\x7f c1\u009b31m`,
		"evil\u202egpj.exe\u2066": `evil\u202egpj.exe\u2066`,
		"bad\xffutf8":             `bad\xffutf8`,
	} {
		if got := termSafe(in); got != want {
			t.Errorf("termSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestListOutputIsTerminalSafe stores what a hostile site could register and
// checks that 'omapasskey list' writes none of it to the terminal raw.
func TestListOutputIsTerminalSafe(t *testing.T) {
	osc52 := "\x1b]52;c;cm0gLXJmIH4K\x07"
	accts := []ctap2.AccountInfo{
		{ID: []byte{1, 2, 3, 4, 5, 6}, RPID: "evil.example" + osc52, UserName: "victim" + osc52, Discoverable: true},
		{ID: []byte{7, 8, 9, 10, 11, 12}, RPID: "x.example", DisplayName: "\u009b2J\u202e\r\nID\tSITE", Discoverable: true},
	}
	var buf bytes.Buffer
	if err := printAccounts(&buf, accts); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if lines := strings.Count(out, "\n"); lines != 3 {
		t.Errorf("want header + 2 rows, got %d lines:\n%s", lines, out)
	}
	for _, r := range out {
		if (r < 0x20 && r != '\n') || (r >= 0x7f && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) {
			t.Fatalf("raw control character %U reached the terminal:\n%q", r, out)
		}
	}
	if !strings.Contains(out, `victim\x1b]52;c;cm0gLXJmIH4K\x07`) {
		t.Errorf("escaped name not shown:\n%s", out)
	}
}

// TestJSONStaysJSON: termSafe on JSON output keeps it valid and equal.
func TestJSONStaysJSON(t *testing.T) {
	in := map[string]string{"name": "a\u009b\u202eb\x1b"}
	raw, _ := json.Marshal(in)
	var back map[string]string
	if err := json.Unmarshal([]byte(termSafe(string(raw))), &back); err != nil || back["name"] != in["name"] {
		t.Fatalf("termSafe broke JSON: %v %q", err, back)
	}
}
