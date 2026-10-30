// Package uicheck holds static checks on the QML plugin that the Go test run
// enforces in CI.
package uicheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Site and account names in the UI come from websites. Qt renders Text and
// Label as AutoText by default, which interprets markup: an <img> in a user
// name would make the shell fetch a URL. Every text item must be plain text,
// and attached ToolTip.text (which uses AutoText) must not be used at all.
func TestEveryTextIsPlain(t *testing.T) {
	files, err := filepath.Glob("../../ui/*.qml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no QML files found: %v", err)
	}
	opener := regexp.MustCompile(`^(\s*)(Text|Label|TextEdit|TextArea)\s*\{\s*$`)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if strings.Contains(line, "ToolTip.text") {
				t.Errorf("%s:%d: attached ToolTip.text renders AutoText; use a ToolTip with a plain Text contentItem", f, i+1)
			}
			if strings.Contains(line, "RichText") || strings.Contains(line, "StyledText") || strings.Contains(line, "AutoText") || strings.Contains(line, "MarkdownText") {
				t.Errorf("%s:%d: rich text format", f, i+1)
			}
			m := opener.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			indent := len(m[1])
			plain := false
			for j := i + 1; j < len(lines); j++ {
				l := lines[j]
				if strings.TrimSpace(l) == "}" && len(l)-len(strings.TrimLeft(l, " ")) == indent {
					break
				}
				if strings.TrimSpace(l) == "textFormat: Text.PlainText" {
					plain = true
				}
			}
			if !plain {
				t.Errorf("%s:%d: %s without textFormat: Text.PlainText", f, i+1, m[2])
			}
		}
	}
}
