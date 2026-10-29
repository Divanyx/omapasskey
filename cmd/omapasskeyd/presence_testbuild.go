//go:build omapasskey_testpresence

package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/Divanyx/omapasskey/internal/ctap2"
	"github.com/Divanyx/omapasskey/internal/presence"
	"github.com/Divanyx/omapasskey/internal/status"
)

// Test builds only: OMAPASSKEY_TEST_PRESENCE=auto confirms every prompt by
// itself, =deny refuses them. Release binaries are never built with this tag.
func newPresence(w *presence.Watcher, publish func(any)) promptPresence {
	real := &presenceBridge{watcher: w, publish: publish}
	mode := os.Getenv("OMAPASSKEY_TEST_PRESENCE")
	if mode == "virtual-ok" {
		slog.Warn("TEST BUILD: software keyboards can confirm")
		w.AllowVirtualForTests()
		return real
	}
	if mode != "auto" && mode != "deny" {
		return real
	}
	slog.Warn("TEST BUILD: user presence is simulated", "mode", mode)
	return &fakePresence{bridge: real, deny: mode == "deny"}
}

// testDelay is how long the simulated user takes (OMAPASSKEY_TEST_DELAY_MS).
func testDelay() time.Duration {
	if ms, err := strconv.Atoi(os.Getenv("OMAPASSKEY_TEST_DELAY_MS")); err == nil && ms >= 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return 300 * time.Millisecond
}

type fakePresence struct {
	bridge *presenceBridge
	deny   bool
}

func (f *fakePresence) Current() *status.Prompt { return f.bridge.Current() }

func (f *fakePresence) Confirm(ctx context.Context, pr ctap2.Prompt) error {
	p := &status.Prompt{ID: f.bridge.next.Add(1), Op: pr.Op, RPID: pr.RPID, TimeoutMs: 30000}
	f.bridge.publish(map[string]any{"type": "prompt", "prompt": p})
	select {
	case <-ctx.Done():
		f.bridge.publish(map[string]any{"type": "prompt-end", "id": p.ID, "result": "cancelled"})
		return ctap2.ErrPresenceDenied
	case <-time.After(testDelay()):
	}
	if f.deny {
		f.bridge.publish(map[string]any{"type": "prompt-end", "id": p.ID, "result": "denied"})
		return ctap2.ErrPresenceDenied
	}
	f.bridge.publish(map[string]any{"type": "prompt-end", "id": p.ID, "result": "confirmed"})
	return nil
}
