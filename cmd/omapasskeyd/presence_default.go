//go:build !omapasskey_testpresence

package main

import "github.com/Divanyx/omapasskey/internal/presence"

// newPresence asks the physical keyboard. Release builds have no other way.
func newPresence(w *presence.Watcher, publish func(any)) promptPresence {
	return &presenceBridge{watcher: w, publish: publish}
}
