//go:build omapasskey_testpresence

package presence

// AllowVirtualForTests makes software keyboards count. It exists only in
// test builds; release binaries cannot be talked into it.
func (w *Watcher) AllowVirtualForTests() { w.allowVirtual = true }
