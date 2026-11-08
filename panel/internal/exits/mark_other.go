//go:build !linux

package exits

import "syscall"

// Außerhalb von Linux (Entwicklung unter Windows) gibt es keine Markierung: direkt verbinden.
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	return nil
}
