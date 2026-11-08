//go:build linux

package exits

import "syscall"

// markControl setzt die Paketmarkierung (SO_MARK) eines Sockets → Routing über die Gruppe.
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		})
		if err != nil {
			return err
		}
		return serr
	}
}
