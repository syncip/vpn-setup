//go:build !linux

package tor2socks

import "errors"

// Run gibt es nur unter Linux.
func Run(dev string, stop <-chan struct{}) error {
	return errors.New("Tor-Ausgänge gibt es nur unter Linux")
}

// Main: nur unter Linux.
func Main(args []string) error {
	if _, _, _, err := parseArgs(args); err != nil {
		return err
	}
	return Run("", nil)
}
