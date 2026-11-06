//go:build !linux && !darwin

package engine

func lockFile(path string) (func(), error) { return func() {}, nil }
