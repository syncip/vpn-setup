//go:build !linux && !darwin

package engine

// diskUsage: nur unter Linux gebraucht (Entwicklung unter Windows läuft im Testmodus).
func diskUsage(string) (used, size uint64) { return 0, 0 }
