//go:build linux || darwin

package engine

import "syscall"

// diskUsage: belegter und gesamter Platz des Dateisystems, auf dem dir liegt.
func diskUsage(dir string) (used, size uint64) {
	var st syscall.Statfs_t
	if dir == "" || syscall.Statfs(dir, &st) != nil {
		return
	}
	size = st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	if free < size {
		used = size - free
	}
	return
}
