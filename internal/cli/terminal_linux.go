//go:build linux

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

func isTerminalFile(file *os.File) bool {
	var state syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&state)))
	return errno == 0
}
