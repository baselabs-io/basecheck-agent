//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func fileFingerprint(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	}
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().Unix())
}
