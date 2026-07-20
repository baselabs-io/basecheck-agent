//go:build windows

package main

import (
	"fmt"
	"os"
)

func fileFingerprint(info os.FileInfo) string {
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().Unix())
}
