//go:build linux

package database

import (
	"errors"
	"io"
	"os"
	"syscall"
)

func readRootOwnedRecoveryManifest(path string, maximumBytes int) (content []byte, err error) {
	before, statErr := os.Lstat(path)
	if statErr != nil || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("recovery manifest is unavailable or unsafe")
	}

	fileDescriptor, openErr := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if openErr != nil {
		return nil, errors.New("recovery manifest is unavailable or unsafe")
	}
	file := os.NewFile(uintptr(fileDescriptor), "recovery-manifest")
	if file == nil {
		_ = syscall.Close(fileDescriptor)
		return nil, errors.New("recovery manifest is unavailable or unsafe")
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			content = nil
			err = errors.New("recovery manifest is unavailable or unsafe")
		}
	}()

	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o400 {
		return nil, errors.New("recovery manifest is unavailable or unsafe")
	}
	platformStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || platformStat.Uid != 0 {
		return nil, errors.New("recovery manifest is unavailable or unsafe")
	}

	content, readErr := io.ReadAll(io.LimitReader(file, int64(maximumBytes)+1))
	if readErr != nil || len(content) > maximumBytes {
		return nil, errors.New("recovery manifest is unavailable or unsafe")
	}
	return content, nil
}
