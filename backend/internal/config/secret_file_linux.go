//go:build linux

package config

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

func readRootOwnedSecretFile(path, name string, maximumBytes int, oversizedError error) (content []byte, err error) {
	before, statErr := os.Lstat(path)
	if statErr != nil || before.Mode()&os.ModeSymlink != 0 {
		return nil, safeSecretFileError(name)
	}

	fileDescriptor, openErr := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if openErr != nil {
		return nil, safeSecretFileError(name)
	}
	file := os.NewFile(uintptr(fileDescriptor), name)
	if file == nil {
		if closeErr := syscall.Close(fileDescriptor); closeErr != nil {
			return nil, safeSecretFileError(name)
		}
		return nil, safeSecretFileError(name)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			clear(content)
			content = nil
			err = safeSecretFileError(name)
		}
	}()

	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o400 {
		return nil, safeSecretFileError(name)
	}
	platformStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || platformStat.Uid != 0 {
		return nil, safeSecretFileError(name)
	}

	content, readErr := io.ReadAll(io.LimitReader(file, int64(maximumBytes)+1))
	if readErr != nil {
		clear(content)
		return nil, safeSecretFileError(name)
	}
	if len(content) > maximumBytes {
		clear(content)
		return nil, oversizedError
	}
	return content, nil
}

func safeSecretFileError(name string) error {
	return fmt.Errorf("%w: %s file is unavailable or unsafe", ErrInvalidSecretFile, name)
}
