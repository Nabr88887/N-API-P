//go:build !linux

package config

import "fmt"

func readRootOwnedSecretFile(_, name string, _ int, _ error) ([]byte, error) {
	return nil, fmt.Errorf("%w: %s file requires Linux", ErrInvalidSecretFile, name)
}
