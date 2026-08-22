//go:build !linux

package database

import "errors"

func readRootOwnedRecoveryManifest(_ string, _ int) ([]byte, error) {
	return nil, errors.New("recovery manifest validation requires Linux")
}
