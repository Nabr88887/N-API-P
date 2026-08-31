package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerfileRestrictsGoModuleProxy(t *testing.T) {
	dockerfilePath := filepath.Join("..", "..", "..", "Dockerfile")
	contents, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}

	dockerfile := strings.ReplaceAll(string(contents), "\r\n", "\n")
	required := []string{
		"ARG GOPROXY=https://proxy.golang.org",
		`"https://proxy.golang.org"|"https://goproxy.cn") ;;`,
		"*) exit 1 ;;",
		`GOPROXY="$GOPROXY" go mod download`,
		`GOPROXY="$GOPROXY" go mod verify`,
	}
	for _, contract := range required {
		if !strings.Contains(dockerfile, contract) {
			t.Errorf("Dockerfile missing Go module proxy contract %q", contract)
		}
	}

	if count := strings.Count(dockerfile, "ARG GOPROXY="); count != 1 {
		t.Errorf("Dockerfile GOPROXY argument count = %d, want 1", count)
	}
	if strings.Contains(dockerfile, ",direct") {
		t.Error("Dockerfile GOPROXY contract must not allow a direct fallback")
	}
}
