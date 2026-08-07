package httpapi

import (
	"strings"
	"testing"
)

func TestRouteInventoryHasGlobalModelPolicyOnlyAndNoTeamOverride(t *testing.T) {
	routes := Routes()
	var foundGlobalRead, foundGlobalReplace bool
	for _, route := range routes {
		if strings.Contains(string(route.Name), "team") && strings.Contains(string(route.Name), "model") {
			t.Fatalf("team-specific model policy route exists: %s", route.Name)
		}
		switch string(route.Name) {
		case "admin.model_allowlist.get":
			foundGlobalRead = true
		case "admin.model_allowlist.replace":
			foundGlobalReplace = true
		}
	}
	if !foundGlobalRead || !foundGlobalReplace {
		t.Fatalf("global model policy routes = read:%t replace:%t", foundGlobalRead, foundGlobalReplace)
	}
}
