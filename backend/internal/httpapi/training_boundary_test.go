package httpapi

import (
	"strings"
	"testing"
)

func TestFirstReleaseHasNoTrainingEndpointsOrRoles(t *testing.T) {
	allowedRoles := map[Role]struct{}{
		RoleEmployee:            {},
		RoleTeamAdministrator:   {},
		RoleSystemAdministrator: {},
	}
	forbiddenRouteTerms := []string{"training", "dataset", "relabel", "convert"}

	for _, route := range Routes() {
		routeText := strings.ToLower(string(route.Name) + " " + route.Pattern)
		for _, term := range forbiddenRouteTerms {
			if strings.Contains(routeText, term) {
				t.Fatalf("first-release route exposes forbidden training capability %q: %+v", term, route)
			}
		}
		for _, role := range route.Roles {
			if _, ok := allowedRoles[role]; !ok {
				t.Fatalf("first-release route exposes unapproved role %q: %+v", role, route)
			}
			if strings.Contains(strings.ToLower(string(role)), "training") {
				t.Fatalf("first-release route exposes training role %q: %+v", role, route)
			}
		}
	}
}
