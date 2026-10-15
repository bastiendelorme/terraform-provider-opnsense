package routes

import (
	"errors"
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/errs"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestExactRouteCandidate(t *testing.T) {
	prior := &routeResourceModel{
		Description: types.StringValue("issue103: 203.0.113.0/24 via endpoint"),
		Network:     types.StringValue("203.0.113.0/24"),
		Gateway:     types.StringValue("ep_issue103-v4"),
		Id:          types.StringValue("old-uuid"),
	}
	row := map[string]any{
		"uuid":    "new-uuid",
		"descr":   "issue103: 203.0.113.0/24 via endpoint",
		"network": "203.0.113.0/24",
		"gateway": "ep_issue103-v4",
	}
	id, err := exactRouteCandidate(prior, []map[string]any{row})
	if err != nil || id != "new-uuid" {
		t.Fatalf("expected route match, got %q %v", id, err)
	}
	tests := []struct {
		name     string
		prior    *routeResourceModel
		rows     []map[string]any
		want     string
		notFound bool
	}{
		{"no match", prior, nil, "", true},
		{"duplicate", prior, []map[string]any{row, row}, "found 2", false},
		{"wrong network", prior, []map[string]any{{"uuid": "other", "descr": "issue103: 203.0.113.0/24 via endpoint", "network": "203.0.114.0/24"}}, "", true},
		{"wrong description", prior, []map[string]any{{"uuid": "other", "descr": "foreign route", "network": "203.0.113.0/24"}}, "", true},
		{"missing id", prior, []map[string]any{{"descr": "issue103: 203.0.113.0/24 via endpoint", "network": "203.0.113.0/24"}}, "lacks UUID", false},
		{"no state gateway", &routeResourceModel{Description: prior.Description, Network: prior.Network, Gateway: types.StringNull()}, []map[string]any{row}, "lacks description", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, e := exactRouteCandidate(tc.prior, tc.rows)
			if tc.notFound {
				var notFound *errs.NotFoundError
				if !errors.As(e, &notFound) {
					t.Fatalf("expected remote-not-found, got %v", e)
				}
				return
			}
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("wanted error with %q, got %v", tc.want, e)
			}
		})
	}
}
