package firewall

import (
	"errors"
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/errs"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestExactFilterReplacement(t *testing.T) {
	prior := &filterResourceModel{
		Description: types.StringValue("issue103: allow endpoint IPv4"),
		Enabled:     types.BoolValue(true),
		Interface: &filterInterfaceBlock{
			Interface: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("ep_issue103")}),
			Invert:    types.BoolValue(false),
		},
		Filter: &filterFilterBlock{
			Quick:       types.BoolValue(true),
			Action:      types.StringValue("pass"),
			Direction:   types.StringValue("in"),
			IPProtocol:  types.StringValue("inet"),
			Protocol:    types.StringValue(""),
			Source:      &firewallLocation{Net: types.StringValue("10.250.99.0/30")},
			Destination: &firewallLocation{Net: types.StringValue("any")},
		},
	}
	match := map[string]any{
		"uuid":             "new-local-rule-uuid",
		"description":      "issue103: allow endpoint IPv4",
		"interface":        "ep_issue103",
		"action":           "pass",
		"direction":        "in",
		"ipprotocol":       "inet",
		"protocol":         "",
		"source_net":       "10.250.99.0/30",
		"destination_net":  "any",
		"source_port":      "",
		"destination_port": "",
	}
	id, err := exactFilterReplacement(prior, []map[string]any{match})
	if err != nil || id != "new-local-rule-uuid" {
		t.Fatalf("expected exact reattach: %q %v", id, err)
	}
	cases := []struct {
		name     string
		rows     []map[string]any
		needle   string
		notFound bool
	}{
		{"missing", nil, "", true},
		{"ambiguous", []map[string]any{match, match}, "found 2", false},
		{"wrong interface", []map[string]any{cloneRow(match, "interface", "wan")}, "", true},
		{"wrong source", []map[string]any{cloneRow(match, "source_net", "any")}, "", true},
		{"wrong destination", []map[string]any{cloneRow(match, "destination_net", "192.0.2.0/24")}, "", true},
		{"wrong direction", []map[string]any{cloneRow(match, "direction", "out")}, "", true},
		{"missing uuid", []map[string]any{cloneRow(match, "uuid", "")}, "no UUID", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := exactFilterReplacement(prior, tc.rows)
			if tc.notFound {
				var notFound *errs.NotFoundError
				if !errors.As(err, &notFound) {
					t.Fatalf("expected remote-not-found, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.needle) {
				t.Fatalf("expected %q, got %v", tc.needle, err)
			}
		})
	}
}

func cloneRow(base map[string]any, key string, value any) map[string]any {
	next := make(map[string]any, len(base))
	for k, v := range base {
		next[k] = v
	}
	next[key] = value
	return next
}
