package interfaces

import (
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/api"
	opninterfaces "github.com/biptec/opnsense-go/pkg/interfaces"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestExactVlanReplacement(t *testing.T) {
	base := &vlanResourceModel{
		Device:      types.StringValue("vlan3990"),
		Parent:      types.StringValue("vtnet1"),
		Tag:         types.Int64Value(3990),
		Description: types.StringValue("issue103 endpoint"),
	}
	candidate := opninterfaces.Vlan{
		UUID: "new-local-uuid", Device: "vlan3990", Tag: "3990",
		Parent: api.SelectedMap("vtnet1"), Description: "issue103 endpoint",
	}
	id, err := exactVlanReplacement(base, []opninterfaces.Vlan{candidate})
	if err != nil || id != candidate.UUID {
		t.Fatalf("expected exact reattachment %q, got %q, %v", candidate.UUID, id, err)
	}

	cases := []struct {
		name     string
		prior    *vlanResourceModel
		rows     []opninterfaces.Vlan
		contains string
	}{
		{"zero matches", base, nil, "found 0"},
		{"ambiguous matches", base, []opninterfaces.Vlan{candidate, candidate}, "found 2"},
		{"different parent", base, []opninterfaces.Vlan{{UUID: "other", Device: "vlan3990", Tag: "3990", Parent: api.SelectedMap("vtnet0"), Description: "issue103 endpoint"}}, "found 0"},
		{"different description", base, []opninterfaces.Vlan{{UUID: "other", Device: "vlan3990", Tag: "3990", Parent: api.SelectedMap("vtnet1"), Description: "local infrastructure"}}, "found 0"},
		{"missing uuid", base, []opninterfaces.Vlan{{Device: "vlan3990", Tag: "3990", Parent: api.SelectedMap("vtnet1"), Description: "issue103 endpoint"}}, "no UUID"},
		{"noncanonical device", &vlanResourceModel{Device: types.StringValue("vlan-other"), Parent: types.StringValue("vtnet1"), Tag: types.Int64Value(3990)}, []opninterfaces.Vlan{candidate}, "canonical"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := exactVlanReplacement(tt.prior, tt.rows)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("expected error containing %q, got %v", tt.contains, err)
			}
		})
	}
}
