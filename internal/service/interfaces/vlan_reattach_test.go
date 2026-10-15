package interfaces

import (
	"errors"
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/api"
	"github.com/biptec/opnsense-go/pkg/errs"
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
	// Actual OPNsense search_item VLAN rows use vlanif with a suffix
	// containing the description, unlike canonical GetVlan rows.
	decorated := candidate
	decorated.Device = "vlan3990 [issue103 endpoint]"
	id, err = exactVlanReplacement(base, []opninterfaces.Vlan{decorated})
	if err != nil || id != candidate.UUID {
		t.Fatalf("decorated search device should reattach exact VLAN: id=%q err=%v", id, err)
	}

	cases := []struct {
		name     string
		prior    *vlanResourceModel
		rows     []opninterfaces.Vlan
		contains string
	}{
		{"ambiguous matches", base, []opninterfaces.Vlan{candidate, candidate}, "found 2"},
		{"missing uuid", base, []opninterfaces.Vlan{{Device: "vlan3990", Tag: "3990", Parent: api.SelectedMap("vtnet1"), Description: "issue103 endpoint"}}, "no UUID"},
		{"noncanonical device", &vlanResourceModel{Device: types.StringValue("vlan-other"), Parent: types.StringValue("vtnet1"), Tag: types.Int64Value(3990)}, []opninterfaces.Vlan{candidate}, "canonical"},
	}
	noMatchCases := [][]opninterfaces.Vlan{
		nil,
		{{UUID: "other", Device: "vlan3990", Tag: "3990", Parent: api.SelectedMap("vtnet0"), Description: "issue103 endpoint"}},
		{{UUID: "other", Device: "vlan3990", Tag: "3990", Parent: api.SelectedMap("vtnet1"), Description: "local infrastructure"}},
		{{UUID: "other", Device: "vlan3990 [other]", Tag: "3990", Parent: api.SelectedMap("vtnet1"), Description: "issue103 endpoint"}},
	}
	for _, rows := range noMatchCases {
		if id, err = exactVlanReplacement(base, rows); id != "" {
			t.Fatalf("zero-match replacement returned unexpected id %q", id)
		} else {
			var notFound *errs.NotFoundError
			if !errors.As(err, &notFound) {
				t.Fatalf("zero-match replacement should be remote-not-found, got %v", err)
			}
		}
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
