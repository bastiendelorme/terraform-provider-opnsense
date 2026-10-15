package system

import (
	"errors"
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/errs"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestExactPolicyAssignmentReplacement(t *testing.T) {
	state := &interfacePolicyAssignmentResourceModel{
		Interface: types.StringValue("ha_issue103_ubuntu"),
		PolicyID:  types.StringValue("endpoint"),
		ID:        types.StringValue("old-local-uuid"),
	}
	match := map[string]string{"uuid": "new-mvc-uuid", "interface": "ha_issue103_ubuntu", "policy_id": "endpoint"}
	got, err := exactPolicyAssignmentReplacement(state, []map[string]string{match})
	if got != "new-mvc-uuid" || err != nil {
		t.Fatalf("expected exact policy adoption, got %q %v", got, err)
	}
	table := []struct {
		name     string
		rows     []map[string]string
		state    *interfacePolicyAssignmentResourceModel
		want     string
		notFound bool
	}{
		{"missing", nil, state, "", true},
		{"ambiguous", []map[string]string{match, match}, state, "found 2", false},
		{"wrong policy", []map[string]string{{"uuid": "foreign", "interface": "ha_issue103_ubuntu", "policy_id": "core"}}, state, "", true},
		{"wrong interface", []map[string]string{{"uuid": "foreign", "interface": "other_endpoint", "policy_id": "endpoint"}}, state, "", true},
		{"missing UUID", []map[string]string{{"interface": "ha_issue103_ubuntu", "policy_id": "endpoint"}}, state, "no UUID", false},
		{"unknown interface", []map[string]string{match}, &interfacePolicyAssignmentResourceModel{Interface: types.StringUnknown(), PolicyID: types.StringValue("endpoint")}, "lacks a stable", false},
	}
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			_, e := exactPolicyAssignmentReplacement(tc.state, tc.rows)
			if tc.notFound {
				var notFound *errs.NotFoundError
				if !errors.As(e, &notFound) {
					t.Fatalf("expected remote-not-found, got %v", e)
				}
				return
			}
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("wanted error containing %q, got %v", tc.want, e)
			}
		})
	}
}
