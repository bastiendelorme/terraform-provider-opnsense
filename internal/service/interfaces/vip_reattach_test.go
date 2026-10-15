package interfaces

import (
	"errors"
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/errs"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestExactVipReplacement(t *testing.T) {
	prior := &vipResourceModel{
		Interface:   types.StringValue("ha_issue103_ubuntu"),
		Mode:        types.StringValue("carp"),
		Network:     types.StringValue("10.250.99.1/30"),
		VHID:        types.Int64Value(165),
		Description: types.StringValue("Issue103 IPv4 CARP"),
	}
	match := map[string]any{
		"uuid": "new-receiver-vip-uuid", "interface": "ha_issue103_ubuntu",
		"mode": "carp", "subnet": "10.250.99.1", "subnet_bits": "30",
		"vhid": "165", "descr": "Issue103 IPv4 CARP", "advskew": "100",
	}
	got, err := exactVipReplacement(prior, []map[string]any{match})
	if err != nil || got != "new-receiver-vip-uuid" {
		t.Fatalf("expected exact receiver VIP reattachment, got %q (%v)", got, err)
	}
	// CARP advskew is strictly receiver local, and must NOT affect identity.
	differentSkew := cloneVipRow(match, "advskew", "0")
	got, err = exactVipReplacement(prior, []map[string]any{differentSkew})
	if err != nil || got != "new-receiver-vip-uuid" {
		t.Fatalf("different local CARP skew must not affect reattachment: %q (%v)", got, err)
	}
	cases := []struct {
		name     string
		state    *vipResourceModel
		rows     []map[string]any
		want     string
		notFound bool
	}{
		{"missing", prior, nil, "", true},
		{"ambiguous", prior, []map[string]any{match, match}, "found 2", false},
		{"wrong subnet", prior, []map[string]any{cloneVipRow(match, "subnet", "10.250.98.1")}, "", true},
		{"wrong prefix", prior, []map[string]any{cloneVipRow(match, "subnet_bits", "32")}, "", true},
		{"wrong interface", prior, []map[string]any{cloneVipRow(match, "interface", "wan")}, "", true},
		{"wrong description", prior, []map[string]any{cloneVipRow(match, "descr", "other")}, "", true},
		{"wrong vhid", prior, []map[string]any{cloneVipRow(match, "vhid", "166")}, "", true},
		{"missing uuid", prior, []map[string]any{cloneVipRow(match, "uuid", "")}, "no UUID", false},
		{"legacy wrong field", prior, []map[string]any{cloneVipRow(cloneVipRow(match, "subnet", ""), "network", "10.250.99.1/30")}, "", true},
		{"missing address state", &vipResourceModel{Interface: prior.Interface, Mode: prior.Mode, Network: types.StringNull(), Description: prior.Description}, []map[string]any{match}, "exact semantic identity", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, e := exactVipReplacement(tc.state, tc.rows)
			if tc.notFound {
				var notFound *errs.NotFoundError
				if !errors.As(e, &notFound) {
					t.Fatalf("expected remote-not-found, got %v", e)
				}
				return
			}
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, e)
			}
		})
	}
}

func cloneVipRow(row map[string]any, key string, value any) map[string]any {
	cloned := make(map[string]any, len(row))
	for k, v := range row {
		cloned[k] = v
	}
	cloned[key] = value
	return cloned
}

func TestExactVipReplacementIPAlias(t *testing.T) {
	prior := &vipResourceModel{
		Interface:   types.StringValue("ha_issue103_ubuntu"),
		Mode:        types.StringValue("ipalias"),
		Network:     types.StringValue("fd42:103:3990::1/64"),
		VHID:        types.Int64Value(165),
		Description: types.StringValue("Issue103 IPv6 VIP alias"),
	}
	row := map[string]any{
		"uuid": "fresh-ipv6-vip-uuid", "interface": "ha_issue103_ubuntu",
		"mode": "ipalias", "subnet": "fd42:103:3990::1", "subnet_bits": "64",
		"vhid": "165", "descr": "Issue103 IPv6 VIP alias",
	}
	id, err := exactVipReplacement(prior, []map[string]any{row})
	if err != nil || id != "fresh-ipv6-vip-uuid" {
		t.Fatalf("IPv6 alias reattachment failed: %q (%v)", id, err)
	}
}
