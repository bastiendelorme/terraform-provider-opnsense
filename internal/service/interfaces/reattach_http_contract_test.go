package interfaces

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/api"
	"github.com/biptec/opnsense-go/pkg/opnsense"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// These HTTP-contract tests exercise the REAL opnsense-go Search methods that
// the Provider uses on a missing UUID. No router, fixture or Terraform state
// is modified. This catches search path/payload/SelectedMap decoding errors
// that exact*Replacement tests with already-decoded rows cannot detect.
func TestReattachVlanHTTPContract(t *testing.T) {
	ctx := context.Background()
	const endpointPath = "/api/interfaces/vlan_settings/search_item"
	calls := 0
	body := map[string]any{
		"total": 1, "rowCount": 1, "current": 1,
		"rows": []map[string]any{{
			"uuid": "new-vlan-uuid", "descr": "Issue #103 shared-test Ubuntu endpoint state continuity",
			"vlanif": "vlan3990", "tag": "3990",
			"if": map[string]any{
				"vtnet0": map[string]any{"selected": 0, "value": "vtnet0"},
				"vtnet1": map[string]any{"selected": 1, "value": "vtnet1"},
			},
			"pcp":   map[string]any{"0": map[string]any{"selected": 1, "value": "0"}},
			"proto": map[string]any{},
		}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		if req.Method != http.MethodPost || req.URL.Path != endpointPath {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encode mock response: %v", err)
		}
	}))
	defer server.Close()
	r := &vlanResource{client: opnsense.NewClient(api.NewClient(api.Options{Uri: server.URL}))}
	prior := &vlanResourceModel{
		Parent:      types.StringValue("vtnet1"),
		Device:      types.StringValue("vlan3990"),
		Tag:         types.Int64Value(3990),
		Description: types.StringValue("Issue #103 shared-test Ubuntu endpoint state continuity"),
	}
	id, err := r.reattachVlan(ctx, prior)
	if err != nil || id != "new-vlan-uuid" {
		t.Fatalf("reattach VLAN through typed OPNsense HTTP Search: id=%q err=%v", id, err)
	}
	if calls != 1 {
		t.Fatalf("search requests=%d, want 1", calls)
	}
	// Even with correct semantic identity, an incomplete/malicious
	// response must fail safely; no phantom create or mistaken UUID adoption.
	body["total"] = 2
	if id, err = r.reattachVlan(ctx, prior); err == nil || !strings.Contains(err.Error(), "incomplete") || id != "" {
		t.Fatalf("incomplete VLAN results must fail closed: id=%q err=%v", id, err)
	}
}

func TestReattachVIPHTTPContract(t *testing.T) {
	ctx := context.Background()
	const endpointPath = "/api/interfaces/vip_settings/search_item"
	calls := 0
	body := map[string]any{
		"total": 1, "rowCount": 1, "current": 1,
		"rows": []map[string]any{{
			"uuid": "new-vip-uuid", "descr": "Issue #103 shared-test Ubuntu endpoint state continuity gateway",
			"mode": "carp", "interface": "ep_ha_issue_f00dbabe", "vhid": "165",
			"subnet": "10.250.99.1", "subnet_bits": "30",
			"advskew": "100", // Local receiver skew must NOT identify the VIP.
		}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		if req.Method != http.MethodPost || req.URL.Path != endpointPath {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encode mock response: %v", err)
		}
	}))
	defer server.Close()
	r := &vipResource{client: opnsense.NewClient(api.NewClient(api.Options{Uri: server.URL}))}
	prior := &vipResourceModel{
		Mode:        types.StringValue("carp"),
		Interface:   types.StringValue("ep_ha_issue_f00dbabe"),
		Network:     types.StringValue("10.250.99.1/30"),
		VHID:        types.Int64Value(165),
		Description: types.StringValue("Issue #103 shared-test Ubuntu endpoint state continuity gateway"),
	}
	id, err := r.reattachVip(ctx, prior)
	if err != nil || id != "new-vip-uuid" {
		t.Fatalf("reattach VIP through untyped OPNsense HTTP Search: id=%q err=%v", id, err)
	}
	if calls != 1 {
		t.Fatalf("search requests=%d, want 1", calls)
	}
	body["total"] = 2
	if id, err = r.reattachVip(ctx, prior); err == nil || !strings.Contains(err.Error(), "incomplete") || id != "" {
		t.Fatalf("incomplete VIP search must fail closed: id=%q err=%v", id, err)
	}
}
