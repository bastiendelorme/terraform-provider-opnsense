package firewall

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/api"
	"github.com/biptec/opnsense-go/pkg/opnsense"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// A stale native firewall UUID must trigger an exact search and no
// guessed adoption, using the actual opnsense-go HTTP search path.
func TestReattachFilterHTTPContract(t *testing.T) {
	ctx := context.Background()
	rows := []map[string]any{{
		"uuid":        "new-firewall-uuid",
		"description": "Issue #103 shared-test Ubuntu endpoint state continuity: allow endpoint IPv4",
		"interface":   "ep_ha_issue_f00dbabe", "action": "pass", "direction": "in",
		"ipprotocol": "inet", "protocol": "", "source_net": "10.250.99.0/30",
		"destination_net": "any", "source_port": "", "destination_port": "",
	}}
	total := 1
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.Method != http.MethodPost || req.URL.Path != "/api/firewall/filter/searchRule" {
			t.Errorf("wrong firewall Search endpoint: %s %s", req.Method, req.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": total, "rowCount": len(rows), "current": 1, "rows": rows,
		})
	}))
	defer server.Close()
	r := &filterResource{client: opnsense.NewClient(api.NewClient(api.Options{Uri: server.URL}))}
	prior := &filterResourceModel{
		Description: types.StringValue("Issue #103 shared-test Ubuntu endpoint state continuity: allow endpoint IPv4"),
		Enabled:     types.BoolValue(true),
		Interface: &filterInterfaceBlock{
			Interface: types.SetValueMust(types.StringType,
				[]attr.Value{types.StringValue("ep_ha_issue_f00dbabe")}),
			Invert: types.BoolValue(false),
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
	id, err := r.reattachFilter(ctx, prior)
	if err != nil || id != "new-firewall-uuid" {
		t.Fatalf("HTTP Search filter reattach = %q, %v", id, err)
	}
	if requests != 1 {
		t.Fatalf("Search calls=%d, expected 1", requests)
	}
	total = 2
	if id, err = r.reattachFilter(ctx, prior); id != "" ||
		err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("truncated HTTP search must refuse: %q %v", id, err)
	}
	total = 1
	rows[0]["interface"] = "wan"
	if id, err = r.reattachFilter(ctx, prior); id != "" ||
		err == nil || !strings.Contains(err.Error(), "found 0") {
		t.Fatalf("foreign firewall rule must not be adopted: %q %v", id, err)
	}
}
