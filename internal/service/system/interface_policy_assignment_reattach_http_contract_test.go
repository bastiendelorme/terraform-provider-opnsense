package system

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/api"
	"github.com/biptec/opnsense-go/pkg/errs"
	"github.com/biptec/opnsense-go/pkg/opnsense"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Native OPNsense MVC policy assignment IDs change on clean routers;
// its API Search is a GET (not the POST used by other native resources).
// Exercise the actual client endpoint plus semantic matching.
func TestReattachPolicyAssignmentHTTPContract(t *testing.T) {
	ctx := context.Background()
	rows := []map[string]string{{
		"uuid":      "new-local-policy-uuid",
		"interface": "ep_ha_issue_f00dbabe",
		"policy_id": "endpoint",
	}}
	total := 1
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.Method != http.MethodGet ||
			req.URL.Path != "/api/api_extensions/interface_policy/searchAssignment" {
			t.Errorf("wrong policy Search endpoint: %s %s", req.Method, req.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": total, "rowCount": len(rows), "current": 1, "rows": rows,
		})
	}))
	defer server.Close()
	r := &interfacePolicyAssignmentResource{
		client: opnsense.NewClient(api.NewClient(api.Options{Uri: server.URL})),
	}
	prior := &interfacePolicyAssignmentResourceModel{
		ID:        types.StringValue("stale-policy-uuid"),
		Interface: types.StringValue("ep_ha_issue_f00dbabe"),
		PolicyID:  types.StringValue("endpoint"),
	}
	id, err := r.reattach(ctx, prior)
	if err != nil || id != "new-local-policy-uuid" {
		t.Fatalf("HTTP policy-assignment reattach = %q, %v", id, err)
	}
	if requests != 1 {
		t.Fatalf("Search requests=%d, expected 1", requests)
	}
	total = 2
	if id, err = r.reattach(ctx, prior); id != "" ||
		err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("truncated policy Search must be rejected: %q %v", id, err)
	}
	total = 1
	rows[0]["policy_id"] = "core"
	id, err = r.reattach(ctx, prior)
	var notFound *errs.NotFoundError
	if id != "" || !errors.As(err, &notFound) {
		t.Fatalf("local core policy must be remote-not-found: %q %v", id, err)
	}
}
