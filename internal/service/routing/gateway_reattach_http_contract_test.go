package routing

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

// Native gateways may get new UUIDs on the replacement Etna; both the
// typed Search fields and the subsequent typed GET must match old identity.
func TestReattachGatewayHTTPContract(t *testing.T) {
	ctx := context.Background()
	prior := &gatewayResourceModel{
		Name:        types.StringValue("ep_issue103-v4"),
		Interface:   types.StringValue("ep_issue103"),
		IPProtocol:  types.StringValue("inet"),
		Gateway:     types.StringValue("10.250.99.2"),
		Description: types.StringValue("issue103 endpoint next hop"),
	}
	total := 1
	getGateway := "10.250.99.2"
	searchCount := 0
	getCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		match := map[string]any{
			"name": "ep_issue103-v4", "interface": map[string]any{
				"ep_issue103": map[string]any{"selected": 1, "value": "ep_issue103"},
				"wan":         map[string]any{"selected": 0, "value": "wan"},
			},
			"ipprotocol": "inet", "gateway": "10.250.99.2",
			"descr": "issue103 endpoint next hop",
		}
		switch req.URL.Path {
		case "/api/routing/settings/searchGateway":
			searchCount++
			if req.Method != http.MethodPost {
				t.Errorf("gateway search must be POST: %s", req.Method)
			}
			row := make(map[string]any, len(match)+1)
			for k, v := range match {
				row[k] = v
			}
			row["uuid"] = "new-gateway-uuid"
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total": total, "rowCount": 1, "current": 1,
				"rows": []map[string]any{row},
			})
		case "/api/routing/settings/getGateway/new-gateway-uuid":
			getCount++
			if req.Method != http.MethodGet {
				t.Errorf("gateway GET must be GET: %s", req.Method)
			}
			match["gateway"] = getGateway
			_ = json.NewEncoder(w).Encode(map[string]any{"gateway_item": match})
		default:
			t.Errorf("unexpected gateway API request %s %s", req.Method, req.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	r := &gatewayResource{routingResourceClient{
		client: opnsense.NewClient(api.NewClient(api.Options{Uri: server.URL})),
	}}
	id, gateway, err := r.reattach(ctx, prior)
	if err != nil || gateway == nil || id != "new-gateway-uuid" ||
		gateway.Gateway != "10.250.99.2" || searchCount != 1 || getCount != 1 {
		t.Fatalf("gateway reattachment id=%q record=%+v error=%v search=%d get=%d",
			id, gateway, err, searchCount, getCount)
	}
	total = 2
	if id, gateway, err = r.reattach(ctx, prior); id != "" || gateway != nil ||
		err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("truncated Search must fail closed: id=%q gateway=%+v error=%v", id, gateway, err)
	}
	total = 1
	getGateway = "10.250.99.3"
	if id, gateway, err = r.reattach(ctx, prior); id != "" || gateway != nil ||
		err == nil || !strings.Contains(err.Error(), "changed identity") {
		t.Fatalf("GET with foreign next-hop must fail closed: id=%q gateway=%+v error=%v", id, gateway, err)
	}
}
