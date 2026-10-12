package routes

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

// Reattachment of static routes must validate the gateway returned by
// GET, not just assume the search row belongs to the retained endpoint.
func TestReattachRouteHTTPContract(t *testing.T) {
	ctx := context.Background()
	description := "issue103: 203.0.113.0/24 via endpoint"
	nextHop := "ep_issue103-v4"
	prior := &routeResourceModel{
		Description: types.StringValue(description),
		Network:     types.StringValue("203.0.113.0/24"),
		Gateway:     types.StringValue(nextHop),
		Id:          types.StringValue("old-router-route-uuid"),
	}
	seenSearch := 0
	seenGet := 0
	responseTotal := 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/api/routes/routes/searchroute":
			seenSearch++
			if req.Method != http.MethodPost {
				t.Errorf("route Search must POST, got %s", req.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total": responseTotal, "rowCount": 1, "current": 1,
				"rows": []map[string]string{{
					"uuid": "new-router-route-uuid", "descr": description,
					"network": "203.0.113.0/24",
				}},
			})
		case "/api/routes/routes/getroute/new-router-route-uuid":
			seenGet++
			if req.Method != http.MethodGet {
				t.Errorf("route GET must use GET, got %s", req.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"route": map[string]any{
					"descr": description, "network": "203.0.113.0/24",
					"gateway": map[string]any{
						nextHop: map[string]any{"selected": 1, "value": nextHop},
					},
				},
			})
		default:
			t.Errorf("unexpected API request: %s %s", req.Method, req.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer server.Close()

	r := &routeResource{client: opnsense.NewClient(api.NewClient(api.Options{Uri: server.URL}))}
	id, remote, err := r.reattachRoute(ctx, prior)
	if err != nil || remote == nil || id != "new-router-route-uuid" ||
		remote.Gateway.String() != nextHop || seenSearch != 1 || seenGet != 1 {
		t.Fatalf("route reattachment: id=%q remote=%+v err=%v search=%d get=%d",
			id, remote, err, seenSearch, seenGet)
	}
	responseTotal = 2
	if id, remote, err = r.reattachRoute(ctx, prior); id != "" || remote != nil ||
		err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("truncated route search must refuse: id=%q remote=%+v err=%v", id, remote, err)
	}
}
