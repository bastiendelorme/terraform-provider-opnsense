package routing

import (
	"errors"
	"strings"
	"testing"

	"github.com/biptec/opnsense-go/pkg/api"
	"github.com/biptec/opnsense-go/pkg/errs"
	apirouting "github.com/biptec/opnsense-go/pkg/routing"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestExactGatewayReplacement(t *testing.T) {
	prior := &gatewayResourceModel{
		Name:        types.StringValue("ep_issue103-v4"),
		Interface:   types.StringValue("ep_issue103"),
		IPProtocol:  types.StringValue("inet"),
		Gateway:     types.StringValue("10.250.99.2"),
		Description: types.StringValue("issue103 endpoint IPv4 next hop"),
	}
	candidate := apirouting.Gateway{
		UUID:        "new-gateway-uuid",
		Name:        "ep_issue103-v4",
		Interface:   api.SelectedMap("ep_issue103"),
		IPProtocol:  api.SelectedMap("inet"),
		Gateway:     "10.250.99.2",
		Description: "issue103 endpoint IPv4 next hop",
	}
	got, err := exactGatewayReplacement(prior, []apirouting.Gateway{candidate})
	if got != candidate.UUID || err != nil {
		t.Fatalf("expected exact gateway match, got %q %v", got, err)
	}
	cases := []struct {
		name     string
		prior    *gatewayResourceModel
		rows     []apirouting.Gateway
		want     string
		notFound bool
	}{
		{"zero matches", prior, nil, "", true},
		{"ambiguous", prior, []apirouting.Gateway{candidate, candidate}, "found 2", false},
		{"wrong IP protocol", prior, []apirouting.Gateway{func() apirouting.Gateway { g := candidate; g.IPProtocol = api.SelectedMap("inet6"); return g }()}, "", true},
		{"wrong interface", prior, []apirouting.Gateway{func() apirouting.Gateway { g := candidate; g.Interface = api.SelectedMap("wan"); return g }()}, "", true},
		{"wrong hop", prior, []apirouting.Gateway{func() apirouting.Gateway { g := candidate; g.Gateway = "10.250.99.3"; return g }()}, "", true},
		{"wrong description", prior, []apirouting.Gateway{func() apirouting.Gateway { g := candidate; g.Description = "foreign"; return g }()}, "", true},
		{"no UUID", prior, []apirouting.Gateway{func() apirouting.Gateway { g := candidate; g.UUID = ""; return g }()}, "no UUID", false},
		{"no stable name", &gatewayResourceModel{Name: types.StringNull(), Interface: prior.Interface, IPProtocol: prior.IPProtocol, Gateway: prior.Gateway}, []apirouting.Gateway{candidate}, "lacks unique", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, e := exactGatewayReplacement(tc.prior, tc.rows)
			if tc.notFound {
				var notFound *errs.NotFoundError
				if !errors.As(e, &notFound) {
					t.Fatalf("expected remote-not-found, got %v", e)
				}
				return
			}
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, e)
			}
		})
	}
}
