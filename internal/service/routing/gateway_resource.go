package routing

import (
	"context"
	"fmt"

	apirouting "github.com/biptec/opnsense-go/pkg/routing"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &gatewayResource{}
var _ resource.ResourceWithConfigure = &gatewayResource{}
var _ resource.ResourceWithImportState = &gatewayResource{}

type gatewayResource struct{ routingResourceClient }

func newGatewayResource() resource.Resource { return &gatewayResource{} }
func (r *gatewayResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_routing_gateway"
}
func (r *gatewayResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = gatewayResourceSchema()
}

// The gateway's unique configured name and endpoint routing details survive
// a clean native HA restore, while its MVC UUID may not.
func exactGatewayReplacement(prior *gatewayResourceModel, rows []apirouting.Gateway) (string, error) {
	if prior.Name.IsNull() || prior.Name.IsUnknown() || prior.Name.ValueString() == "" ||
		prior.Interface.IsNull() || prior.Interface.IsUnknown() || prior.Interface.ValueString() == "" ||
		prior.IPProtocol.IsNull() || prior.IPProtocol.IsUnknown() || prior.IPProtocol.ValueString() == "" ||
		prior.Gateway.IsNull() || prior.Gateway.IsUnknown() || prior.Gateway.ValueString() == "" {
		return "", fmt.Errorf("gateway state lacks unique name, interface, IP protocol and next hop")
	}
	matched := []string{}
	for _, g := range rows {
		if g.Name != prior.Name.ValueString() ||
			g.Interface.String() != prior.Interface.ValueString() ||
			g.IPProtocol.String() != prior.IPProtocol.ValueString() ||
			g.Gateway != prior.Gateway.ValueString() ||
			(!prior.Description.IsNull() && !prior.Description.IsUnknown() &&
				g.Description != prior.Description.ValueString()) {
			continue
		}
		if g.UUID == "" {
			return "", fmt.Errorf("matching gateway has no UUID")
		}
		matched = append(matched, g.UUID)
	}
	if len(matched) != 1 {
		return "", fmt.Errorf("expected exactly one matching gateway, found %d", len(matched))
	}
	return matched[0], nil
}

func (r *gatewayResource) reattach(ctx context.Context, prior *gatewayResourceModel) (string, *apirouting.Gateway, error) {
	response, err := r.client.Routing().SearchGateway(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("search gateways: %w", err)
	}
	if response == nil || response.Total > len(response.Rows) {
		return "", nil, fmt.Errorf("incomplete gateway search; cannot reattach safely")
	}
	id, err := exactGatewayReplacement(prior, response.Rows)
	if err != nil {
		return "", nil, err
	}
	candidate, err := r.client.Routing().GetGateway(ctx, id)
	if err != nil {
		return "", nil, fmt.Errorf("read matched gateway: %w", err)
	}
	if candidate.Name != prior.Name.ValueString() ||
		candidate.Interface.String() != prior.Interface.ValueString() ||
		candidate.IPProtocol.String() != prior.IPProtocol.ValueString() ||
		candidate.Gateway != prior.Gateway.ValueString() {
		return "", nil, fmt.Errorf("matching gateway changed identity")
	}
	return id, candidate, nil
}

func (r *gatewayResource) operations() routingCRUDOperations[gatewayResourceModel, apirouting.Gateway] {
	controller := r.client.Routing()
	return routingCRUDOperations[gatewayResourceModel, apirouting.Gateway]{
		Name: "Routing Gateway", Convert: convertGatewaySchemaToStruct, Expand: convertGatewayStructToSchema,
		Add: controller.AddGateway, Get: controller.GetGateway, Update: controller.UpdateGateway, Delete: controller.DeleteGateway,
		Reattach: r.reattach,
		GetID:    func(d *gatewayResourceModel) string { return d.Id.ValueString() },
		SetID:    func(d *gatewayResourceModel, id string) { d.Id = types.StringValue(id) },
	}
}
func (r *gatewayResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	createRoutingResource(ctx, req, resp, r.operations())
}
func (r *gatewayResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	readRoutingResource(ctx, req, resp, r.operations())
}
func (r *gatewayResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	updateRoutingResource(ctx, req, resp, r.operations())
}
func (r *gatewayResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	deleteRoutingResource(ctx, req, resp, r.operations())
}
func (r *gatewayResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
