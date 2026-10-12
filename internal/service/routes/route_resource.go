package routes

import (
	"context"
	"errors"
	"fmt"

	"github.com/biptec/opnsense-go/pkg/api"
	"github.com/biptec/opnsense-go/pkg/errs"
	"github.com/biptec/opnsense-go/pkg/opnsense"
	apiroutes "github.com/biptec/opnsense-go/pkg/routes"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &routeResource{}
var _ resource.ResourceWithConfigure = &routeResource{}
var _ resource.ResourceWithImportState = &routeResource{}

func newRouteResource() resource.Resource {
	return &routeResource{}
}

// routeResource defines the resource implementation.
type routeResource struct {
	client opnsense.Client
}

func (r *routeResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_route"
}

func (r *routeResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = routeResourceSchema()
}

func (r *routeResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	apiClient, ok := req.ProviderData.(*api.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *opnsense.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = opnsense.NewClient(apiClient)
}

func (r *routeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *routeResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Convert TF schema OPNsense struct
	route, err := convertRouteSchemaToStruct(data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to parse route, got error: %s", err))
		return
	}

	// Add route to OPNsense
	id, err := r.client.Routes().AddRouteResolved(ctx, route)
	if err != nil {
		if id != "" {
			data.Id = types.StringValue(id)

			// Read back so state captures API-normalised values (defaults,
			// sorting, trimming); fall back to plan-only state if the
			// read-back fails so the upstream resource isn't orphaned.
			if readStruct, readErr := r.client.Routes().GetRoute(ctx, id); readErr == nil {
				if readModel, convErr := convertRouteStructToSchema(readStruct); convErr == nil {
					readModel.Id = data.Id
					data = readModel
				}
			}

			resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		}

		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to create route, got error: %s", err))
		return
	}

	// Tag new resource with ID from OPNsense
	data.Id = types.StringValue(id)

	// Write logs using the tflog package
	tflog.Trace(ctx, "created a resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Routes do not have a stable UUID across clean native HA restores.
// Description and network provide a candidate key; the gateway is verified
// through the typed GET endpoint before the retained state is reattached.
func exactRouteCandidate(prior *routeResourceModel, rows []map[string]any) (string, error) {
	if prior.Description.IsNull() || prior.Description.IsUnknown() || prior.Description.ValueString() == "" ||
		prior.Network.IsNull() || prior.Network.IsUnknown() || prior.Network.ValueString() == "" ||
		prior.Gateway.IsNull() || prior.Gateway.IsUnknown() || prior.Gateway.ValueString() == "" {
		return "", fmt.Errorf("route lacks description, network, or gateway identity")
	}
	matches := []string{}
	for _, row := range rows {
		description, ok := row["descr"].(string)
		if !ok || description != prior.Description.ValueString() {
			continue
		}
		network, ok := row["network"].(string)
		if !ok || network != prior.Network.ValueString() {
			continue
		}
		uuid, ok := row["uuid"].(string)
		if !ok || uuid == "" {
			return "", fmt.Errorf("matching route lacks UUID")
		}
		matches = append(matches, uuid)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected exactly one matching route, found %d", len(matches))
	}
	return matches[0], nil
}

func (r *routeResource) reattachRoute(ctx context.Context, prior *routeResourceModel) (string, *apiroutes.Route, error) {
	result, err := api.Search[map[string]any](
		r.client.Routes().Client(), ctx,
		api.Endpoint{Path: "/routes/routes/searchroute", Method: "POST"},
	)
	if err != nil {
		return "", nil, fmt.Errorf("search replacement routes: %w", err)
	}
	if result == nil || result.Total > len(result.Rows) {
		return "", nil, fmt.Errorf("incomplete route search response; cannot safely reattach")
	}
	id, err := exactRouteCandidate(prior, result.Rows)
	if err != nil {
		return "", nil, err
	}
	remote, err := r.client.Routes().GetRoute(ctx, id)
	if err != nil {
		return "", nil, fmt.Errorf("read matching route: %w", err)
	}
	if remote.Description != prior.Description.ValueString() ||
		remote.Network != prior.Network.ValueString() ||
		remote.Gateway.String() != prior.Gateway.ValueString() {
		return "", nil, fmt.Errorf("candidate route has different network, gateway, or description")
	}
	return id, remote, nil
}

func (r *routeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *routeResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Get route from OPNsense core API
	route, err := r.client.Routes().GetRoute(ctx, data.Id.ValueString())
	if err != nil {
		var notFoundError *errs.NotFoundError
		if errors.As(err, &notFoundError) {
			// Missing unnamed routes retain Terraform's conventional behavior.
			// Named endpoint routes fail closed if identity is ambiguous.
			if data.Description.IsNull() || data.Description.IsUnknown() ||
				data.Description.ValueString() == "" {
				resp.State.RemoveResource(ctx)
				return
			}
			id, found, findErr := r.reattachRoute(ctx, data)
			if findErr != nil {
				resp.Diagnostics.AddError("Unable to Reattach Route After Router Replacement", findErr.Error())
				return
			}
			data.Id = types.StringValue(id)
			route = found
		} else {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read route, got error: %s", err))
			return
		}
	}

	// Convert OPNsense struct to TF schema
	routeModel, err := convertRouteStructToSchema(route)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to read route, got error: %s", err))
		return
	}

	// ID cannot be added by convert... func, have to add here
	routeModel.Id = data.Id

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &routeModel)...)
}

func (r *routeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data *routeResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Convert TF schema OPNsense struct
	route, err := convertRouteSchemaToStruct(data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to parse route, got error: %s", err))
		return
	}

	// Update route in OPNsense core
	err = r.client.Routes().UpdateRouteResolved(ctx, data.Id.ValueString(), route)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to update route, got error: %s", err))
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *routeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *routeResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.Routes().DeleteRoute(ctx, data.Id.ValueString())

	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to delete route, got error: %s", err))
		return
	}
}

func (r *routeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
