package interfaces

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/biptec/opnsense-go/pkg/api"
	"github.com/biptec/opnsense-go/pkg/errs"
	opninterfaces "github.com/biptec/opnsense-go/pkg/interfaces"
	"github.com/biptec/opnsense-go/pkg/opnsense"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &vlanResource{}
var _ resource.ResourceWithConfigure = &vlanResource{}
var _ resource.ResourceWithImportState = &vlanResource{}

func newVlanResource() resource.Resource {
	return &vlanResource{}
}

// vlanResource defines the resource implementation.
type vlanResource struct {
	client opnsense.Client
}

func (r *vlanResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_interfaces_vlan"
}

func (r *vlanResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = vlanResourceSchema()
}

func (r *vlanResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *vlanResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *vlanResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Convert TF schema OPNsense struct
	vlan, err := convertVlanSchemaToStruct(data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to parse vlan, got error: %s", err))
		return
	}

	// Add VLAN to OPNsense interfaces
	id, err := r.client.Interfaces().AddVlan(ctx, vlan)
	if err != nil {
		if id != "" {
			data.Id = types.StringValue(id)

			// Read back so state captures API-normalised values (defaults,
			// sorting, trimming); fall back to plan-only state if the
			// read-back fails so the upstream resource isn't orphaned.
			if readStruct, readErr := r.client.Interfaces().GetVlan(ctx, id); readErr == nil {
				if readModel, convErr := convertVlanStructToSchema(readStruct); convErr == nil {
					readModel.Id = data.Id
					data = readModel
				}
			}

			resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		}

		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to create vlan, got error: %s", err))
		return
	}

	// Tag new resource with ID from OPNsense
	data.Id = types.StringValue(id)

	// Write logs using the tflog package
	tflog.Trace(ctx, "created a resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// exactVlanReplacement finds exactly one replacement for a lost UUID.
// A device with a non-empty, canonical name uniquely identifies a managed
// endpoint VLAN only together with its parent, tag and description. Never
// guess among duplicates or adopt a local-only VLAN on a partial match.
func exactVlanReplacement(prior *vlanResourceModel, candidates []opninterfaces.Vlan) (string, error) {
	device := prior.Device.ValueString()
	parent := prior.Parent.ValueString()
	description := prior.Description.ValueString()
	if prior.Device.IsNull() || prior.Device.IsUnknown() || device == "" ||
		prior.Parent.IsNull() || prior.Parent.IsUnknown() || parent == "" ||
		prior.Tag.IsNull() || prior.Tag.IsUnknown() || !strings.HasPrefix(device, "vlan") ||
		device != fmt.Sprintf("vlan%d", prior.Tag.ValueInt64()) {
		return "", fmt.Errorf("prior VLAN state lacks a canonical device, parent and tag for safe reattachment")
	}
	matches := []string{}
	for _, row := range candidates {
		if row.Device != device || row.Tag != fmt.Sprintf("%d", prior.Tag.ValueInt64()) ||
			row.Parent.String() != parent || row.Description != description {
			continue
		}
		if row.UUID == "" {
			return "", fmt.Errorf("matched VLAN has no UUID")
		}
		matches = append(matches, row.UUID)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected exactly one matching VLAN, found %d", len(matches))
	}
	return matches[0], nil
}

func (r *vlanResource) reattachVlan(ctx context.Context, prior *vlanResourceModel) (string, error) {
	result, err := r.client.Interfaces().SearchVlan(ctx)
	if err != nil {
		return "", fmt.Errorf("search replacement VLAN: %w", err)
	}
	if result == nil || result.Total > len(result.Rows) {
		return "", fmt.Errorf("incomplete VLAN search response; cannot reattach safely")
	}
	return exactVlanReplacement(prior, result.Rows)
}

func (r *vlanResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *vlanResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Get VLAN from OPNsense core API
	vlan, err := r.client.Interfaces().GetVlan(ctx, data.Id.ValueString())
	if err != nil {
		var notFoundError *errs.NotFoundError
		if errors.As(err, &notFoundError) {
			// Preserve normal Terraform recreation semantics for legacy VLANs
			// without the canonical endpoint device identity.
			if data.Device.IsNull() || data.Device.IsUnknown() ||
				data.Tag.IsNull() || data.Tag.IsUnknown() ||
				data.Device.ValueString() != fmt.Sprintf("vlan%d", data.Tag.ValueInt64()) {
				resp.State.RemoveResource(ctx)
				return
			}
			// Explicit, fail-closed reattachment keeps pre-rebuild endpoint state
			// usable without imports or any saved UUID manifest.
			id, reattachErr := r.reattachVlan(ctx, data)
			if reattachErr != nil {
				resp.Diagnostics.AddError("Unable to Reattach VLAN After Router Replacement", reattachErr.Error())
				return
			}
			vlan, err = r.client.Interfaces().GetVlan(ctx, id)
			if err != nil {
				resp.Diagnostics.AddError("Unable to Read Reattached VLAN", err.Error())
				return
			}
			data.Id = types.StringValue(id)
			tflog.Info(ctx, "reattached VLAN with changed OPNsense UUID")
		} else {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read vlan, got error: %s", err))
			return
		}

	}

	// Convert OPNsense struct to TF schema
	vlanModel, err := convertVlanStructToSchema(vlan)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to read vlan, got error: %s", err))
		return
	}

	// ID cannot be added by convert... func, have to add here
	vlanModel.Id = data.Id

	// Handle empty device attribute (i.e. let OPNsense generate a device name)
	// If the VLAN was created with device == "", then we ignore any changes to device.
	// During import, data.Device is null (not empty string), so we skip this and
	// keep the actual device value returned by the API.
	if !data.Device.IsNull() && data.Device.ValueString() == "" {
		vlanModel.Device = types.StringValue("")
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &vlanModel)...)
}

func (r *vlanResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data *vlanResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Convert TF schema OPNsense struct
	vlan, err := convertVlanSchemaToStruct(data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to parse vlan, got error: %s", err))
		return
	}

	// Update VLAN in OPNsense core
	err = r.client.Interfaces().UpdateVlan(ctx, data.Id.ValueString(), vlan)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to update vlan, got error: %s", err))
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *vlanResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *vlanResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.Interfaces().DeleteVlan(ctx, data.Id.ValueString())

	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to delete vlan, got error: %s", err))
		return
	}
}

func (r *vlanResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
