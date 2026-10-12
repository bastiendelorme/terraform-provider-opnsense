package interfaces

import (
	"context"
	"errors"
	"fmt"

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
var _ resource.Resource = &vipResource{}
var _ resource.ResourceWithConfigure = &vipResource{}
var _ resource.ResourceWithImportState = &vipResource{}
var _ resource.ResourceWithUpgradeState = &vipResource{}

func newVipResource() resource.Resource {
	return &vipResource{}
}

// vipResource defines the resource implementation.
type vipResource struct {
	client opnsense.Client
}

type vipResourceModelV0 struct {
	Mode              types.String `tfsdk:"mode"`
	Interface         types.String `tfsdk:"interface"`
	Network           types.String `tfsdk:"network"`
	Gateway           types.String `tfsdk:"gateway"`
	NoExpand          types.Bool   `tfsdk:"no_expand"`
	NoBind            types.Bool   `tfsdk:"no_bind"`
	Password          types.String `tfsdk:"password"`
	VHID              types.Int64  `tfsdk:"vhid"`
	AdvertisementBase types.Int64  `tfsdk:"advertisement_base"`
	AdvertisementSkew types.Int64  `tfsdk:"advertisement_skew"`
	PeerIPv4          types.String `tfsdk:"peer_ipv4"`
	PeerIPv6          types.String `tfsdk:"peer_ipv6"`
	NoSync            types.Bool   `tfsdk:"no_sync"`
	Address           types.String `tfsdk:"address"`
	VHIDText          types.String `tfsdk:"vhid_text"`
	Description       types.String `tfsdk:"description"`
	Id                types.String `tfsdk:"id"`
}

func (r *vipResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_interfaces_vip"
}

func (r *vipResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = vipResourceSchema()
}

func (r *vipResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *vipResource) readState(ctx context.Context, id string, prior *vipResourceModel) (*vipResourceModel, error) {
	vip, err := r.client.Interfaces().GetVip(ctx, id)
	if err != nil {
		return nil, err
	}
	state, err := convertVipStructToSchema(vip)
	if err != nil {
		return nil, err
	}
	state.Id = types.StringValue(id)
	if prior != nil && !prior.PasswordVersion.IsNull() && !prior.PasswordVersion.IsUnknown() {
		state.PasswordVersion = prior.PasswordVersion
	} else {
		state.PasswordVersion = types.Int64Value(0)
	}
	return state, nil
}

func vipFallbackState(data *vipResourceModel, id string) *vipResourceModel {
	data.Id = types.StringValue(id)
	if data.Address.IsUnknown() {
		data.Address = types.StringNull()
	}
	if data.VHIDText.IsUnknown() {
		data.VHIDText = types.StringNull()
	}
	data.Password = types.StringNull()
	if data.PasswordVersion.IsNull() || data.PasswordVersion.IsUnknown() {
		data.PasswordVersion = types.Int64Value(0)
	}
	if data.PasswordConfigured.IsUnknown() {
		data.PasswordConfigured = types.BoolValue(data.Mode.ValueString() == "carp")
	}
	return data
}

func (r *vipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *vipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var password types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("password"), &password)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vip, err := convertVipSchemaToStruct(data, password)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to parse vip, got error: %s", err))
		return
	}

	id, addErr := r.client.Interfaces().AddVip(ctx, vip)
	if id != "" {
		state, readErr := r.readState(ctx, id, data)
		if readErr != nil {
			state = vipFallbackState(data, id)
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
		if addErr == nil && readErr != nil {
			resp.Diagnostics.AddError("VIP Created but Read Failed", readErr.Error())
			return
		}
	}
	if addErr != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create vip, got error: %s", addErr))
		return
	}
	if id == "" {
		resp.Diagnostics.AddError("Client Error", "Unable to create vip: API returned an empty identifier")
		return
	}
	tflog.Trace(ctx, "created a resource", map[string]any{"id": id})
}

// A receiver-created VIP may have a different UUID after a clean router
// rebuild. Reattach only by an exact, unique, stable semantic identity. CARP
// advskew and write-only password are deliberately NOT part of that identity:
// they are locally configured values and must not be copied from a peer.
func exactVipReplacement(prior *vipResourceModel, rows []opninterfaces.Vip) (string, error) {
	mode := prior.Mode.ValueString()
	iface := prior.Interface.ValueString()
	network := prior.Network.ValueString()
	description := prior.Description.ValueString()
	if prior.Mode.IsNull() || prior.Mode.IsUnknown() || prior.Interface.IsNull() || prior.Interface.IsUnknown() ||
		prior.Network.IsNull() || prior.Network.IsUnknown() || mode == "" || iface == "" || network == "" ||
		prior.Description.IsNull() || prior.Description.IsUnknown() || description == "" {
		return "", fmt.Errorf("old VIP state lacks an exact semantic identity")
	}
	vhid := ""
	if !prior.VHID.IsNull() && !prior.VHID.IsUnknown() {
		vhid = fmt.Sprintf("%d", prior.VHID.ValueInt64())
	}
	matches := []string{}
	for _, row := range rows {
		if row.Mode.String() != mode || row.Interface.String() != iface ||
			row.Network != network || row.Description != description || row.VHID != vhid {
			continue
		}
		if row.UUID == "" {
			return "", fmt.Errorf("matched VIP has no UUID")
		}
		matches = append(matches, row.UUID)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected exactly one matching VIP, found %d", len(matches))
	}
	return matches[0], nil
}

func (r *vipResource) reattachVip(ctx context.Context, prior *vipResourceModel) (string, error) {
	result, err := r.client.Interfaces().SearchVip(ctx)
	if err != nil {
		return "", fmt.Errorf("search replacement VIP: %w", err)
	}
	if result == nil || result.Total > len(result.Rows) {
		return "", fmt.Errorf("incomplete VIP search response; cannot safely reattach")
	}
	return exactVipReplacement(prior, result.Rows)
}

func (r *vipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *vipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	state, err := r.readState(ctx, data.Id.ValueString(), data)
	if err != nil {
		var notFoundError *errs.NotFoundError
		if errors.As(err, &notFoundError) {
			// Only explicitly described endpoint-like VIPs have a stable identity
			// strong enough for automatic reattachment. Preserve legacy behavior
			// for unnamed/non-endpoint VIPs.
			if data.Description.IsNull() || data.Description.IsUnknown() || data.Description.ValueString() == "" {
				resp.State.RemoveResource(ctx)
				return
			}
			id, reattachErr := r.reattachVip(ctx, data)
			if reattachErr != nil {
				resp.Diagnostics.AddError("Unable to Reattach VIP After Router Replacement", reattachErr.Error())
				return
			}
			state, err = r.readState(ctx, id, data)
			if err != nil {
				resp.Diagnostics.AddError("Unable to Read Reattached VIP", err.Error())
				return
			}
			tflog.Info(ctx, "reattached VIP with changed OPNsense UUID")
		} else {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read vip, got error: %s", err))
			return
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *vipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data, old vipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
	var password types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("password"), &password)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if data.Mode.ValueString() == "carp" && !data.PasswordVersion.IsNull() && !data.PasswordVersion.IsUnknown() && !old.PasswordVersion.IsNull() && !old.PasswordVersion.IsUnknown() && data.PasswordVersion.ValueInt64() != old.PasswordVersion.ValueInt64() {
		if password.IsNull() || password.IsUnknown() || password.ValueString() == "" {
			resp.Diagnostics.AddError("Missing Rotated CARP Password", "password_version changed but no write-only password was supplied. Provide the new password together with the incremented password_version.")
			return
		}
	}
	id := data.Id.ValueString()
	remote, err := r.client.Interfaces().GetVip(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read vip before update, got error: %s", err))
		return
	}
	effectivePassword := password
	if data.Mode.ValueString() == "carp" && (password.IsNull() || password.IsUnknown() || password.ValueString() == "") {
		effectivePassword = types.StringValue(remote.Password)
	}
	vip, err := convertVipSchemaToStruct(&data, effectivePassword)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to parse vip, got error: %s", err))
		return
	}
	if err := r.client.Interfaces().UpdateVip(ctx, id, vip); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to update vip, got error: %s", err))
		return
	}
	state, err := r.readState(ctx, id, &data)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, vipFallbackState(&data, id))...)
		resp.Diagnostics.AddError("VIP Updated but Read Failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *vipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *vipResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.Interfaces().DeleteVip(ctx, data.Id.ValueString())

	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to delete vip, got error: %s", err))
		return
	}
}

func (r *vipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("password_version"), int64(0))...)
}

func (r *vipResource) UpgradeState(context.Context) map[int64]resource.StateUpgrader {
	prior := vipResourceSchemaV0()
	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema: &prior,
			StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
				var old vipResourceModelV0
				resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
				if resp.Diagnostics.HasError() {
					return
				}
				configured := !old.Password.IsNull() && !old.Password.IsUnknown() && old.Password.ValueString() != ""
				resp.Diagnostics.Append(resp.State.Set(ctx, &vipResourceModel{
					Mode: old.Mode, Interface: old.Interface, Network: old.Network, Gateway: old.Gateway,
					NoExpand: old.NoExpand, NoBind: old.NoBind, Password: types.StringNull(),
					PasswordVersion: types.Int64Value(0), PasswordConfigured: types.BoolValue(configured),
					VHID: old.VHID, AdvertisementBase: old.AdvertisementBase, AdvertisementSkew: old.AdvertisementSkew,
					PeerIPv4: old.PeerIPv4, PeerIPv6: old.PeerIPv6, NoSync: old.NoSync, Address: old.Address,
					VHIDText: old.VHIDText, Description: old.Description, Id: old.Id,
				})...)
			},
		},
	}
}
