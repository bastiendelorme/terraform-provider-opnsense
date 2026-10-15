package system

import (
	"context"
	"errors"
	"fmt"

	"github.com/biptec/opnsense-go/pkg/api"
	apiextensions "github.com/biptec/opnsense-go/pkg/api_extensions"
	"github.com/biptec/opnsense-go/pkg/errs"
	"github.com/biptec/opnsense-go/pkg/opnsense"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &interfacePolicyAssignmentResource{}
var _ resource.ResourceWithConfigure = &interfacePolicyAssignmentResource{}
var _ resource.ResourceWithImportState = &interfacePolicyAssignmentResource{}

type interfacePolicyAssignmentResource struct{ client opnsense.Client }

func newInterfacePolicyAssignmentResource() resource.Resource {
	return &interfacePolicyAssignmentResource{}
}

func (r *interfacePolicyAssignmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_interface_policy_assignment"
}

func (r *interfacePolicyAssignmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = interfacePolicyAssignmentResourceSchema()
}

func (r *interfacePolicyAssignmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

func interfacePolicyAssignmentToAPI(data *interfacePolicyAssignmentResourceModel) *apiextensions.InterfacePolicyAssignment {
	return &apiextensions.InterfacePolicyAssignment{
		Interface: api.SelectedMap(data.Interface.ValueString()),
		PolicyID:  api.SelectedMap(data.PolicyID.ValueString()),
	}
}

func interfacePolicyAssignmentFromAPI(remote *apiextensions.InterfacePolicyAssignment, id string) *interfacePolicyAssignmentResourceModel {
	return &interfacePolicyAssignmentResourceModel{
		Interface: types.StringValue(remote.Interface.String()),
		PolicyID:  types.StringValue(remote.PolicyID.String()),
		ID:        types.StringValue(id),
	}
}

func (r *interfacePolicyAssignmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data interfacePolicyAssignmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.ApiExtensions().AddInterfacePolicyAssignment(ctx, interfacePolicyAssignmentToAPI(&data))
	if err != nil {
		resp.Diagnostics.AddError("Unable to Create Interface Policy Assignment", err.Error())
		return
	}
	remote, err := r.client.ApiExtensions().GetInterfacePolicyAssignment(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Interface Policy Assignment Created but Read Failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, interfacePolicyAssignmentFromAPI(remote, id))...)
}

// New OPNsense routers generate local MVC UUIDs. An endpoint policy
// relation is reattached only on exact, unique interface + policy identity.
func exactPolicyAssignmentReplacement(
	prior *interfacePolicyAssignmentResourceModel,
	rows []map[string]string,
) (string, error) {
	if prior.Interface.IsNull() || prior.Interface.IsUnknown() || prior.Interface.ValueString() == "" ||
		prior.PolicyID.IsNull() || prior.PolicyID.IsUnknown() || prior.PolicyID.ValueString() == "" {
		return "", fmt.Errorf("prior policy assignment lacks a stable interface and policy identifier")
	}
	matches := []string{}
	for _, row := range rows {
		if row["interface"] == prior.Interface.ValueString() && row["policy_id"] == prior.PolicyID.ValueString() {
			if row["uuid"] == "" {
				return "", fmt.Errorf("matching policy assignment has no UUID")
			}
			matches = append(matches, row["uuid"])
		}
	}
	if len(matches) == 0 {
		return "", errs.NewNotFoundError()
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected exactly one matching policy assignment, found %d", len(matches))
	}
	return matches[0], nil
}

func (r *interfacePolicyAssignmentResource) reattach(ctx context.Context, prior *interfacePolicyAssignmentResourceModel) (string, error) {
	result, err := api.Search[map[string]string](
		r.client.ApiExtensions().Client(), ctx, apiextensions.InterfacePolicyAssignmentOpts.Search,
	)
	if err != nil {
		return "", fmt.Errorf("search policy assignments: %w", err)
	}
	if result == nil || result.Total > len(result.Rows) {
		return "", fmt.Errorf("incomplete assignment search response; cannot reattach")
	}
	return exactPolicyAssignmentReplacement(prior, result.Rows)
}

func (r *interfacePolicyAssignmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data interfacePolicyAssignmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	remote, err := r.client.ApiExtensions().GetInterfacePolicyAssignment(ctx, data.ID.ValueString())
	if err != nil {
		var notFound *errs.NotFoundError
		if errors.As(err, &notFound) {
			id, reattachErr := r.reattach(ctx, &data)
			if reattachErr != nil {
				var replacementNotFound *errs.NotFoundError
				if errors.As(reattachErr, &replacementNotFound) {
					resp.State.RemoveResource(ctx)
					return
				}
				resp.Diagnostics.AddError("Unable to Reattach Interface Policy Assignment", reattachErr.Error())
				return
			}
			remote, err = r.client.ApiExtensions().GetInterfacePolicyAssignment(ctx, id)
			if err != nil {
				resp.Diagnostics.AddError("Unable to Read Reattached Policy Assignment", err.Error())
				return
			}
			data.ID = types.StringValue(id)
		} else {
			resp.Diagnostics.AddError("Unable to Read Interface Policy Assignment", err.Error())
			return
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, interfacePolicyAssignmentFromAPI(remote, data.ID.ValueString()))...)
}

func (r *interfacePolicyAssignmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data interfacePolicyAssignmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.ApiExtensions().UpdateInterfacePolicyAssignment(ctx, data.ID.ValueString(), interfacePolicyAssignmentToAPI(&data)); err != nil {
		resp.Diagnostics.AddError("Unable to Update Interface Policy Assignment", err.Error())
		return
	}
	remote, err := r.client.ApiExtensions().GetInterfacePolicyAssignment(ctx, data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Interface Policy Assignment Updated but Read Failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, interfacePolicyAssignmentFromAPI(remote, data.ID.ValueString()))...)
}

func (r *interfacePolicyAssignmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data interfacePolicyAssignmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.ApiExtensions().DeleteInterfacePolicyAssignment(ctx, data.ID.ValueString()); err != nil {
		var notFound *errs.NotFoundError
		if !errors.As(err, &notFound) {
			resp.Diagnostics.AddError("Unable to Delete Interface Policy Assignment", err.Error())
		}
	}
}

func (r *interfacePolicyAssignmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
