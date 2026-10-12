package routing

import (
	"context"
	"errors"
	"fmt"

	"github.com/biptec/opnsense-go/pkg/api"
	"github.com/biptec/opnsense-go/pkg/errs"
	"github.com/biptec/opnsense-go/pkg/opnsense"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type routingResourceClient struct {
	client opnsense.Client
}

func (c *routingResourceClient) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	apiClient, ok := req.ProviderData.(*api.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected *api.Client, got %T.", req.ProviderData))
		return
	}
	c.client = opnsense.NewClient(apiClient)
}

type routingDataSourceClient struct {
	client opnsense.Client
}

func (c *routingDataSourceClient) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	apiClient, ok := req.ProviderData.(*api.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type", fmt.Sprintf("Expected *api.Client, got %T.", req.ProviderData))
		return
	}
	c.client = opnsense.NewClient(apiClient)
}

type routingCRUDOperations[Model any, APIModel any] struct {
	Name    string
	Convert func(*Model) (*APIModel, error)
	Expand  func(*APIModel) (*Model, error)
	Add     func(context.Context, *APIModel) (string, error)
	Get     func(context.Context, string) (*APIModel, error)
	// Optional safe UUID reattachment for resources recreated by native HA.
	// A missing or ambiguous candidate must be returned as an error, never
	// silently removed from an endpoint Terraform state.
	Reattach func(context.Context, *Model) (string, *APIModel, error)
	Update   func(context.Context, string, *APIModel) error
	Delete   func(context.Context, string) error
	GetID    func(*Model) string
	SetID    func(*Model, string)
}

func createRoutingResource[Model any, APIModel any](ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse, ops routingCRUDOperations[Model, APIModel]) {
	var data Model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	apiModel, err := ops.Convert(&data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid "+ops.Name, err.Error())
		return
	}
	id, err := ops.Add(ctx, apiModel)
	if err != nil {
		if id != "" {
			ops.SetID(&data, id)
			resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		}
		resp.Diagnostics.AddError("Unable to Create "+ops.Name, err.Error())
		return
	}
	remote, err := ops.Get(ctx, id)
	if err != nil {
		ops.SetID(&data, id)
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		resp.Diagnostics.AddError(ops.Name+" Created but Read Failed", err.Error())
		return
	}
	state, err := ops.Expand(remote)
	if err != nil {
		ops.SetID(&data, id)
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		resp.Diagnostics.AddError("Unable to Decode "+ops.Name, err.Error())
		return
	}
	ops.SetID(state, id)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	tflog.Trace(ctx, "created routing resource", map[string]any{"type": ops.Name, "id": id})
}

func readRoutingResource[Model any, APIModel any](ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse, ops routingCRUDOperations[Model, APIModel]) {
	var data Model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := ops.GetID(&data)
	remote, err := ops.Get(ctx, id)
	if err != nil {
		var notFound *errs.NotFoundError
		if errors.As(err, &notFound) {
			if ops.Reattach == nil {
				resp.State.RemoveResource(ctx)
				return
			}
			id, remote, err = ops.Reattach(ctx, &data)
			if err != nil {
				resp.Diagnostics.AddError("Unable to Reattach "+ops.Name+" After Router Replacement", err.Error())
				return
			}
		} else {
			resp.Diagnostics.AddError("Unable to Read "+ops.Name, err.Error())
			return
		}
	}
	state, err := ops.Expand(remote)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Decode "+ops.Name, err.Error())
		return
	}
	ops.SetID(state, id)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func updateRoutingResource[Model any, APIModel any](ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse, ops routingCRUDOperations[Model, APIModel]) {
	var data Model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	apiModel, err := ops.Convert(&data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid "+ops.Name, err.Error())
		return
	}
	id := ops.GetID(&data)
	if err := ops.Update(ctx, id, apiModel); err != nil {
		resp.Diagnostics.AddError("Unable to Update "+ops.Name, err.Error())
		return
	}
	remote, err := ops.Get(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError(ops.Name+" Updated but Read Failed", err.Error())
		return
	}
	state, err := ops.Expand(remote)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Decode "+ops.Name, err.Error())
		return
	}
	ops.SetID(state, id)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func deleteRoutingResource[Model any, APIModel any](ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse, ops routingCRUDOperations[Model, APIModel]) {
	var data Model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := ops.Delete(ctx, ops.GetID(&data)); err != nil {
		var notFound *errs.NotFoundError
		if errors.As(err, &notFound) {
			return
		}
		resp.Diagnostics.AddError("Unable to Delete "+ops.Name, err.Error())
	}
}

func readRoutingDataSource[Model any, APIModel any](ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse, name string, get func(context.Context, string) (*APIModel, error), expand func(*APIModel) (*Model, error), getID func(*Model) string, setID func(*Model, string)) {
	var data Model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := getID(&data)
	remote, err := get(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Read "+name, err.Error())
		return
	}
	state, err := expand(remote)
	if err != nil {
		resp.Diagnostics.AddError("Unable to Decode "+name, err.Error())
		return
	}
	setID(state, id)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}
