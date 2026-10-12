package firewall

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/biptec/opnsense-go/pkg/api"
	"github.com/biptec/opnsense-go/pkg/errs"
	apifirewall "github.com/biptec/opnsense-go/pkg/firewall"
	"github.com/biptec/opnsense-go/pkg/opnsense"
	"github.com/biptec/opnsense-go/pkg/routing"
	"github.com/biptec/terraform-provider-opnsense/internal/validators"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &filterResource{}
var _ resource.ResourceWithConfigure = &filterResource{}
var _ resource.ResourceWithImportState = &filterResource{}
var _ resource.ResourceWithConfigValidators = &filterResource{}
var _ resource.ResourceWithUpgradeState = &filterResource{}

func newFilterResource() resource.Resource {
	return &filterResource{}
}

// filterResource defines the resource implementation.
type filterResource struct {
	client opnsense.Client
}

func (r *filterResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_filter"
}

func (r *filterResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = filterResourceSchema()
}

func (r *filterResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		// Ensure adaptive end is greater than or equal to adaptive start
		validators.NumericGreaterThanOrEqual(
			path.MatchRoot("stateful_firewall").AtName("adaptive_timeouts").AtName("end"),
			path.MatchRoot("stateful_firewall").AtName("adaptive_timeouts").AtName("start"),
		),
		// Ensure adaptive end is greater than or equal to max states
		validators.NumericGreaterThanOrEqual(
			path.MatchRoot("stateful_firewall").AtName("adaptive_timeouts").AtName("end"),
			path.MatchRoot("stateful_firewall").AtName("max").AtName("states"),
		),
		// Ensure max.states is only set for TCP protocols
		validators.RequiresStringEqualsOneOf(
			path.MatchRoot("stateful_firewall").AtName("max").AtName("states"),
			path.MatchRoot("filter").AtName("protocol"),
			[]string{"TCP", "TCP/UDP"},
		),
		// Ensure icmp_type is only set for ICMP protocol
		validators.RequiresStringEqualsOneOf(
			path.MatchRoot("filter").AtName("icmp_type"),
			path.MatchRoot("filter").AtName("protocol"),
			[]string{"ICMP"},
		),
	}
}

func (r *filterResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

const (
	gatewayReadinessRetryInterval = time.Second
	gatewayReadinessRetryTimeout  = 25 * time.Second
)

func (r *filterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *filterResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Convert TF schema OPNsense struct
	resourceStruct, err := convertFilterSchemaToStruct(data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to parse firwall filter, got error: %s", err))
		return
	}

	// OPNsense may briefly expose a stale policy/reply-to gateway option list
	// after a gateway is created. Retry only that exact validation failure, and
	// only after verifying that the referenced gateway exists with the same IP family.
	id, err := r.addFilterResolved(ctx, resourceStruct)
	if err != nil {
		if id != "" {
			data.Id = types.StringValue(id)

			// Read back so state captures API-normalised values (defaults,
			// sorting, trimming); fall back to plan-only state if the
			// read-back fails so the upstream resource isn't orphaned.
			if resourceStruct, readErr := r.client.Firewall().GetFilter(ctx, id); readErr == nil {
				if readModel, convErr := convertFilterStructToSchema(resourceStruct); convErr == nil {
					readModel.Id = data.Id
					data = readModel
				}
			}

			resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		}

		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to create firewall filter, got error: %s", err))
		return
	}

	// Tag new resource with ID from OPNsense
	data.Id = types.StringValue(id)

	// Write logs using the tflog package
	tflog.Trace(ctx, "created a resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *filterResource) addFilterResolved(ctx context.Context, filter *apifirewall.Filter) (string, error) {
	return r.addFilterResolvedWithTiming(ctx, filter, gatewayReadinessRetryInterval, gatewayReadinessRetryTimeout)
}

func (r *filterResource) addFilterResolvedWithTiming(ctx context.Context, filter *apifirewall.Filter, retryInterval, retryTimeout time.Duration) (string, error) {
	deadline := time.Now().Add(retryTimeout)
	gatewayVerified := false

	for {
		id, err := r.client.Firewall().AddFilter(ctx, filter)
		if err == nil {
			return id, nil
		}

		gatewayName, gatewayField := staleGatewayReference(err, filter)
		if gatewayName == "" {
			return id, err
		}

		if !gatewayVerified {
			exists, verifyErr := r.gatewayExists(ctx, gatewayName, filter.IPProtocol.String())
			if verifyErr != nil {
				return "", fmt.Errorf("verify %s gateway: %w", gatewayField, verifyErr)
			}
			if !exists {
				return id, err
			}
			gatewayVerified = true
		}

		if retryTimeout <= 0 || time.Now().Add(retryInterval).After(deadline) {
			return id, err
		}

		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
}

func staleGatewayReference(err error, filter *apifirewall.Filter) (string, string) {
	message := err.Error()
	if !strings.Contains(message, "Specify a valid gateway from the list matching the networks ip protocol") {
		return "", ""
	}
	if strings.Contains(message, "rule.replyto") {
		return filter.ReplyTo.String(), "reply-to"
	}
	if strings.Contains(message, "rule.gateway") {
		return filter.Gateway.String(), "policy-routing"
	}
	return "", ""
}

func (r *filterResource) gatewayExists(ctx context.Context, name, ipProtocol string) (bool, error) {
	type gatewayReadinessRow struct {
		Name       string          `json:"name"`
		IPProtocol api.SelectedMap `json:"ipprotocol"`
	}

	// Search responses can normalize unrelated gateway fields differently from
	// the model endpoints (for example disabled can be a native JSON boolean).
	// Decode only the fields needed for readiness validation so those unrelated
	// representations cannot break the check.
	result, err := api.Search[gatewayReadinessRow](r.client.Routing().Client(), ctx, routing.GatewayOpts.Search)
	if err != nil {
		return false, err
	}
	for _, gateway := range result.Rows {
		if gateway.Name == name && gateway.IPProtocol.String() == ipProtocol {
			return true, nil
		}
	}
	return false, nil
}

// Native XMLRPC rule UUIDs need not survive a clean router reinstall.
// Only an exact and unique endpoint rule may be adopted into a retained
// Terraform state; infrastructure/unrelated rules are never guessed by UUID.
func normalizedRuleInterfaces(value string) string {
	parts := strings.Split(value, ",")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			clean = append(clean, part)
		}
	}
	sort.Strings(clean)
	return strings.Join(clean, ",")
}

func exactFilterReplacement(prior *filterResourceModel, rows []map[string]any) (string, error) {
	if prior.Description.IsNull() || prior.Description.IsUnknown() ||
		prior.Description.ValueString() == "" || prior.Interface == nil ||
		prior.Filter == nil || prior.Interface.Interface.IsNull() ||
		prior.Interface.Interface.IsUnknown() {
		return "", fmt.Errorf("firewall rule lacks a stable description/interface/filter identity")
	}
	desired, err := convertFilterSchemaToStruct(prior)
	if err != nil {
		return "", fmt.Errorf("convert prior firewall rule: %w", err)
	}
	if desired.Interface.String() == "" {
		return "", fmt.Errorf("firewall rule has no concrete endpoint interface")
	}
	field := func(row map[string]any, key string) string {
		value, ok := row[key].(string)
		if !ok {
			return ""
		}
		return value
	}
	matches := []string{}
	for _, row := range rows {
		if field(row, "description") != desired.Description ||
			normalizedRuleInterfaces(field(row, "interface")) != normalizedRuleInterfaces(desired.Interface.String()) ||
			field(row, "action") != desired.Action.String() ||
			field(row, "direction") != desired.Direction.String() ||
			field(row, "ipprotocol") != desired.IPProtocol.String() ||
			field(row, "protocol") != desired.Protocol.String() ||
			field(row, "source_net") != desired.SourceNet ||
			field(row, "destination_net") != desired.DestinationNet ||
			field(row, "source_port") != desired.SourcePort ||
			field(row, "destination_port") != desired.DestinationPort {
			continue
		}
		uuid := field(row, "uuid")
		if uuid == "" {
			return "", fmt.Errorf("matching firewall rule has no UUID")
		}
		matches = append(matches, uuid)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected exactly one matching firewall rule, found %d", len(matches))
	}
	return matches[0], nil
}

func (r *filterResource) reattachFilter(ctx context.Context, prior *filterResourceModel) (string, error) {
	response, err := api.Search[map[string]any](
		r.client.Firewall().Client(), ctx,
		api.Endpoint{Path: "/firewall/filter/searchRule", Method: "POST"},
	)
	if err != nil {
		return "", fmt.Errorf("search remote firewall rules: %w", err)
	}
	if response == nil || response.Total > len(response.Rows) {
		return "", fmt.Errorf("incomplete firewall-rule search response; cannot safely reattach")
	}
	return exactFilterReplacement(prior, response.Rows)
}

func (r *filterResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *filterResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Get firewall filter from OPNsense unbound API
	resourceStruct, err := r.client.Firewall().GetFilter(ctx, data.Id.ValueString())
	if err != nil {
		var notFoundError *errs.NotFoundError
		if errors.As(err, &notFoundError) {
			// Legacy non-endpoint rules retain the usual missing-resource
			// behavior, while named endpoint rules fail closed if ambiguous.
			if data.Description.IsNull() || data.Description.IsUnknown() ||
				data.Description.ValueString() == "" {
				resp.State.RemoveResource(ctx)
				return
			}
			id, reattachErr := r.reattachFilter(ctx, data)
			if reattachErr != nil {
				resp.Diagnostics.AddError("Unable to Reattach Firewall Rule After Router Replacement", reattachErr.Error())
				return
			}
			resourceStruct, err = r.client.Firewall().GetFilter(ctx, id)
			if err != nil {
				resp.Diagnostics.AddError("Unable to Read Reattached Firewall Rule", err.Error())
				return
			}
			data.Id = types.StringValue(id)
		} else {
			resp.Diagnostics.AddError("Client Error",
				fmt.Sprintf("Unable to read firewall filter, got error: %s", err))
			return
		}
	}

	// Convert OPNsense struct to TF schema
	resourceModel, err := convertFilterStructToSchema(resourceStruct)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to read firewall filter, got error: %s", err))
		return
	}

	// ID cannot be added by convert... func, have to add here
	resourceModel.Id = data.Id

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &resourceModel)...)
}

func (r *filterResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data *filterResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Convert TF schema OPNsense struct
	resourceStruct, err := convertFilterSchemaToStruct(data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to parse firewall filter, got error: %s", err))
		return
	}

	// Update firewall filter in unbound
	err = r.client.Firewall().UpdateFilter(ctx, data.Id.ValueString(), resourceStruct)
	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to create firewall filter, got error: %s", err))
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *filterResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *filterResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.Firewall().DeleteFilter(ctx, data.Id.ValueString())

	if err != nil {
		resp.Diagnostics.AddError("Client Error",
			fmt.Sprintf("Unable to delete firewall filter, got error: %s", err))
		return
	}
}

func (r *filterResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *filterResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	schemaV0 := filterResourceSchemaV0()
	return map[int64]resource.StateUpgrader{
		// Upgrade from version 0 (old flat schema) to version 1 (nested schema)
		0: {
			PriorSchema:   &schemaV0,
			StateUpgrader: upgradeFilterStateV0toV1,
		},
	}
}

// upgradeFilterStateV0toV1 migrates state from schema version 0 to version 1.
// Schema v0 had a flat structure with top-level attributes.
// Schema v1 reorganizes into nested blocks: interface, filter, stateful_firewall, etc.
func upgradeFilterStateV0toV1(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	tflog.Info(ctx, "Upgrading filter resource state from v0 to v1")

	// Parse the old state from RawState JSON
	var oldState filterResourceModelV0

	// Read old state
	resp.Diagnostics.Append(req.State.Get(ctx, &oldState)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to read old state during upgrade")
		return
	}

	// Extract source and destination objects
	var oldSource *firewallLocation
	var oldDest *firewallLocation

	if !oldState.Source.IsNull() {
		oldSource = &firewallLocation{}
		resp.Diagnostics.Append(oldState.Source.As(ctx, oldSource, basetypes.ObjectAsOptions{})...)
	}

	if !oldState.Destination.IsNull() {
		oldDest = &firewallLocation{}
		resp.Diagnostics.Append(oldState.Destination.As(ctx, oldDest, basetypes.ObjectAsOptions{})...)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Build new v1 state structure
	newState := &filterResourceModel{
		// Top-level fields (preserved)
		Enabled:     oldState.Enabled,
		Sequence:    oldState.Sequence,
		Description: oldState.Description,
		Id:          oldState.Id,

		// New top-level fields (defaults)
		NoXMLRPCSync: types.BoolValue(false),
		Categories:   types.SetValueMust(types.StringType, []attr.Value{}),

		// Interface block (transform Set → nested with invert)
		Interface: &filterInterfaceBlock{
			Invert:    types.BoolValue(false),
			Interface: oldState.Interface,
		},

		// Filter block (consolidate many old top-level fields)
		Filter: &filterFilterBlock{
			Quick:         oldState.Quick,
			Action:        oldState.Action,
			AllowOptions:  types.BoolValue(false), // New field, default
			Direction:     oldState.Direction,
			IPProtocol:    oldState.IPProtocol,
			Protocol:      oldState.Protocol,
			ICMPType:      types.SetValueMust(types.StringType, []attr.Value{}), // New field, default
			Source:        oldSource,
			Destination:   oldDest,
			Log:           oldState.Log,
			TCPFlags:      types.SetValueMust(types.StringType, []attr.Value{}), // New field, default
			TCPFlagsOutOf: types.SetValueMust(types.StringType, []attr.Value{}), // New field, default
			Schedule:      types.StringValue(""),                                // New field, default
		},

		// Stateful Firewall block (new, all defaults)
		StatefulFirewall: &filterStatefulFirewallBlock{
			Type:    types.StringValue("keep"),
			Policy:  types.StringValue(""),
			Timeout: types.Int64Value(-1),
			AdaptiveTimeouts: &filterAdaptiveTimeouts{
				Start: types.Int64Value(-1),
				End:   types.Int64Value(-1),
			},
			Max: &filterMax{
				States:            types.Int64Value(-1),
				SourceNodes:       types.Int64Value(-1),
				SourceStates:      types.Int64Value(-1),
				SourceConnections: types.Int64Value(-1),
				NewConnections: &filterNewConnections{
					Count:   types.Int64Value(-1),
					Seconds: types.Int64Value(-1),
				},
			},
			OverloadTable: types.StringValue(""),
			NoPfsync:      types.BoolValue(false),
		},

		// Traffic Shaping block (new, all defaults)
		TrafficShaping: &filterTrafficShapingBlock{
			Shaper:        types.StringValue(""),
			ReverseShaper: types.StringValue(""),
		},

		// Source Routing block (gateway moved here)
		SourceRouting: &filterSourceRoutingBlock{
			Gateway:        oldState.Gateway,
			DisableReplyTo: types.BoolValue(false), // New field, default
			ReplyTo:        types.StringValue(""),  // New field, default
		},

		// Priority block (new, all defaults)
		Priority: &filterPriorityBlock{
			Match:       types.Int64Value(-1),
			Set:         types.Int64Value(-1),
			LowDelaySet: types.Int64Value(-1),
			MatchTOS:    types.StringValue(""),
		},

		// Internal Tagging block (new, all defaults)
		InternalTagging: &filterInternalTaggingBlock{
			SetLocal:   types.StringValue(""),
			MatchLocal: types.StringValue(""),
		},
	}

	// Set the upgraded state
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)

	if !resp.Diagnostics.HasError() {
		tflog.Info(ctx, "Successfully upgraded filter resource state from v0 to v1", map[string]any{
			"id": oldState.Id.ValueString(),
		})
	}
}
