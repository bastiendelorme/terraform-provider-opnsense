package interfaces

import (
	"testing"

	"github.com/biptec/opnsense-go/pkg/api"
	apiinterfaces "github.com/biptec/opnsense-go/pkg/interfaces"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestConvertVipCARP(t *testing.T) {
	t.Parallel()
	model := vipResourceModel{Mode: types.StringValue("carp"), Interface: types.StringValue("lan"), Network: types.StringValue("192.0.2.10/24"), Gateway: types.StringNull(), NoExpand: types.BoolValue(false), NoBind: types.BoolValue(false), Password: types.StringValue("secret"), VHID: types.Int64Value(10), VirtualMAC: types.StringValue("02:DE:AD:BE:EF:10"), AdvertisementBase: types.Int64Value(1), AdvertisementSkew: types.Int64Value(20), PeerIPv4: types.StringNull(), PeerIPv6: types.StringNull(), NoSync: types.BoolValue(false), Description: types.StringValue("HA VIP")}
	got, err := convertVipSchemaToStruct(&model, types.StringValue("secret"))
	if err != nil {
		t.Fatalf("convertVipSchemaToStruct() error = %v", err)
	}
	if got.Mode.String() != "carp" || got.VHID != "10" || got.VirtualMAC != "02:de:ad:be:ef:10" || got.AdvertisementSkew != "20" {
		t.Fatalf("vip = %#v", got)
	}
}

func TestConvertVipRequiresCARPCredentials(t *testing.T) {
	t.Parallel()
	model := vipResourceModel{Mode: types.StringValue("carp"), Interface: types.StringValue("lan"), Network: types.StringValue("192.0.2.10/24"), Password: types.StringNull(), VHID: types.Int64Null(), AdvertisementBase: types.Int64Value(1), AdvertisementSkew: types.Int64Value(0)}
	if _, err := convertVipSchemaToStruct(&model, types.StringNull()); err == nil {
		t.Fatal("expected CARP validation error")
	}
}

func TestConvertVipRejectsInvalidVirtualMAC(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"01:00:5e:00:00:01", "ff:ff:ff:ff:ff:ff", "not-a-mac"} {
		model := vipResourceModel{Mode: types.StringValue("carp"), Interface: types.StringValue("wan"), Network: types.StringValue("192.0.2.10/24"), Password: types.StringValue("secret"), VHID: types.Int64Value(10), VirtualMAC: types.StringValue(value), AdvertisementBase: types.Int64Value(1), AdvertisementSkew: types.Int64Value(0)}
		if _, err := convertVipSchemaToStruct(&model, types.StringValue("secret")); err == nil {
			t.Fatalf("expected virtual MAC validation error for %q", value)
		}
	}
}

func TestConvertVipRejectsVirtualMACOutsideCARP(t *testing.T) {
	t.Parallel()
	model := vipResourceModel{Mode: types.StringValue("ipalias"), Interface: types.StringValue("wan"), Network: types.StringValue("192.0.2.11/24"), VirtualMAC: types.StringValue("02:de:ad:be:ef:11"), VHID: types.Int64Value(10), AdvertisementBase: types.Int64Value(1), AdvertisementSkew: types.Int64Value(0)}
	if _, err := convertVipSchemaToStruct(&model, types.StringNull()); err == nil {
		t.Fatal("expected virtual_mac mode validation error")
	}
}

func TestVipFallbackStateResolvesComputedUnknowns(t *testing.T) {
	t.Parallel()

	model := &vipResourceModel{
		Address:  types.StringUnknown(),
		VHIDText: types.StringUnknown(),
	}
	got := vipFallbackState(model, "vip-id")
	if got.Id.ValueString() != "vip-id" {
		t.Fatalf("id = %q, want vip-id", got.Id.ValueString())
	}
	if !got.Address.IsNull() || !got.VHIDText.IsNull() {
		t.Fatalf("computed fields were not resolved: address=%#v vhid_text=%#v", got.Address, got.VHIDText)
	}
}

func TestConvertVipIPAliasWithVHID(t *testing.T) {
	t.Parallel()
	model := vipResourceModel{Mode: types.StringValue("ipalias"), Interface: types.StringValue("wan"), Network: types.StringValue("192.0.2.11/24"), Password: types.StringNull(), VHID: types.Int64Value(10), AdvertisementBase: types.Int64Value(1), AdvertisementSkew: types.Int64Value(0), NoExpand: types.BoolValue(false), NoBind: types.BoolValue(false), NoSync: types.BoolValue(false)}
	got, err := convertVipSchemaToStruct(&model, types.StringNull())
	if err != nil {
		t.Fatalf("convertVipSchemaToStruct() error = %v", err)
	}
	if got.Mode.String() != "ipalias" || got.VHID != "10" || got.Password != "" {
		t.Fatalf("vip = %#v", got)
	}
}

func TestConvertVipRejectsPasswordOnIPAlias(t *testing.T) {
	t.Parallel()
	model := vipResourceModel{Mode: types.StringValue("ipalias"), Interface: types.StringValue("wan"), Network: types.StringValue("192.0.2.11/24"), Password: types.StringValue("secret"), VHID: types.Int64Value(10), AdvertisementBase: types.Int64Value(1), AdvertisementSkew: types.Int64Value(0)}
	if _, err := convertVipSchemaToStruct(&model, types.StringValue("secret")); err == nil {
		t.Fatal("expected password validation error")
	}
}

func TestConvertVipRejectsVHIDOnProxyARP(t *testing.T) {
	t.Parallel()
	model := vipResourceModel{Mode: types.StringValue("proxyarp"), Interface: types.StringValue("wan"), Network: types.StringValue("192.0.2.11/32"), Password: types.StringNull(), VHID: types.Int64Value(10), AdvertisementBase: types.Int64Value(1), AdvertisementSkew: types.Int64Value(0)}
	if _, err := convertVipSchemaToStruct(&model, types.StringNull()); err == nil {
		t.Fatal("expected vhid validation error")
	}
}

func TestVipPasswordIsWriteOnly(t *testing.T) {
	t.Parallel()
	schema := vipResourceSchema()
	password := schema.Attributes["password"]
	if !password.IsSensitive() || !password.IsWriteOnly() || password.IsComputed() {
		t.Fatal("CARP password must be sensitive write-only and not computed")
	}
	if schema.Version != 1 {
		t.Fatalf("VIP schema version = %d, want 1", schema.Version)
	}
	if _, ok := schema.Attributes["password_version"]; !ok {
		t.Fatal("password_version attribute missing")
	}
	if _, ok := schema.Attributes["password_configured"]; !ok {
		t.Fatal("password_configured attribute missing")
	}
	if _, ok := vipDataSourceSchema().Attributes["password"]; ok {
		t.Fatal("VIP data source must not expose password")
	}
	legacy := vipResourceSchemaV0()
	if legacy.Attributes["password"].IsWriteOnly() {
		t.Fatal("legacy VIP schema must describe the old stateful password for migration")
	}
}

func TestConvertVipIPAliasSkewIgnoresLocalHAOverride(t *testing.T) {
	for _, mode := range []string{"ipalias", "proxyarp"} {
		m, err := convertVipStructToSchema(&apiinterfaces.Vip{
			Mode: api.SelectedMap(mode), Interface: api.SelectedMap("endpoint"),
			Network: "fd42:103:3990::1/64", VHID: "165",
			AdvertisementBase: "1", AdvertisementSkew: "200",
		})
		if err != nil || m.AdvertisementSkew.ValueInt64() != 0 {
			t.Fatalf("non-CARP mode %s must normalize ignored advskew: %+v, %v", mode, m, err)
		}
	}
	carp, err := convertVipStructToSchema(&apiinterfaces.Vip{
		Mode: api.SelectedMap("carp"), Interface: api.SelectedMap("endpoint"),
		Network: "10.250.99.1/30", VHID: "165",
		AdvertisementBase: "1", AdvertisementSkew: "100",
	})
	if err != nil || carp.AdvertisementSkew.ValueInt64() != 100 {
		t.Fatalf("CARP skew must remain receiver-local: %+v, %v", carp, err)
	}
}

func TestConvertVipStructDoesNotReturnPassword(t *testing.T) {
	t.Parallel()
	model, err := convertVipStructToSchema(&apiinterfaces.Vip{
		Mode: api.SelectedMap("carp"), Interface: api.SelectedMap("wan"), Network: "192.0.2.10/24",
		Password: "remote-secret", VHID: "10", VirtualMAC: "02:de:ad:be:ef:10", AdvertisementBase: "1", AdvertisementSkew: "0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !model.Password.IsNull() || !model.PasswordConfigured.ValueBool() || model.VirtualMAC.ValueString() != "02:de:ad:be:ef:10" {
		t.Fatalf("password leaked into model or configured flag missing: %+v", model)
	}
}
