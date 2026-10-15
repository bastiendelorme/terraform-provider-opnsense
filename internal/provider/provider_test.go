package provider_test

import (
	"context"
	"testing"

	"github.com/biptec/terraform-provider-opnsense/internal/acctest"
	"github.com/biptec/terraform-provider-opnsense/internal/provider"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestProvider(t *testing.T) {
	opnsense, err := provider.NewProvider(context.Background())
	if opnsense == nil || err != nil {
		t.Fatal("provider.New() returned nil")
	}
}

func TestProvider_RequestTimeoutSchema(t *testing.T) {
	_, p, err := provider.ProtoV6ProviderServerFactory(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}

	var resp frameworkprovider.SchemaResponse
	p.Schema(context.Background(), frameworkprovider.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("provider schema diagnostics: %v", resp.Diagnostics)
	}

	attr, ok := resp.Schema.Attributes["request_timeout"]
	if !ok {
		t.Fatal("request_timeout attribute missing from provider schema")
	}
	if !attr.IsOptional() {
		t.Fatal("request_timeout must be optional")
	}
}

func TestProvider_Configure(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					func(s *terraform.State) error {
						return nil
					},
				),
			},
		},
	})
}

const testAccProviderConfig = `
provider "opnsense" {
  # Configuration will be loaded from environment variables
  # OPNSENSE_URI, OPNSENSE_API_KEY, OPNSENSE_API_SECRET
}
`
