package dstest

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/stretchr/testify/require"
)

// CreateTestFederationRelationships creates a set of test federation relationships for testing.
// It returns four federation relationships with different configurations that can be used in tests.
func CreateTestFederationRelationships(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) []*datastore.FederationRelationship {
	fr1 := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("spiffe://example-1.org"),
		BundleEndpointURL:     RequireURLFromString(t, "https://example-1-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}
	_, err := ds.CreateFederationRelationship(context.Background(), fr1)
	require.NoError(t, err)

	trustDomainBundle := createBundle(t, ds, "spiffe://example-2.org", cert)
	fr2 := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("spiffe://example-2.org"),
		BundleEndpointURL:     RequireURLFromString(t, "https://example-2-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
		EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://example-2.org/test"),
		TrustDomainBundle:     trustDomainBundle,
	}
	_, err = ds.CreateFederationRelationship(context.Background(), fr2)
	require.NoError(t, err)

	fr3 := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("spiffe://example-3.org"),
		BundleEndpointURL:     RequireURLFromString(t, "https://example-3-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
		EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://example-2.org/test"),
	}
	_, err = ds.CreateFederationRelationship(context.Background(), fr3)
	require.NoError(t, err)

	fr4 := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("spiffe://example-4.org"),
		BundleEndpointURL:     RequireURLFromString(t, "https://example-4-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}
	_, err = ds.CreateFederationRelationship(context.Background(), fr4)
	require.NoError(t, err)

	return []*datastore.FederationRelationship{fr1, fr2, fr3, fr4}
}
