package dstest

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertFederationRelationship helper for the test package
// AssertFederationRelationship compares expected and actual federation relationships.
func AssertFederationRelationship(t *testing.T, exp, actual *datastore.FederationRelationship) {
	if exp == nil {
		assert.Nil(t, actual)
		return
	}
	assert.Equal(t, exp.BundleEndpointProfile, actual.BundleEndpointProfile)
	assert.Equal(t, exp.BundleEndpointURL, actual.BundleEndpointURL)
	assert.Equal(t, exp.EndpointSPIFFEID, actual.EndpointSPIFFEID)
	assert.Equal(t, exp.TrustDomain, actual.TrustDomain)
	spiretest.AssertProtoEqual(t, exp.TrustDomainBundle, actual.TrustDomainBundle)
}

// requireURLFromString helper for the test package
// RequireURLFromString parses s into a URL and fails the test on error.
func RequireURLFromString(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		require.FailNow(t, err.Error())
	}
	return u
}

// fetchBundle helper for the test package
func fetchBundle(t *testing.T, ds datastore.DataStore, trustDomainID string) *common.Bundle {
	bundle, err := ds.FetchBundle(ctx, trustDomainID)
	require.NoError(t, err)
	return bundle
}

// createBundle helper for the test package
func createBundle(t *testing.T, ds datastore.DataStore, trustDomainID string, cert *x509.Certificate) *common.Bundle {
	bundle, err := ds.CreateBundle(ctx, bundleutil.BundleProtoFromRootCA(trustDomainID, cert))
	require.NoError(t, err)
	return bundle
}

// makeFederatedRegistrationEntry for the test package
func makeFederatedRegistrationEntry() *common.RegistrationEntry {
	return &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
		},
		SpiffeId:      "spiffe://example.org/foo",
		FederatesWith: []string{"spiffe://otherdomain.org"},
	}
}

// createRegistrationEntry helper for the test package
func createRegistrationEntry(t *testing.T, ds datastore.DataStore, entry *common.RegistrationEntry) *common.RegistrationEntry {
	registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
	require.NoError(t, err)
	require.NotNil(t, registrationEntry)
	return registrationEntry
}

// fetchRegistrationEntry helper for the test package
func fetchRegistrationEntry(t *testing.T, ds datastore.DataStore, entryID string) *common.RegistrationEntry {
	registrationEntry, err := ds.FetchRegistrationEntry(ctx, entryID)
	require.NoError(t, err)
	require.NotNil(t, registrationEntry)
	return registrationEntry
}

func CreateBundles(t *testing.T, ds datastore.DataStore, trustDomains []string) {
	for _, td := range trustDomains {
		_, err := ds.CreateBundle(ctx, &common.Bundle{
			TrustDomainId: td,
			RootCas: []*common.Certificate{
				{
					DerBytes: []byte{1},
				},
			},
		})
		require.NoError(t, err)
	}
}
