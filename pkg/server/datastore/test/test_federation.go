package dstest

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	types "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// TestRegistrationEntriesFederatesWithAgainstMissingBundle tests that registration entries cannot federate with missing bundles
func TestRegistrationEntriesFederatesWithAgainstMissingBundle(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	// cannot federate with a trust bundle that does not exist
	_, err := ds.CreateRegistrationEntry(ctx, makeFederatedRegistrationEntry())
	require.ErrorContains(t, err, `unable to find federated bundle "spiffe://otherdomain.org"`)
}

// TestRegistrationEntriesFederatesWithSuccess tests that registration entries can successfully federate with existing bundles
func TestRegistrationEntriesFederatesWithSuccess(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	// create two bundles but only federate with one. having a second bundle
	// has the side effect of asserting that only the code only associates
	// the entry with the exact bundle referenced during creation.
	createBundle(t, ds, "spiffe://otherdomain.org", cert)
	createBundle(t, ds, "spiffe://otherdomain2.org", cert)

	expected := CreateRegistrationEntry(t, ds, makeFederatedRegistrationEntry())
	// fetch the entry and make sure the federated trust ids come back
	actual := fetchRegistrationEntry(t, ds, expected.EntryId)
	spiretest.AssertProtoEqual(t, expected, actual)
}

// TestDeleteBundleRestrictedByRegistrationEntries tests that bundle deletion is restricted when registration entries use the bundle
func TestDeleteBundleRestrictedByRegistrationEntries(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	// create the bundle and associated entry
	createBundle(t, ds, "spiffe://otherdomain.org", cert)
	CreateRegistrationEntry(t, ds, makeFederatedRegistrationEntry())

	// delete the bundle in RESTRICTED mode
	err := ds.DeleteBundle(context.Background(), "spiffe://otherdomain.org", datastore.Restrict)
	require.ErrorContains(t, err, "datastore-sql: cannot delete bundle; federated with 1 registration entries")
}

// TestDeleteBundleDeleteRegistrationEntries tests bundle deletion with Delete mode that removes associated registration entries
func TestDeleteBundleDeleteRegistrationEntries(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	// create an unrelated registration entry to make sure the delete
	// operation only deletes associated registration entries.
	unrelated := CreateRegistrationEntry(t, ds, &common.RegistrationEntry{
		SpiffeId:  "spiffe://example.org/foo",
		Selectors: []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
	})

	// create the bundle and associated entry
	createBundle(t, ds, "spiffe://otherdomain.org", cert)
	entry := CreateRegistrationEntry(t, ds, makeFederatedRegistrationEntry())

	// delete the bundle in Delete mode
	err := ds.DeleteBundle(context.Background(), "spiffe://otherdomain.org", datastore.Delete)
	require.NoError(t, err)

	// verify that the registration entry has been deleted
	registrationEntry, err := ds.FetchRegistrationEntry(context.Background(), entry.EntryId)
	require.NoError(t, err)
	require.Nil(t, registrationEntry)

	// make sure the unrelated entry still exists
	fetchRegistrationEntry(t, ds, unrelated.EntryId)
}

// TestDeleteBundleDissociateRegistrationEntries tests bundle deletion with Dissociate mode that removes bundle associations
func TestDeleteBundleDissociateRegistrationEntries(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	// create the bundle and associated entry
	createBundle(t, ds, "spiffe://otherdomain.org", cert)
	entry := CreateRegistrationEntry(t, ds, makeFederatedRegistrationEntry())

	// delete the bundle in DISSOCIATE mode
	err := ds.DeleteBundle(context.Background(), "spiffe://otherdomain.org", datastore.Dissociate)
	require.NoError(t, err)

	// make sure the entry still exists, albeit without an associated bundle
	entry = fetchRegistrationEntry(t, ds, entry.EntryId)
	require.Empty(t, entry.FederatesWith)
}

// CreateFederationRelationship helper test function
func TestCreateFederationRelationship(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	// Create required bundles
	createBundle(t, ds, "spiffe://federated-td-spiffe.org", cert)
	createBundle(t, ds, "spiffe://federated-td-spiffe-with-bundle.org", cert)

	testCases := []struct {
		name       string
		expectCode codes.Code
		expectMsg  string
		fr         *datastore.FederationRelationship
	}{
		{
			name: "creating a new federation relationship succeeds for web profile",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
				BundleEndpointURL:     RequireURLFromString(t, "federated-td-web.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name: "creating a new federation relationship succeeds for spiffe profile",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
				BundleEndpointURL:     RequireURLFromString(t, "federated-td-spiffe.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe.org/federated-server"),
			},
		},
		{
			name: "creating a new federation relationship succeeds for web profile and new bundle",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web-with-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "federated-td-web-with-bundle.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://federated-td-web-with-bundle.org", cert)
					newBundle.RefreshHint = int64(10) // modify bundle to assert it was updated
					return newBundle
				}(),
			},
		},
		{
			name: "creating a new federation relationship succeeds for spiffe profile and new bundle",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe-with-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "federated-td-spiffe-with-bundle.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe-with-bundle.org/federated-server"),
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://federated-td-spiffe-with-bundle.org", cert)
					newBundle.RefreshHint = int64(10) // modify bundle to assert it was updated
					return newBundle
				}(),
			},
		},
		{
			name:       "creating a new nil federation relationship fails nicely ",
			expectCode: codes.InvalidArgument,
			expectMsg:  "federation relationship is nil",
		},
		{
			name:       "creating a new federation relationship without trust domain fails nicely ",
			expectCode: codes.InvalidArgument,
			expectMsg:  "trust domain is required",
			fr: &datastore.FederationRelationship{
				BundleEndpointURL:     RequireURLFromString(t, "federated-td-web.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name:       "creating a new federation relationship without bundle endpoint URL fails nicely",
			expectCode: codes.InvalidArgument,
			expectMsg:  "bundle endpoint URL is required",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe.org/federated-server"),
			},
		},
		{
			name:       "creating a new SPIFFE federation relationship without bundle endpoint SPIFFE ID fails nicely",
			expectCode: codes.InvalidArgument,
			expectMsg:  "bundle endpoint SPIFFE ID is required",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
				BundleEndpointURL:     RequireURLFromString(t, "federated-td-spiffe.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
			},
		},
		{
			name:       "creating a new SPIFFE federation relationship without initial bundle pass",
			expectCode: codes.OK,
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("no-initial-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "no-initial-bundle.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://no-initial-bundle.org/federated-server"),
			},
		},
		{
			name:       "creating a new federation relationship of unknown type fails nicely",
			expectCode: codes.InvalidArgument,
			expectMsg:  "unknown bundle endpoint profile type: \"wrong-type\"",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("no-initial-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "no-initial-bundle.org/bundleendpoint"),
				BundleEndpointProfile: "wrong-type",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			fr, err := ds.CreateFederationRelationship(ctx, tt.fr)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				require.Nil(t, fr)
				return
			}
			// TODO: when FetchFederationRelationship is implemented, assert if entry was created

			switch fr.BundleEndpointProfile {
			case datastore.BundleEndpointWeb:
			case datastore.BundleEndpointSPIFFE:
			default:
				require.FailNowf(t, "unexpected bundle endpoint profile type: %q", string(fr.BundleEndpointProfile))
			}

			if fr.TrustDomainBundle != nil {
				// Assert bundle is updated
				bundle, err := ds.FetchBundle(ctx, fr.TrustDomain.IDString())
				require.NoError(t, err)
				spiretest.RequireProtoEqual(t, bundle, fr.TrustDomainBundle)
			}
		})
	}
}

// NoSQL specific
func TestListFederationRelationshipsNonIntegerTokens(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	testRelationships := CreateTestFederationRelationships(t, ds, cert)
	fr1, fr2, fr3, fr4 := testRelationships[0], testRelationships[1], testRelationships[2], testRelationships[3]

	tests := []struct {
		name               string
		pagination         *datastore.Pagination
		expectedList       []*datastore.FederationRelationship
		expectedPagination *datastore.Pagination
		expectedErr        string
	}{
		{
			name:         "no pagination",
			expectedList: []*datastore.FederationRelationship{fr1, fr2, fr3, fr4},
		},
		{
			name: "page size bigger than items",
			pagination: &datastore.Pagination{
				PageSize: 5,
			},
			expectedList: []*datastore.FederationRelationship{fr1, fr2, fr3, fr4},
			expectedPagination: &datastore.Pagination{
				Token:    "",
				PageSize: 5,
			},
		},
		{
			name: "pagination page size is zero",
			pagination: &datastore.Pagination{
				PageSize: 0,
			},
			expectedErr: "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0",
		},
		{
			name: "federation relationships first page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 2,
			},
			expectedList: []*datastore.FederationRelationship{fr1, fr2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, err := ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{
				Pagination: test.pagination,
			})
			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			require.Len(t, resp.FederationRelationships, len(test.expectedList))
			for i, each := range resp.FederationRelationships {
				AssertFederationRelationship(t, test.expectedList[i], each)
			}
		})
	}
	nextToken := ""
	t.Run("federation relationships first page", func(t *testing.T) {
		resp, err := ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{
			Pagination: &datastore.Pagination{
				Token:    nextToken,
				PageSize: 2,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)

		require.Len(t, resp.FederationRelationships, 2)
		AssertFederationRelationship(t, fr1, resp.FederationRelationships[0])
		AssertFederationRelationship(t, fr2, resp.FederationRelationships[1])

		nextToken = resp.Pagination.Token
	})
	t.Run("federation relationships second page", func(t *testing.T) {
		resp, err := ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{
			Pagination: &datastore.Pagination{
				Token:    nextToken,
				PageSize: 2,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)

		require.Len(t, resp.FederationRelationships, 2)
		AssertFederationRelationship(t, fr3, resp.FederationRelationships[0])
		AssertFederationRelationship(t, fr4, resp.FederationRelationships[1])

		nextToken = resp.Pagination.Token
	})
	t.Run("Assert next token is empty", func(t *testing.T) {
		require.Equal(t, "", nextToken)
	})
}

// TestListFederationRelationships tests federation relationships listing functionality
func TestListFederationRelationships(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	testRelationships := CreateTestFederationRelationships(t, ds, cert)
	fr1, fr2, fr3, fr4 := testRelationships[0], testRelationships[1], testRelationships[2], testRelationships[3]

	tests := []struct {
		name               string
		pagination         *datastore.Pagination
		expectedList       []*datastore.FederationRelationship
		expectedPagination *datastore.Pagination
		expectedErr        string
	}{
		{
			name:         "no pagination",
			expectedList: []*datastore.FederationRelationship{fr1, fr2, fr3, fr4},
		},
		{
			name: "page size bigger than items",
			pagination: &datastore.Pagination{
				PageSize: 5,
			},
			expectedList: []*datastore.FederationRelationship{fr1, fr2, fr3, fr4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 5,
			},
		},
		{
			name: "pagination page size is zero",
			pagination: &datastore.Pagination{
				PageSize: 0,
			},
			expectedErr: "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0",
		},
		{
			name: "federation relationships first page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 2,
			},
			expectedList: []*datastore.FederationRelationship{fr1, fr2},
			expectedPagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
		},
		{
			name: "federation relationships second page",
			pagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
			expectedList: []*datastore.FederationRelationship{fr3, fr4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
		},
		{
			name:         "federation relationships third page",
			expectedList: []*datastore.FederationRelationship{},
			pagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				Token:    "",
				PageSize: 2,
			},
		},
		{
			name:         "invalid token",
			expectedList: []*datastore.FederationRelationship{},
			expectedErr:  "rpc error: code = InvalidArgument desc = could not parse token 'invalid token'",
			pagination: &datastore.Pagination{
				Token:    "invalid token",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				PageSize: 2,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, err := ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{
				Pagination: test.pagination,
			})
			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			require.Len(t, resp.FederationRelationships, len(test.expectedList))
			for i, each := range resp.FederationRelationships {
				AssertFederationRelationship(t, test.expectedList[i], each)
			}

			require.Equal(t, test.expectedPagination, resp.Pagination)
		})
	}
}

// TestUpdateFederationRelationship tests updating federation relationships using the provided datastore
func TestUpdateFederationRelationship(t *testing.T, ds datastore.DataStore, cert *x509.Certificate) {
	// ensure a bundle exists for tests that expect a pre-existent bundle
	createBundle(t, ds, "spiffe://td-with-bundle.org", cert)

	testCases := []struct {
		name      string
		initialFR *datastore.FederationRelationship
		fr        *datastore.FederationRelationship
		mask      *types.FederationRelationshipMask
		expFR     *datastore.FederationRelationship
		expErr    string
	}{
		{
			name: "updating bundle endpoint URL succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:       spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL: RequireURLFromString(t, "td.org/other-bundle-endpoint"),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointUrl: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td.org/other-bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name: "updating bundle endpoint profile with pre-existent bundle and no input bundle succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
				TrustDomainBundle:     bundleutil.BundleProtoFromRootCA("spiffe://td-with-bundle.org", cert),
			},
		},
		{
			name: "updating bundle endpoint profile with pre-existent bundle and input bundle succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://td-with-bundle.org", cert)
					newBundle.RefreshHint = int64(10) // modify bundle to assert it was updated
					return newBundle
				}(),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://td-with-bundle.org", cert)
					newBundle.RefreshHint = int64(10)
					return newBundle
				}(),
			},
		},
		{
			name: "updating bundle endpoint profile to SPIFFE without pre-existent bundle succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-without-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td-without-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-without-bundle.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-without-bundle.org/federated-server"),
				TrustDomainBundle:     bundleutil.BundleProtoFromRootCA("spiffe://td-without-bundle.org", cert),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-without-bundle.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td-without-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-without-bundle.org/federated-server"),
				TrustDomainBundle:     bundleutil.BundleProtoFromRootCA("spiffe://td-without-bundle.org", cert),
			},
		},
		{
			name: "updating bundle endpoint profile to without pre-existent bundle and no input bundle pass",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td.org/federated-server"),
			},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td.org/federated-server"),
				BundleEndpointURL:     RequireURLFromString(t, "td.org/bundle-endpoint"),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
		},
		{
			name: "updating federation relationship for non-existent trust domain fails nicely",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("non-existent-td.org"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td.org/federated-server"),
			},
			mask:   &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expErr: "rpc error: code = NotFound desc = unable to fetch federation relationship: record not found",
		},
		{
			name:   "updatinga nil federation relationship fails nicely ",
			expErr: "rpc error: code = InvalidArgument desc = federation relationship is nil",
		},
		{
			name:   "updating a federation relationship without trust domain fails nicely ",
			expErr: "rpc error: code = InvalidArgument desc = trust domain is required",
			fr:     &datastore.FederationRelationship{},
		},
		{
			name:   "updating a federation relationship without bundle endpoint URL fails nicely",
			expErr: "rpc error: code = InvalidArgument desc = bundle endpoint URL is required",
			mask:   protoutil.AllTrueFederationRelationshipMask,
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td.org/federated-server"),
			},
		},
		{
			name:   "updating a federation relationship of unknown type fails nicely",
			expErr: "rpc error: code = InvalidArgument desc = unknown bundle endpoint profile type: \"wrong-type\"",
			mask:   protoutil.AllTrueFederationRelationshipMask,
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     RequireURLFromString(t, "td.org/bundle-endpoint"),
				BundleEndpointProfile: "wrong-type",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.initialFR != nil {
				_, err := ds.CreateFederationRelationship(ctx, tt.initialFR)
				require.NoError(t, err)
				defer func() { require.NoError(t, ds.DeleteFederationRelationship(ctx, tt.initialFR.TrustDomain)) }()
			}

			updatedFR, err := ds.UpdateFederationRelationship(ctx, tt.fr, tt.mask)
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Nil(t, updatedFR)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, updatedFR)

			if tt.expFR != nil {
				switch tt.expFR.BundleEndpointProfile {
				case datastore.BundleEndpointWeb:
				case datastore.BundleEndpointSPIFFE:
					bundle, err := ds.FetchBundle(ctx, tt.expFR.TrustDomain.IDString())
					require.NoError(t, err)
					spiretest.AssertProtoEqual(t, bundle, updatedFR.TrustDomainBundle)

					// Now that bundles were asserted, set them to nil to be able to compare other fields
					tt.expFR.TrustDomainBundle = nil
					updatedFR.TrustDomainBundle = nil
				default:
					require.FailNowf(t, "unexpected bundle endpoint profile type: %q", string(tt.expFR.BundleEndpointProfile))
				}
			}

			require.Equal(t, tt.expFR, updatedFR)
		})
	}
}

type FederatedTrustDomainRaw struct {
	TrustDomain           string
	BundleEndpointURL     string
	BundleEndpointProfile string // string form of datastore.BundleEndpointProfile
	EndpointSPIFFEID      string // empty when not set
	// TrustDomainBundle is not needed for “corrupted” rows in these tests.
}

// TestFetchFederationRelationship is a backend-agnostic test. Backends supply:
//   - ds: the datastore under test
//   - createRaw: a callback that persists a raw FR record (used for corrupted rows)
func TestFetchFederationRelationship(t *testing.T, ds datastore.DataStore, createRaw func(FederatedTrustDomainRaw) error) {
	ctx := context.Background()

	testCases := []struct {
		name        string
		trustDomain spiffeid.TrustDomain
		expErr      string
		expFR       *datastore.FederationRelationship
	}{
		{
			name:        "fetching an existent federation relationship succeeds for web profile",
			trustDomain: spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
			expFR: func() *datastore.FederationRelationship {
				fr, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
					BundleEndpointURL:     RequireURLFromString(t, "federated-td-web.org/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				})
				require.NoError(t, err)
				return fr
			}(),
		},
		{
			name:        "fetching an existent federation relationship succeeds for spiffe profile",
			trustDomain: spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
			expFR: func() *datastore.FederationRelationship {
				// Build an in-memory bundle for the FR payload (matches sqlstore test intent).
				tdBundle := bundleutil.BundleProtoFromRootCAs("spiffe://federated-td-spiffe.org", nil)
				fr, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
					BundleEndpointURL:     RequireURLFromString(t, "federated-td-spiffe.org/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe.org/federated-server"),
					TrustDomainBundle:     (*common.Bundle)(tdBundle),
				})
				require.NoError(t, err)
				return fr
			}(),
		},
		{
			name:        "fetching an existent federation relationship succeeds for profile without bundle",
			trustDomain: spiffeid.RequireTrustDomainFromString("domain.test"),
			expFR: func() *datastore.FederationRelationship {
				fr, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("domain.test"),
					BundleEndpointURL:     RequireURLFromString(t, "https://domain.test/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://domain.test/federated-server"),
				})
				require.NoError(t, err)
				return fr
			}(),
		},
		{
			name:        "fetching a non-existent federation relationship returns nil",
			trustDomain: spiffeid.RequireTrustDomainFromString("non-existent-td.org"),
		},
		{
			name:   "fetching en empty trust domain fails nicely",
			expErr: "rpc error: code = InvalidArgument desc = trust domain is required",
		},
		{
			name:        "fetching a federation relationship with corrupted bundle endpoint URL fails nicely",
			expErr:      "rpc error: code = Unknown desc = unable to parse URL: parse \"not-valid-endpoint-url%\": invalid URL escape \"%\"",
			trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-bundle-endpoint-url.org"),
			expFR: func() *datastore.FederationRelationship { // returns nil on purpose
				raw := FederatedTrustDomainRaw{
					TrustDomain:           "corrupted-bundle-endpoint-url.org",
					BundleEndpointURL:     "not-valid-endpoint-url%",
					BundleEndpointProfile: string(datastore.BundleEndpointWeb),
				}
				require.NoError(t, createRaw(raw))
				return nil
			}(),
		},
		{
			name:        "fetching a federation relationship with corrupted bundle endpoint SPIFFE ID fails nicely",
			expErr:      "rpc error: code = Unknown desc = unable to parse bundle endpoint SPIFFE ID: scheme is missing or invalid",
			trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-bundle-endpoint-id.org"),
			expFR: func() *datastore.FederationRelationship { // returns nil on purpose
				raw := FederatedTrustDomainRaw{
					TrustDomain:           "corrupted-bundle-endpoint-id.org",
					BundleEndpointURL:     "corrupted-bundle-endpoint-id.org/bundleendpoint",
					BundleEndpointProfile: string(datastore.BundleEndpointSPIFFE),
					EndpointSPIFFEID:      "invalid-id",
				}
				require.NoError(t, createRaw(raw))
				return nil
			}(),
		},
		{
			name:        "fetching a federation relationship with corrupted type fails nicely",
			expErr:      "rpc error: code = Unknown desc = unknown bundle endpoint profile type: \"other\"",
			trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-endpoint-profile.org"),
			expFR: func() *datastore.FederationRelationship { // returns nil on purpose
				raw := FederatedTrustDomainRaw{
					TrustDomain:           "corrupted-endpoint-profile.org",
					BundleEndpointURL:     "corrupted-endpoint-profile.org/bundleendpoint",
					BundleEndpointProfile: "other",
				}
				require.NoError(t, createRaw(raw))
				return nil
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var td spiffeid.TrustDomain
			if (tc.trustDomain == spiffeid.TrustDomain{}) {
				// empty TD branch exercises error path
				fr, err := ds.FetchFederationRelationship(ctx, tc.trustDomain)
				if tc.expErr != "" {
					require.EqualError(t, err, tc.expErr)
					require.Nil(t, fr)
					return
				}
				require.NoError(t, err)
				AssertFederationRelationship(t, tc.expFR, fr)
				return
			}
			td = tc.trustDomain

			fr, err := ds.FetchFederationRelationship(ctx, td)
			if tc.expErr != "" {
				require.EqualError(t, err, tc.expErr)
				require.Nil(t, fr)
				return
			}
			require.NoError(t, err)
			AssertFederationRelationship(t, tc.expFR, fr)
		})
	}
}

func TestDeleteFederationRelationship(t *testing.T, ds datastore.DataStore) {
	ctx := context.Background()

	tests := []struct {
		name        string
		trustDomain spiffeid.TrustDomain
		expErr      string
		setupFn     func()
	}{
		{
			name:        "deleting an existent federation relationship succeeds",
			trustDomain: spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
			setupFn: func() {
				_, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
					BundleEndpointURL:     RequireURLFromString(t, "federated-td-web.org/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				})
				require.NoError(t, err)
			},
		},
		{
			name:        "deleting an unexistent federation relationship returns not found",
			trustDomain: spiffeid.RequireTrustDomainFromString("non-existent-td.org"),
			expErr:      "rpc error: code = NotFound desc = datastore-sql: record not found",
		},
		{
			name:   "deleting a federation relationship using an empty trust domain fails nicely",
			expErr: "rpc error: code = InvalidArgument desc = trust domain is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupFn != nil {
				tc.setupFn()
			}

			err := ds.DeleteFederationRelationship(ctx, tc.trustDomain)
			if tc.expErr != "" {
				require.EqualError(t, err, tc.expErr)
				return
			}
			require.NoError(t, err)

			fr, err := ds.FetchFederationRelationship(ctx, tc.trustDomain)
			require.NoError(t, err)
			require.Nil(t, fr)
		})
	}
}
