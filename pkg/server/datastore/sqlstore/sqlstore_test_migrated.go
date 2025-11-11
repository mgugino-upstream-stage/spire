package sqlstore

import (
	"context"
	"fmt"

	"github.com/spiffe/spire/pkg/server/datastore"
	dstest "github.com/spiffe/spire/pkg/server/datastore/test"
	"google.golang.org/grpc/codes"
)

func (s *PluginSuite) TestBundleCRUD() {
	dstest.TestBundleCRUD(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestCountBundles() {
	dstest.TestCountBundles(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestListBundlesWithPagination() {
	dstest.TestListBundlesWithPagination(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestCreateFederationRelationship() {
	dstest.TestCreateFederationRelationship(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestListFederationRelationships() {
	dstest.TestListFederationRelationships(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestUpdateFederationRelationship() {
	dstest.TestUpdateFederationRelationship(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestCreateJoinToken() {
	dstest.TestCreateJoinToken(s.T(), s.ds)
}

func (s *PluginSuite) TestCreateAndFetchJoinToken() {
	dstest.TestCreateAndFetchJoinToken(s.T(), s.ds)
}

func (s *PluginSuite) TestDeleteJoinToken() {
	dstest.TestDeleteJoinToken(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneJoinTokens() {
	dstest.TestPruneJoinTokens(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestSetBundle() {
	dstest.TestSetBundle(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestBundlePrune() {
	dstest.TestBundlePrune(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestCountAttestedNodes() {
	dstest.TestCountAttestedNodes(s.T(), s.ds)
}

func (s *PluginSuite) TestTaintX509CA() {
	dstest.TestTaintX509CA(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestRevokeX509CA() {
	dstest.TestRevokeX509CA(s.T(), s.ds, s.cert, s.cacert)
}

func (s *PluginSuite) TestTaintJWTKey() {
	dstest.TestTaintJWTKey(s.T(), s.ds)
}

func (s *PluginSuite) TestRevokeJWTKey() {
	dstest.TestRevokeJWTKey(s.T(), s.ds)
}

func (s *PluginSuite) TestCreateAttestedNode() {
	dstest.TestCreateAttestedNode(s.T(), s.ds)
}

func (s *PluginSuite) TestSetCAJournal() {
	dstest.TestSetCAJournal(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchCAJournal() {
	dstest.TestFetchCAJournal(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneCAJournal() {
	dstest.TestPruneCAJournal(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneAttestedExpiredNodes() {
	dstest.TestPruneAttestedExpiredNodes(s.T(), s.ds)
}

func (s *PluginSuite) TestDeleteAttestedNode() {
	dstest.TestDeleteAttestedNode(s.T(), s.ds)
}

func (s *PluginSuite) TestListAttestedNodeEvents() {
	dstest.TestListAttestedNodeEvents(s.T(), s.ds)
}

func (s *PluginSuite) TestPruneAttestedNodeEvents() {
	dstest.TestPruneAttestedNodeEvents(s.T(), s.ds)
}

func (s *PluginSuite) TestNodeSelectors() {
	dstest.TestNodeSelectors(s.T(), s.ds)
}

func (s *PluginSuite) TestListNodeSelectors() {
	dstest.TestListNodeSelectors(s.T(), s.ds)
}

func (s *PluginSuite) TestListAttestedNodes() {
	dstest.TestListAttestedNodes(s.T(), func() datastore.DataStore { return s.newPlugin() })
}

func (s *PluginSuite) TestUpdateAttestedNode() {
	dstest.TestUpdateAttestedNode(s.T(), func() datastore.DataStore { return s.newPlugin() })
}

func (s *PluginSuite) TestFetchAttestedNodeMissing() {
	dstest.TestFetchAttestedNodeMissing(s.T(), s.ds)
}

// wip
func (s *PluginSuite) TestFetchFederationRelationship() {
	// createRaw inserts a raw federated trust domain record into the SQL database.
	createRaw := func(r dstest.FederatedTrustDomainRaw) error {

		model := FederatedTrustDomain{
			TrustDomain:           r.TrustDomain,
			BundleEndpointURL:     r.BundleEndpointURL,
			BundleEndpointProfile: r.BundleEndpointProfile,
			EndpointSPIFFEID:      r.EndpointSPIFFEID,
		}

		return s.ds.db.Create(&model).Error
	}

	dstest.TestFetchFederationRelationship(s.T(), s.ds, createRaw)
}

// In your SQL provider test suite (package sqlstore_test)

func (s *PluginSuite) TestListNodeSelectorsGroupsBySpiffeID() {
	// SQL insertRaw uses the same row shape the old test expected.
	insertRaw := func(spiffeID, selectorType, selectorValue string) error {
		// Use the existing DB handle on s.ds.db.raw
		query := maybeRebind(
			s.ds.db.databaseType,
			"INSERT INTO node_resolver_map_entries (spiffe_id, type, value) VALUES (?, ?, ?)",
		)

		_, err := s.ds.db.raw.Exec(query, spiffeID, selectorType, selectorValue)
		return err
	}

	dstest.TestListNodeSelectorsGroupsBySpiffeID(s.T(), s.ds, insertRaw)
}

func (s *PluginSuite) TestDeleteFederationRelationship() {
	dstest.TestDeleteFederationRelationship(s.T(), s.ds)
}

// Having replicated yet

func (s *PluginSuite) TestListRegistrationEntriesWhenCruftRowsExist() {
	ctx := context.Background()

	// Wrap into shared helper; rawDeleteBaseAll reproduces the original direct DELETE:
	rawDeleteBaseAll := func() error {
		// This matches your original direct exec against "registered_entries".
		// We preserve the rows-affected check by converting it into an error on mismatch.
		res, err := s.ds.db.raw.Exec("DELETE FROM registered_entries")
		if err != nil {
			return err
		}
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rowsAffected != 1 {
			return fmt.Errorf("expected to delete 1 row from registered_entries, deleted %d", rowsAffected)
		}
		return nil
	}

	// Seed + verify via shared test (keeps business logic identical)
	dstest.TestListRegistrationEntriesWhenCruftRowsExist(s.T(), s.ds, rawDeleteBaseAll)

	// No extra assertions needed; the shared test performs the final list check:
	// resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	// s.Require().NoError(err)
	// s.Require().Empty(resp.Entries)
	_ = ctx // preserve original local variable; avoid unused warning if build tags differ
}

func (s *PluginSuite) TestListRegistrationEntries() {
	// Connection is never used, each test creates new connection to a different database
	s.ds.Close()

	// Delegate to shared dstest implementation which accepts a newDS factory
	dstest.TestListRegistrationEntries(s.T(), func() datastore.DataStore { return s.newPlugin() }, s.cert, s.cacert)

	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			PageSize: 0,
		},
	})
	s.RequireGRPCStatus(err, codes.InvalidArgument, "cannot paginate with pagesize = 0")
	s.Require().Nil(resp)

	resp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			Token:    "invalid int",
			PageSize: 10,
		},
	})
	s.Require().Error(err, "could not parse token 'invalid int'")
	s.Require().Nil(resp)

	resp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		BySelectors: &datastore.BySelectors{},
	})
	s.RequireGRPCStatus(err, codes.InvalidArgument, "cannot list by empty selector set")
	s.Require().Nil(resp)
}

func (s *PluginSuite) TestFetchInexistentRegistrationEntry() {
	dstest.TestFetchInexistentRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestRegistrationEntriesFederatesWithAgainstMissingBundle() {
	dstest.TestRegistrationEntriesFederatesWithAgainstMissingBundle(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestRegistrationEntriesFederatesWithSuccess() {
	dstest.TestRegistrationEntriesFederatesWithSuccess(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestDeleteBundleRestrictedByRegistrationEntries() {
	dstest.TestDeleteBundleRestrictedByRegistrationEntries(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestDeleteBundleDeleteRegistrationEntries() {
	dstest.TestDeleteBundleDeleteRegistrationEntries(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestDeleteBundleDissociateRegistrationEntries() {
	dstest.TestDeleteBundleDissociateRegistrationEntries(s.T(), s.ds, s.cert)
}

func (s *PluginSuite) TestCreateRegistrationEntry() {
	dstest.TestCreateRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestCreateOrReturnRegistrationEntry() {
	dstest.TestCreateOrReturnRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestCreateInvalidRegistrationEntry() {
	dstest.TestCreateInvalidRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchRegistrationEntry() {
	dstest.TestFetchRegistrationEntry(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchRegistrationEntryDoesNotExist() {
	dstest.TestFetchRegistrationEntryDoesNotExist(s.T(), s.ds)
}

func (s *PluginSuite) TestFetchRegistrationEntries() {
	dstest.TestFetchRegistrationEntries(s.T(), s.ds)
}

func (s *PluginSuite) TestCountRegistrationEntries() {
	dstest.TestCountRegistrationEntries(s.T(), s.ds)
}
