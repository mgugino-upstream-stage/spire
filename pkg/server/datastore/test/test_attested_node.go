package dstest

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
)

// TestCreateAttestedNode tests creating and fetching an attested node.
func TestCreateAttestedNode(t *testing.T, ds datastore.DataStore) {
	node := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	attestedNode, err := ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)
	assert.Equal(t, node, attestedNode)

	attestedNode, err = ds.FetchAttestedNode(ctx, node.SpiffeId)
	require.NoError(t, err)
	assert.Equal(t, node, attestedNode)
}

// TestFetchAttestedNodeMissing verifies fetching a missing attested node returns nil.
func TestFetchAttestedNodeMissing(t *testing.T, ds datastore.DataStore) {
	attestedNode, err := ds.FetchAttestedNode(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, attestedNode)
}

// TestListAttestedNodes exercises listing attested nodes with many filters and pagination.
// TestListAttestedNodes runs the full matrix of list tests. It accepts newDS
// factory which should return a fresh datastore instance for each inner test
// to guarantee isolation (the SQL plugin tests call s.newPlugin for this).
func TestListAttestedNodes(t *testing.T, newDS func() datastore.DataStore) {
	// This test uses helper functions MakeID, MakeSelectors, BySelectors, and AssertSelectorsEqual
	now := time.Now()
	expired := now.Add(-time.Hour)
	unexpired := now.Add(time.Hour)

	makeAttestedNode := func(spiffeIDSuffix, attestationType string, notAfter time.Time, sn string, canReattest bool, selectors ...string) *common.AttestedNode {
		return &common.AttestedNode{
			SpiffeId:            MakeID(spiffeIDSuffix),
			AttestationDataType: attestationType,
			CertSerialNumber:    sn,
			CertNotAfter:        notAfter.Unix(),
			CanReattest:         canReattest,
			Selectors:           MakeSelectors(selectors...),
		}
	}

	banned := ""
	bannedFalse := false
	bannedTrue := true
	unbanned := "IRRELEVANT"

	canReattestFalse := false
	canReattestTrue := true

	nodeA := makeAttestedNode("A", "T1", expired, unbanned, false, "S1")
	nodeB := makeAttestedNode("B", "T2", expired, unbanned, false, "S1")
	nodeC := makeAttestedNode("C", "T1", expired, unbanned, false, "S2")
	nodeD := makeAttestedNode("D", "T2", expired, unbanned, false, "S2")
	nodeE := makeAttestedNode("E", "T1", unexpired, banned, false, "S1", "S2")
	nodeF := makeAttestedNode("F", "T2", unexpired, banned, false, "S1", "S3")
	nodeG := makeAttestedNode("G", "T1", unexpired, banned, false, "S2", "S3")
	nodeH := makeAttestedNode("H", "T2", unexpired, banned, false, "S2", "S3")
	nodeI := makeAttestedNode("I", "T1", unexpired, unbanned, true, "S1")
	nodeJ := makeAttestedNode("J", "T1", now, unbanned, false, "S1", "S2")

	for _, tt := range []struct {
		test                string
		nodes               []*common.AttestedNode
		pageSize            int32
		byExpiresBefore     time.Time
		byValidAt           time.Time
		byAttestationType   string
		bySelectors         *datastore.BySelectors
		byBanned            *bool
		byCanReattest       *bool
		expectNodesOut      []*common.AttestedNode
		expectPagedTokensIn []string
		expectPagedNodesOut [][]*common.AttestedNode
	}{
		{
			test:                "without attested nodes",
			expectNodesOut:      []*common.AttestedNode{},
			expectPagedTokensIn: []string{""},
			expectPagedNodesOut: [][]*common.AttestedNode{{}},
		},
		{
			test:                "with partial page",
			nodes:               []*common.AttestedNode{nodeA},
			pageSize:            2,
			expectNodesOut:      []*common.AttestedNode{nodeA},
			expectPagedTokensIn: []string{"", "1"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {}},
		},
		{
			test:                "with full page",
			nodes:               []*common.AttestedNode{nodeA, nodeB},
			pageSize:            2,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB},
			expectPagedTokensIn: []string{"", "2"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA, nodeB}, {}},
		},
		{
			test:                "with page and a half",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC},
			pageSize:            2,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeC},
			expectPagedTokensIn: []string{"", "2", "3"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA, nodeB}, {nodeC}, {}},
		},
		// By expiration
		{
			test:                "by expires before",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeB, nodeF, nodeG, nodeC},
			byExpiresBefore:     now,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeC},
			expectPagedTokensIn: []string{"", "1", "3", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeC}, {}},
		},
		{
			test:                "by valid at",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeJ},
			byValidAt:           now.Add(-time.Minute),
			expectNodesOut:      []*common.AttestedNode{nodeE, nodeJ},
			expectPagedTokensIn: []string{"", "2", "3"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeE}, {nodeJ}, {}},
		},
		// By attestation type
		{
			test:                "by attestation type",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE},
			byAttestationType:   "T1",
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeC, nodeE},
			expectPagedTokensIn: []string{"", "1", "3", "5"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeC}, {nodeE}, {}},
		},
		// By banned
		{
			test:                "by banned",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			byBanned:            &bannedTrue,
			expectNodesOut:      []*common.AttestedNode{nodeE, nodeF},
			expectPagedTokensIn: []string{"", "2", "3"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeE}, {nodeF}, {}},
		},
		{
			test:                "by unbanned",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			byBanned:            &bannedFalse,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB},
			expectPagedTokensIn: []string{"", "1", "4"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {}},
		},
		{
			test:                "banned undefined",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			byBanned:            nil,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			expectPagedTokensIn: []string{"", "1", "2", "3", "4"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeE}, {nodeF}, {nodeB}, {}},
		},
		// By selector subset
		{
			test:                "by selector subset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         BySelectors(datastore.Subset, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB},
			expectPagedTokensIn: []string{"", "1", "2"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {}},
		},
		{
			test:                "by selectors subset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         BySelectors(datastore.Subset, "S1", "S3"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeF},
			expectPagedTokensIn: []string{"", "1", "2", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeF}, {}},
		},
		// By exact selector exact
		{
			test:                "by selector exact",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         BySelectors(datastore.Exact, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB},
			expectPagedTokensIn: []string{"", "1", "2"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {}},
		},
		{
			test:                "by selectors exact",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         BySelectors(datastore.Exact, "S1", "S3"),
			expectNodesOut:      []*common.AttestedNode{nodeF},
			expectPagedTokensIn: []string{"", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeF}, {}},
		},
		// By exact selector match any
		{
			test:                "by selector match any",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         BySelectors(datastore.MatchAny, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF},
			expectPagedTokensIn: []string{"", "1", "2", "5", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeE}, {nodeF}, {}},
		},
		{
			test:                "by selectors match any",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         BySelectors(datastore.MatchAny, "S1", "S3"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF, nodeG, nodeH},
			expectPagedTokensIn: []string{"", "1", "2", "5", "6", "7", "8"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeE}, {nodeF}, {nodeG}, {nodeH}, {}},
		},
		// By exact selector superset
		{
			test:                "by selector superset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         BySelectors(datastore.Superset, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF},
			expectPagedTokensIn: []string{"", "1", "2", "5", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeE}, {nodeF}, {}},
		},
		{
			test:                "by selectors superset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         BySelectors(datastore.Superset, "S1", "S2"),
			expectNodesOut:      []*common.AttestedNode{nodeE},
			expectPagedTokensIn: []string{"", "5"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeE}, {}},
		},
		// By CanReattest=true
		{
			test:                "by CanReattest=true",
			nodes:               []*common.AttestedNode{nodeA, nodeI},
			byAttestationType:   "T1",
			bySelectors:         nil,
			byCanReattest:       &canReattestTrue,
			expectNodesOut:      []*common.AttestedNode{nodeI},
			expectPagedTokensIn: []string{"", "2"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeI}, {}},
		},
		// By CanReattest=false
		{
			test:                "by CanReattest=false",
			nodes:               []*common.AttestedNode{nodeA, nodeI},
			byAttestationType:   "T1",
			bySelectors:         nil,
			byCanReattest:       &canReattestFalse,
			expectNodesOut:      []*common.AttestedNode{nodeA},
			expectPagedTokensIn: []string{"", "1"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {}},
		},
		// By attestation type and selector subset. This is to exercise some
		// of the logic that combines these parts of the queries together to
		// make sure they glom well.
		{
			test:                "by attestation type and selector subset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE},
			byAttestationType:   "T1",
			bySelectors:         BySelectors(datastore.Subset, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA},
			expectPagedTokensIn: []string{"", "1"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {}},
		},
		// Exercise all filters together
		{
			test:                "all filters",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeB, nodeF, nodeG, nodeC},
			byBanned:            &bannedFalse,
			byExpiresBefore:     now,
			byAttestationType:   "T1",
			bySelectors:         BySelectors(datastore.Subset, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA},
			expectPagedTokensIn: []string{"", "1"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {}},
			byCanReattest:       &canReattestFalse,
		},
	} {
		for _, withPagination := range []bool{true, false} {
			for _, withSelectors := range []bool{true, false} {
				name := tt.test
				if withSelectors {
					name += " with selectors"
				} else {
					name += " without selectors"
				}
				if withPagination {
					name += " with pagination"
				} else {
					name += " without pagination"
				}
				t.Run(name, func(t *testing.T) {
					// Create a fresh datastore for this run to mirror sqlstore behavior.
					ds := newDS()
					if closer, ok := ds.(interface{ Close() }); ok {
						defer closer.Close()
					}

					// Create entries for the test.
					for _, node := range tt.nodes {
						_, err := ds.CreateAttestedNode(ctx, node)
						require.NoError(t, err)
						err = ds.SetNodeSelectors(ctx, node.SpiffeId, node.Selectors)
						require.NoError(t, err)
					}

					var pagination *datastore.Pagination
					if withPagination {
						pagination = &datastore.Pagination{
							PageSize: tt.pageSize,
						}
						if pagination.PageSize == 0 {
							pagination.PageSize = 1
						}
					}

					var tokensIn []string
					var actualIDsOut [][]string
					actualSelectorsOut := make(map[string][]*common.Selector)
					req := &datastore.ListAttestedNodesRequest{
						Pagination:        pagination,
						ByExpiresBefore:   tt.byExpiresBefore,
						ValidAt:           tt.byValidAt,
						ByAttestationType: tt.byAttestationType,
						BySelectorMatch:   tt.bySelectors,
						ByBanned:          tt.byBanned,
						ByCanReattest:     tt.byCanReattest,
						FetchSelectors:    withSelectors,
					}

					for i := 0; ; i++ {
						if i > len(tt.nodes) {
							require.FailNowf(t, "Exhausted paging limit in test", "tokens=%q spiffeids=%q", tokensIn, actualIDsOut)
						}
						if req.Pagination != nil {
							tokensIn = append(tokensIn, req.Pagination.Token)
						}
						resp, err := ds.ListAttestedNodes(ctx, req)
						require.NoError(t, err)
						require.NotNil(t, resp)
						if withPagination {
							require.NotNil(t, resp.Pagination, "response missing pagination")
							assert.Equal(t, req.Pagination.PageSize, resp.Pagination.PageSize, "response page size did not match request")
						} else {
							require.Nil(t, resp.Pagination, "response has pagination")
						}

						var idSet []string
						for _, node := range resp.Nodes {
							idSet = append(idSet, node.SpiffeId)
							actualSelectorsOut[node.SpiffeId] = node.Selectors
						}
						actualIDsOut = append(actualIDsOut, idSet)

						if resp.Pagination == nil || resp.Pagination.Token == "" {
							break
						}
						req.Pagination = resp.Pagination
					}

					expectNodesOut := tt.expectPagedNodesOut
					if !withPagination {
						expectNodesOut = [][]*common.AttestedNode{tt.expectNodesOut}
					}

					var expectIDsOut [][]string
					expectSelectorsOut := make(map[string][]*common.Selector)
					for _, nodeSet := range expectNodesOut {
						var idSet []string
						for _, node := range nodeSet {
							idSet = append(idSet, node.SpiffeId)
							if withSelectors {
								expectSelectorsOut[node.SpiffeId] = node.Selectors
							}
						}
						expectIDsOut = append(expectIDsOut, idSet)
					}

					if withPagination {
						assert.Equal(t, tt.expectPagedTokensIn, tokensIn, "unexpected request tokens")
					} else {
						assert.Empty(t, tokensIn, "unexpected request tokens")
					}
					assert.Equal(t, expectIDsOut, actualIDsOut, "unexpected response nodes")
					AssertSelectorsEqual(t, expectSelectorsOut, actualSelectorsOut, "unexpected response selectors")
				})
			}
		}
	}
}

// TestUpdateAttestedNode tests update semantics with masks.
// Accepts newDS factory to provide a fresh datastore instance per subtest for isolation.
func TestUpdateAttestedNode(t *testing.T, newDS func() datastore.DataStore) {
	nodeID := "spiffe-id"
	attestationType := "attestation-data-type"
	serial := "cert-serial-number-1"
	expires := int64(1)
	newSerial := "new-cert-serial-number"
	newExpires := int64(2)

	updatedSerial := "cert-serial-number-2"
	updatedExpires := int64(3)
	updatedNewSerial := ""
	updatedNewExpires := int64(0)

	for _, tt := range []struct {
		name           string
		updateNode     *common.AttestedNode
		updateNodeMask *common.AttestedNodeMask
		expUpdatedNode *common.AttestedNode
		expCode        int
		expMsg         string
	}{
		{
			name: "update non-existing attested node",
			updateNode: &common.AttestedNode{
				SpiffeId:         "non-existent-node-id",
				CertSerialNumber: updatedSerial,
				CertNotAfter:     updatedExpires,
			},
			// Expect an error for not found; backend-specific error translation
			expCode: 1,
		},
		{
			name: "update attested node with all false mask",
			updateNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
			},
			updateNodeMask: &common.AttestedNodeMask{},
			expUpdatedNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				AttestationDataType: attestationType,
				CertSerialNumber:    serial,
				CertNotAfter:        expires,
				NewCertNotAfter:     newExpires,
				NewCertSerialNumber: newSerial,
			},
		},
		{
			name: "update attested node with mask set only some fields: 'CertSerialNumber', 'NewCertNotAfter'",
			updateNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
			},
			updateNodeMask: &common.AttestedNodeMask{
				CertSerialNumber: true,
				NewCertNotAfter:  true,
			},
			expUpdatedNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				AttestationDataType: attestationType,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        expires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: newSerial,
			},
		},
		{
			name: "update attested node with nil mask",
			updateNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
			},
			expUpdatedNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				AttestationDataType: attestationType,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ds := newDS()
			if closer, ok := ds.(interface{ Close() }); ok {
				defer closer.Close()
			}

			_, err := ds.CreateAttestedNode(ctx, &common.AttestedNode{
				SpiffeId:            nodeID,
				AttestationDataType: attestationType,
				CertSerialNumber:    serial,
				CertNotAfter:        expires,
				NewCertNotAfter:     newExpires,
				NewCertSerialNumber: newSerial,
			})
			require.NoError(t, err)

			// Update attested node
			updatedNode, err := ds.UpdateAttestedNode(ctx, tt.updateNode, tt.updateNodeMask)
			if tt.expCode != 0 {
				// Expect an error code
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, updatedNode)
			require.Equal(t, tt.expUpdatedNode, updatedNode)

			// Check a fresh fetch shows the updated attested node
			attestedNode, err := ds.FetchAttestedNode(ctx, tt.updateNode.SpiffeId)
			require.NoError(t, err)
			require.NotNil(t, attestedNode)
			require.Equal(t, tt.expUpdatedNode, attestedNode)
		})
	}
}

// TestPruneAttestedExpiredNodes copies the prune tests for expired attested nodes.
func TestPruneAttestedExpiredNodes(t *testing.T, ds datastore.DataStore) {
	clk := clock.NewMock(t)
	now := clk.Now()

	nodes := map[string]*common.AttestedNode{
		"valid": {
			SpiffeId:            "valid",
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CanReattest:         true,
			CertNotAfter:        now.Add(time.Hour).Unix(),
		},
		"expired": {
			SpiffeId:            "expired",
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CanReattest:         true,
			CertNotAfter:        now.Add(-time.Hour).Unix(),
		},
		"expired-banned": {
			SpiffeId:            "expired-banned",
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "",
			CanReattest:         true,
			CertNotAfter:        now.Add(-time.Hour).Unix(),
		},
		"expired-non-reattestable": {
			SpiffeId:            "expired-non-reattestable",
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CanReattest:         false,
			CertNotAfter:        now.Add(-time.Hour).Unix(),
		},
	}
	selectors := []*common.Selector{{Type: "TYPE", Value: "VALUE"}}

	for _, node := range nodes {
		_, err := ds.CreateAttestedNode(ctx, node)
		require.NoError(t, err)
		err = ds.SetNodeSelectors(ctx, node.SpiffeId, selectors)
		require.NoError(t, err)
	}

	// prune before expiry: nothing should be deleted
	err := ds.PruneAttestedExpiredNodes(ctx, now.Add(-time.Hour), false)
	require.NoError(t, err)
	for _, node := range nodes {
		attestedNode, err := ds.FetchAttestedNode(ctx, node.SpiffeId)
		require.NoError(t, err)
		require.NotNil(t, attestedNode)
	}

	// prune expired attested nodes (default behavior)
	err = ds.PruneAttestedExpiredNodes(ctx, now.Add(-time.Minute), false)
	require.NoError(t, err)

	// valid node should be present
	attestedValidNode, err := ds.FetchAttestedNode(ctx, nodes["valid"].SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, attestedValidNode)

	attestedExpiredNode, err := ds.FetchAttestedNode(ctx, nodes["expired"].SpiffeId)
	require.NoError(t, err)
	require.Nil(t, attestedExpiredNode)

	deletedExpiredNodeSelectors, err := ds.GetNodeSelectors(ctx, nodes["expired"].SpiffeId, datastore.RequireCurrent)
	require.NoError(t, err)
	require.Nil(t, deletedExpiredNodeSelectors)

	attestedNotReattestableNode, err := ds.FetchAttestedNode(ctx, nodes["expired-non-reattestable"].SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, attestedNotReattestableNode)

	attestedBannedNode, err := ds.FetchAttestedNode(ctx, nodes["expired-banned"].SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, attestedBannedNode)

	// prune expired attested nodes including non-reattestable nodes
	err = ds.PruneAttestedExpiredNodes(ctx, now.Add(-time.Minute), true)
	require.NoError(t, err)

	attestedNotReattestableNode, err = ds.FetchAttestedNode(ctx, nodes["expired-non-reattestable"].SpiffeId)
	require.NoError(t, err)
	require.Nil(t, attestedNotReattestableNode)

	deletedExpiredNonReattestableNodeSelectors, err := ds.GetNodeSelectors(ctx, nodes["expired-non-reattestable"].SpiffeId, datastore.RequireCurrent)
	require.NoError(t, err)
	require.Nil(t, deletedExpiredNonReattestableNodeSelectors)

	attestedBannedNode, err = ds.FetchAttestedNode(ctx, nodes["expired-banned"].SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, attestedBannedNode)
}

// TestDeleteAttestedNode tests deletion semantics and selector cleanup.
func TestDeleteAttestedNode(t *testing.T, ds datastore.DataStore) {
	entryFoo := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}
	entryBar := &common.AttestedNode{
		SpiffeId:            "bar",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	// delete non-existing
	_, err := ds.DeleteAttestedNode(ctx, entryFoo.SpiffeId)
	require.Error(t, err)

	// delete without selectors
	_, err = ds.CreateAttestedNode(ctx, entryFoo)
	require.NoError(t, err)

	deletedNode, err := ds.DeleteAttestedNode(ctx, entryFoo.SpiffeId)
	require.NoError(t, err)
	assert.Equal(t, entryFoo, deletedNode)

	attestedNode, err := ds.FetchAttestedNode(ctx, entryFoo.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, attestedNode)

	// delete with selectors
	selectors := []*common.Selector{{Type: "TYPE1", Value: "VALUE1"}, {Type: "TYPE2", Value: "VALUE2"}}
	_, err = ds.CreateAttestedNode(ctx, entryFoo)
	require.NoError(t, err)
	require.NoError(t, ds.SetNodeSelectors(ctx, entryFoo.SpiffeId, selectors))
	require.NoError(t, ds.SetNodeSelectors(ctx, entryBar.SpiffeId, selectors))

	nodeSelectors, err := ds.GetNodeSelectors(ctx, entryFoo.SpiffeId, datastore.RequireCurrent)
	require.NoError(t, err)
	assert.Equal(t, selectors, nodeSelectors)

	deletedNode, err = ds.DeleteAttestedNode(ctx, entryFoo.SpiffeId)
	require.NoError(t, err)
	assert.Equal(t, entryFoo, deletedNode)

	attestedNode, err = ds.FetchAttestedNode(ctx, deletedNode.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, attestedNode)

	deletedSelectors, err := ds.GetNodeSelectors(ctx, deletedNode.SpiffeId, datastore.RequireCurrent)
	require.NoError(t, err)
	require.Nil(t, deletedSelectors)

	nodeSelectors, err = ds.GetNodeSelectors(ctx, entryBar.SpiffeId, datastore.RequireCurrent)
	require.NoError(t, err)
	assert.Equal(t, selectors, nodeSelectors)
}

// TestListAttestedNodeEvents tests attested node event listing and filtering.
func TestListAttestedNodeEvents(t *testing.T, ds datastore.DataStore) {
	var expectedEvents []datastore.AttestedNodeEvent

	node1, err := ds.CreateAttestedNode(ctx, &common.AttestedNode{SpiffeId: "foo", AttestationDataType: "aws-tag", CertSerialNumber: "badcafe", CertNotAfter: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	expectedEvents = append(expectedEvents, datastore.AttestedNodeEvent{EventID: 1, SpiffeID: node1.SpiffeId})

	selectors1 := []*common.Selector{{Type: "FOO1", Value: "1"}}
	require.NoError(t, ds.SetNodeSelectors(ctx, node1.SpiffeId, selectors1))
	expectedEvents = append(expectedEvents, datastore.AttestedNodeEvent{EventID: 2, SpiffeID: node1.SpiffeId})

	node2, err := ds.CreateAttestedNode(ctx, &common.AttestedNode{SpiffeId: "bar", AttestationDataType: "aws-tag", CertSerialNumber: "badcafe", CertNotAfter: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	expectedEvents = append(expectedEvents, datastore.AttestedNodeEvent{EventID: 3, SpiffeID: node2.SpiffeId})

	selectors2 := []*common.Selector{{Type: "BAR1", Value: "1"}}
	require.NoError(t, ds.SetNodeSelectors(ctx, node2.SpiffeId, selectors2))
	expectedEvents = append(expectedEvents, datastore.AttestedNodeEvent{EventID: 4, SpiffeID: node2.SpiffeId})

	updatedNode, err := ds.UpdateAttestedNode(ctx, node1, nil)
	require.NoError(t, err)
	expectedEvents = append(expectedEvents, datastore.AttestedNodeEvent{EventID: 5, SpiffeID: updatedNode.SpiffeId})

	updatedSelectors := []*common.Selector{{Type: "FOO2", Value: "2"}}
	require.NoError(t, ds.SetNodeSelectors(ctx, updatedNode.SpiffeId, updatedSelectors))
	expectedEvents = append(expectedEvents, datastore.AttestedNodeEvent{EventID: 6, SpiffeID: updatedNode.SpiffeId})

	deletedNode, err := ds.DeleteAttestedNode(ctx, node2.SpiffeId)
	require.NoError(t, err)
	expectedEvents = append(expectedEvents, datastore.AttestedNodeEvent{EventID: 7, SpiffeID: deletedNode.SpiffeId})

	require.NoError(t, ds.SetNodeSelectors(ctx, deletedNode.SpiffeId, nil))
	expectedEvents = append(expectedEvents, datastore.AttestedNodeEvent{EventID: 8, SpiffeID: deletedNode.SpiffeId})

	tests := []struct {
		name                 string
		greaterThanEventID   uint
		lessThanEventID      uint
		expectedEvents       []datastore.AttestedNodeEvent
		expectedFirstEventID uint
		expectedLastEventID  uint
		expectedErr          string
	}{
		{name: "All Events", greaterThanEventID: 0, expectedFirstEventID: 1, expectedLastEventID: uint(len(expectedEvents)), expectedEvents: expectedEvents},
		{name: "Greater than half of the Events", greaterThanEventID: uint(len(expectedEvents) / 2), expectedFirstEventID: uint(len(expectedEvents)/2) + 1, expectedLastEventID: uint(len(expectedEvents)), expectedEvents: expectedEvents[len(expectedEvents)/2:]},
		{name: "Less than half of the Events", lessThanEventID: uint(len(expectedEvents) / 2), expectedFirstEventID: 1, expectedLastEventID: uint(len(expectedEvents)/2) - 1, expectedEvents: expectedEvents[:len(expectedEvents)/2-1]},
		{name: "Greater than largest Event ID", greaterThanEventID: uint(len(expectedEvents)), expectedEvents: []datastore.AttestedNodeEvent{}},
		{name: "Setting both greater and less than", greaterThanEventID: 1, lessThanEventID: 1, expectedErr: "datastore-sql: can't set both greater and less than event id"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, err := ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{GreaterThanEventID: test.greaterThanEventID, LessThanEventID: test.lessThanEventID})
			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expectedEvents, resp.Events)
			if len(resp.Events) > 0 {
				require.Equal(t, test.expectedFirstEventID, resp.Events[0].EventID)
				require.Equal(t, test.expectedLastEventID, resp.Events[len(resp.Events)-1].EventID)
			}
		})
	}
}

// TestPruneAttestedNodeEvents tests pruning of attested node events.
func TestPruneAttestedNodeEvents(t *testing.T, ds datastore.DataStore) {
	node, err := ds.CreateAttestedNode(ctx, &common.AttestedNode{SpiffeId: "foo", AttestationDataType: "aws-tag", CertSerialNumber: "badcafe", CertNotAfter: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)

	resp, err := ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
	require.NoError(t, err)
	require.Equal(t, node.SpiffeId, resp.Events[0].SpiffeID)

	for _, tt := range []struct {
		name           string
		olderThan      time.Duration
		expectedEvents []datastore.AttestedNodeEvent
	}{
		{name: "Don't prune valid events", olderThan: 1 * time.Hour, expectedEvents: []datastore.AttestedNodeEvent{{EventID: 1, SpiffeID: node.SpiffeId}}},
		{name: "Prune old events", olderThan: 0 * time.Second, expectedEvents: []datastore.AttestedNodeEvent{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err = ds.PruneAttestedNodeEvents(ctx, tt.olderThan)
			require.NoError(t, err)

			resp, err := ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedEvents, resp.Events)
		})
	}
}

// TestNodeSelectors tests node selectors CRUD.
func TestNodeSelectors(t *testing.T, ds datastore.DataStore) {
	foo1 := []*common.Selector{{Type: "FOO1", Value: "1"}}
	foo2 := []*common.Selector{{Type: "FOO2", Value: "1"}}
	bar := []*common.Selector{{Type: "BAR", Value: "FIGHT"}}

	selectors := dsGetNodeSelectors(t, ds, "foo")
	require.Empty(t, selectors)

	require.NoError(t, ds.SetNodeSelectors(ctx, "foo", foo1))
	require.NoError(t, ds.SetNodeSelectors(ctx, "bar", bar))

	selectors = dsGetNodeSelectors(t, ds, "foo")
	assert.Equal(t, foo1, selectors)

	require.NoError(t, ds.SetNodeSelectors(ctx, "foo", foo2))
	selectors = dsGetNodeSelectors(t, ds, "foo")
	assert.Equal(t, foo2, selectors)

	require.NoError(t, ds.SetNodeSelectors(ctx, "foo", []*common.Selector{}))
	selectors = dsGetNodeSelectors(t, ds, "foo")
	require.Empty(t, selectors)

	selectors = dsGetNodeSelectors(t, ds, "bar")
	assert.Equal(t, bar, selectors)
}

// TestListNodeSelectors and related functions are exercised in separate helpers
func TestListNodeSelectors(t *testing.T, ds datastore.DataStore) {
	// Lightweight checks to ensure listing selectors works; the heavy cases are exercised at plugin level
	resp := dsListNodeSelectors(t, ds, &datastore.ListNodeSelectorsRequest{})
	AssertSelectorsEqual(t, nil, resp.Selectors)
}

// TestListNodeSelectorsWithEntries creates several attested nodes and selectors and validates listing
func TestListNodeSelectorsWithEntries(t *testing.T, ds datastore.DataStore) {
	const numNonExpiredAttNodes = 3
	const attestationDataType = "fake_nodeattestor"
	now := time.Now()

	var allAttNodesToCreate []*common.AttestedNode
	for i := 0; i < numNonExpiredAttNodes; i++ {
		n := &common.AttestedNode{
			SpiffeId:            MakeID(fmt.Sprintf("non-expired-node-%d", i)),
			AttestationDataType: attestationDataType,
			CertSerialNumber:    fmt.Sprintf("non-expired serial %d-1", i),
			CertNotAfter:        now.Add(time.Hour).Unix(),
			NewCertSerialNumber: fmt.Sprintf("non-expired serial %d-2", i),
			NewCertNotAfter:     now.Add(2 * time.Hour).Unix(),
		}
		allAttNodesToCreate = append(allAttNodesToCreate, n)
	}

	// expired nodes
	for i := 0; i < 2; i++ {
		n := &common.AttestedNode{
			SpiffeId:            MakeID(fmt.Sprintf("expired-node-%d", i)),
			AttestationDataType: attestationDataType,
			CertSerialNumber:    fmt.Sprintf("expired serial %d-1", i),
			CertNotAfter:        now.Add(-24 * time.Hour).Unix(),
			NewCertSerialNumber: fmt.Sprintf("expired serial %d-2", i),
			NewCertNotAfter:     now.Add(-12 * time.Hour).Unix(),
		}
		allAttNodesToCreate = append(allAttNodesToCreate, n)
	}

	selectorMap := make(map[string][]*common.Selector)
	for i, n := range allAttNodesToCreate {
		_, err := ds.CreateAttestedNode(ctx, n)
		require.NoError(t, err)
		selectors := []*common.Selector{{Type: "foo", Value: fmt.Sprintf("%d", i)}}
		require.NoError(t, ds.SetNodeSelectors(ctx, n.SpiffeId, selectors))
		selectorMap[n.SpiffeId] = selectors
	}

	resp := dsListNodeSelectors(t, ds, &datastore.ListNodeSelectorsRequest{})
	AssertSelectorsEqual(t, selectorMap, resp.Selectors)
}

// Helper shims that call datastore methods and wrap results for tests
func dsGetNodeSelectors(t *testing.T, ds datastore.DataStore, spiffeID string) []*common.Selector {
	selectors, err := ds.GetNodeSelectors(ctx, spiffeID, datastore.TolerateStale)
	require.NoError(t, err)
	return selectors
}

func dsListNodeSelectors(t *testing.T, ds datastore.DataStore, req *datastore.ListNodeSelectorsRequest) *datastore.ListNodeSelectorsResponse {
	resp, err := ds.ListNodeSelectors(ctx, req)
	require.NoError(t, err)
	return resp
}

// Exported helper utilities used by attested node tests
func MakeSelectors(vs ...string) []*common.Selector {
	var ss []*common.Selector
	for _, v := range vs {
		ss = append(ss, &common.Selector{Type: v, Value: v})
	}
	return ss
}

func BySelectors(match datastore.MatchBehavior, ss ...string) *datastore.BySelectors {
	return &datastore.BySelectors{Match: match, Selectors: MakeSelectors(ss...)}
}

func MakeID(suffix string) string {
	return "spiffe://example.org/" + suffix
}

// AssertSelectorsEqual compares two selector maps for equality
func AssertSelectorsEqual(t *testing.T, expected, actual map[string][]*common.Selector, msgAndArgs ...any) {
	type selector struct{ Type, Value string }
	convert := func(in map[string][]*common.Selector) map[string][]selector {
		out := make(map[string][]selector)
		for spiffeID, selectors := range in {
			for _, s := range selectors {
				out[spiffeID] = append(out[spiffeID], selector{Type: s.Type, Value: s.Value})
			}
		}
		return out
	}
	assert.Equal(t, convert(expected), convert(actual), msgAndArgs...)
}

// In package dstest

func TestListNodeSelectorsGroupsBySpiffeID(
	t *testing.T,
	ds datastore.DataStore,
	insertRaw func(spiffeID, selectorType, selectorValue string) error,
) {
	// Insert selectors out of order with respect to SPIFFE ID so the
	// datastore must group/aggregate correctly by spiffe_id.
	require.NoError(t, insertRaw("spiffe://example.org/node3", "A", "a"))
	require.NoError(t, insertRaw("spiffe://example.org/node2", "B", "b"))
	require.NoError(t, insertRaw("spiffe://example.org/node3", "C", "c"))
	require.NoError(t, insertRaw("spiffe://example.org/node1", "D", "d"))
	require.NoError(t, insertRaw("spiffe://example.org/node2", "E", "e"))
	require.NoError(t, insertRaw("spiffe://example.org/node3", "F", "f"))

	resp, err := ds.ListNodeSelectors(ctx, &datastore.ListNodeSelectorsRequest{})
	require.NoError(t, err)

	AssertSelectorsEqual(t, map[string][]*common.Selector{
		"spiffe://example.org/node1": {{Type: "D", Value: "d"}},
		"spiffe://example.org/node2": {{Type: "B", Value: "b"}, {Type: "E", Value: "e"}},
		"spiffe://example.org/node3": {{Type: "A", Value: "a"}, {Type: "C", Value: "c"}, {Type: "F", Value: "f"}},
	}, resp.Selectors)
}
