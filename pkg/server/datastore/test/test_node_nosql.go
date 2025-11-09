package dstest

import (
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListAttestedNodesWithPaginationNoSQL validates pagination behavior using the
// Cassandra driver's token model (count-so-far) without asserting exact token
// sequences. It pages until token == "" and validates the collected results.
// It also exercises a few key filters (expiresBefore, validAt, selectors).
func TestListAttestedNodesWithPaginationNoSQL(t *testing.T, newDS func() datastore.DataStore) {
	now := time.Now()
	expired := now.Add(-time.Hour)
	unexpired := now.Add(time.Hour)

	makeNode := func(suffix, attType string, notAfter time.Time, serial string, canReattest bool, sels ...string) *common.AttestedNode {
		return &common.AttestedNode{
			SpiffeId:            MakeID(suffix),
			AttestationDataType: attType,
			CertSerialNumber:    serial,
			CertNotAfter:        notAfter.Unix(),
			CanReattest:         canReattest,
			Selectors:           MakeSelectors(sels...),
		}
	}

	// Fixtures (same shape as in the original tests)
	banned := ""
	unbanned := "IRRELEVANT"

	nodeA := makeNode("A", "T1", expired, unbanned, false, "S1")
	nodeB := makeNode("B", "T2", expired, unbanned, false, "S1")
	nodeC := makeNode("C", "T1", expired, unbanned, false, "S2")
	nodeD := makeNode("D", "T2", expired, unbanned, false, "S2")
	nodeE := makeNode("E", "T1", unexpired, banned, false, "S1", "S2")
	nodeF := makeNode("F", "T2", unexpired, banned, false, "S1", "S3")
	nodeG := makeNode("G", "T1", unexpired, banned, false, "S2", "S3")
	nodeH := makeNode("H", "T2", unexpired, banned, false, "S2", "S3")
	nodeI := makeNode("I", "T1", unexpired, unbanned, true, "S1")
	nodeJ := makeNode("J", "T1", now, unbanned, false, "S1", "S2")

	type pageCase struct {
		name              string
		nodes             []*common.AttestedNode
		pageSize          int32
		fetchSelectors    bool
		byExpiresBefore   time.Time
		byValidAt         time.Time
		byAttestationType string
		bySelectors       *datastore.BySelectors
		byBanned          *bool
		byCanReattest     *bool

		expectIDsInOrder []string                      // full set after paging
		expectSelectors  map[string][]*common.Selector // only checked when fetchSelectors=true
	}

	truePtr := func() *bool { b := true; return &b }()
	falsePtr := func() *bool { b := false; return &b }()

	tests := []pageCase{
		{
			name:             "empty_without_pagination",
			nodes:            nil,
			pageSize:         0, // no pagination object
			fetchSelectors:   true,
			expectIDsInOrder: []string{},
			expectSelectors:  map[string][]*common.Selector{},
		},
		{
			name:           "partial_page_ps2",
			nodes:          []*common.AttestedNode{nodeA},
			pageSize:       2,
			fetchSelectors: true,
			expectIDsInOrder: []string{
				nodeA.SpiffeId,
			},
			expectSelectors: map[string][]*common.Selector{
				nodeA.SpiffeId: nodeA.Selectors,
			},
		},
		{
			name:           "full_page_exact_ps2",
			nodes:          []*common.AttestedNode{nodeA, nodeB},
			pageSize:       2,
			fetchSelectors: false, // make sure we can omit selectors
			expectIDsInOrder: []string{
				nodeA.SpiffeId, nodeB.SpiffeId,
			},
		},
		{
			name:           "page_and_a_half_ps2",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC},
			pageSize:       2,
			fetchSelectors: true,
			expectIDsInOrder: []string{
				nodeA.SpiffeId, nodeB.SpiffeId, nodeC.SpiffeId,
			},
			expectSelectors: map[string][]*common.Selector{
				nodeA.SpiffeId: nodeA.Selectors,
				nodeB.SpiffeId: nodeB.Selectors,
				nodeC.SpiffeId: nodeC.Selectors,
			},
		},
		{
			name:            "filter_by_expires_before",
			nodes:           []*common.AttestedNode{nodeA, nodeE, nodeB, nodeF, nodeG, nodeC},
			pageSize:        2,
			fetchSelectors:  true,
			byExpiresBefore: now,
			// driver orders by spiffe_id asc for the partition; with A,B,C expired, expect A,B,C
			expectIDsInOrder: []string{
				nodeA.SpiffeId, nodeB.SpiffeId, nodeC.SpiffeId,
			},
			expectSelectors: map[string][]*common.Selector{
				nodeA.SpiffeId: nodeA.Selectors,
				nodeB.SpiffeId: nodeB.Selectors,
				nodeC.SpiffeId: nodeC.Selectors,
			},
		},
		{
			name:           "filter_by_valid_at",
			nodes:          []*common.AttestedNode{nodeA, nodeE, nodeJ},
			pageSize:       2,
			fetchSelectors: false,
			byValidAt:      now.Add(-time.Minute),
			// valid at: E and J
			expectIDsInOrder: []string{
				nodeE.SpiffeId, nodeJ.SpiffeId,
			},
		},
		{
			name:              "filter_by_attestation_type_T1",
			nodes:             []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE},
			pageSize:          2,
			fetchSelectors:    true,
			byAttestationType: "T1",
			expectIDsInOrder: []string{
				nodeA.SpiffeId, nodeC.SpiffeId, nodeE.SpiffeId,
			},
			expectSelectors: map[string][]*common.Selector{
				nodeA.SpiffeId: nodeA.Selectors,
				nodeC.SpiffeId: nodeC.Selectors,
				nodeE.SpiffeId: nodeE.Selectors,
			},
		},
		{
			name:           "filter_by_banned_true",
			nodes:          []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			pageSize:       2,
			fetchSelectors: false,
			byBanned:       truePtr,
			// banned are E,F -> driver order by ID: A, B, E, F overall; filtered -> E, F
			expectIDsInOrder: []string{nodeE.SpiffeId, nodeF.SpiffeId},
		},
		{
			name:           "filter_by_banned_false",
			nodes:          []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			pageSize:       2,
			fetchSelectors: true,
			byBanned:       falsePtr,
			expectIDsInOrder: []string{
				nodeA.SpiffeId, nodeB.SpiffeId,
			},
			expectSelectors: map[string][]*common.Selector{
				nodeA.SpiffeId: nodeA.Selectors,
				nodeB.SpiffeId: nodeB.Selectors,
			},
		},
		{
			name:           "filter_by_selector_subset_S1",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			pageSize:       2,
			fetchSelectors: true,
			bySelectors:    BySelectors(datastore.Subset, "S1"),
			expectIDsInOrder: []string{
				nodeA.SpiffeId, nodeB.SpiffeId,
			},
			expectSelectors: map[string][]*common.Selector{
				nodeA.SpiffeId: nodeA.Selectors,
				nodeB.SpiffeId: nodeB.Selectors,
			},
		},
		{
			name:           "filter_by_selectors_exact_S1_S3",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			pageSize:       2,
			fetchSelectors: false,
			bySelectors:    BySelectors(datastore.Exact, "S1", "S3"),
			expectIDsInOrder: []string{
				nodeF.SpiffeId,
			},
		},
		{
			name:              "filter_can_reattest_true_in_T1",
			nodes:             []*common.AttestedNode{nodeA, nodeI},
			pageSize:          2,
			fetchSelectors:    true,
			byAttestationType: "T1",
			byCanReattest:     truePtr,
			expectIDsInOrder: []string{
				nodeI.SpiffeId,
			},
			expectSelectors: map[string][]*common.Selector{
				nodeI.SpiffeId: nodeI.Selectors,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ds := newDS()
			if closer, ok := ds.(interface{ Close() }); ok {
				defer closer.Close()
			}

			// Seed data
			for _, n := range tc.nodes {
				_, err := ds.CreateAttestedNode(ctx, n)
				require.NoError(t, err)
				require.NoError(t, ds.SetNodeSelectors(ctx, n.SpiffeId, n.Selectors))
			}

			// Build the base request
			var pg *datastore.Pagination
			if tc.pageSize > 0 {
				pg = &datastore.Pagination{PageSize: tc.pageSize}
			}
			req := &datastore.ListAttestedNodesRequest{
				Pagination:        pg,
				ByExpiresBefore:   tc.byExpiresBefore,
				ValidAt:           tc.byValidAt,
				ByAttestationType: tc.byAttestationType,
				BySelectorMatch:   tc.bySelectors,
				ByBanned:          tc.byBanned,
				ByCanReattest:     tc.byCanReattest,
				FetchSelectors:    tc.fetchSelectors,
			}

			// Page through all results, collecting in order
			collectedIDs := make([]string, 0, len(tc.expectIDsInOrder)) // ensure non-nil on empty
			collectedSelectors := make(map[string][]*common.Selector)

			for {
				resp, err := ds.ListAttestedNodes(ctx, req)
				require.NoError(t, err)
				require.NotNil(t, resp)

				if tc.pageSize > 0 {
					require.NotNil(t, resp.Pagination, "expected pagination in response")
					assert.Equal(t, tc.pageSize, resp.Pagination.PageSize, "page size mismatch")
				} else {
					require.Nil(t, resp.Pagination, "unexpected pagination in response")
				}

				for _, n := range resp.Nodes {
					collectedIDs = append(collectedIDs, n.SpiffeId)
					if tc.fetchSelectors {
						collectedSelectors[n.SpiffeId] = n.Selectors
					} else {
						// when not requested, selectors must be omitted
						require.Nil(t, n.Selectors)
					}
				}

				// stop when no next page
				if resp.Pagination == nil || resp.Pagination.Token == "" {
					break
				}
				req.Pagination = resp.Pagination
			}

			// Verify the final set/order
			assert.Equal(t, tc.expectIDsInOrder, collectedIDs, "unexpected IDs in order")

			if tc.fetchSelectors {
				AssertSelectorsEqual(t, tc.expectSelectors, collectedSelectors, "unexpected selectors")
			}
		})
	}

	// Separate "page through everything" smoke test with a bigger corpus.
	t.Run("page_through_all_nodes_smoke", func(t *testing.T) {
		ds := newDS()
		if closer, ok := ds.(interface{ Close() }); ok {
			defer closer.Close()
		}

		seed := []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH, nodeI, nodeJ}
		for _, n := range seed {
			_, err := ds.CreateAttestedNode(ctx, n)
			require.NoError(t, err)
			require.NoError(t, ds.SetNodeSelectors(ctx, n.SpiffeId, n.Selectors))
		}

		pageSize := int32(3)
		var nextToken string
		ids := make([]string, 0, len(seed)) // ensure non-nil for empty comparisons

		for {
			resp, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
				Pagination:     &datastore.Pagination{Token: nextToken, PageSize: pageSize},
				FetchSelectors: false,
			})
			require.NoError(t, err)
			for _, n := range resp.Nodes {
				ids = append(ids, n.SpiffeId)
				require.Nil(t, n.Selectors) // not requested
			}
			if resp.Pagination == nil || resp.Pagination.Token == "" {
				break
			}
			nextToken = resp.Pagination.Token
		}

		// Expect natural ascending ID order (A..J) with whatever exists in this DS run.
		expect := []string{
			nodeA.SpiffeId, nodeB.SpiffeId, nodeC.SpiffeId, nodeD.SpiffeId, nodeE.SpiffeId,
			nodeF.SpiffeId, nodeG.SpiffeId, nodeH.SpiffeId, nodeI.SpiffeId, nodeJ.SpiffeId,
		}
		assert.Equal(t, expect, ids)
	})
}

// TestListAttestedNodesNoSQL mirrors TestListAttestedNodes but adjusts expectations
// for the Cassandra ordering (spiffe_id ASC) and token-less single-shot lists.
func TestListAttestedNodesNoSQL(t *testing.T, newDS func() datastore.DataStore) {
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

	// Fixtures
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

	type tt struct {
		name              string
		nodes             []*common.AttestedNode
		byExpiresBefore   time.Time
		byValidAt         time.Time
		byAttestationType string
		bySelectors       *datastore.BySelectors
		byBanned          *bool
		byCanReattest     *bool
		expectNodesOut    []*common.AttestedNode
	}

	tests := []tt{
		{
			name:           "without_attested_nodes_without_selectors",
			expectNodesOut: []*common.AttestedNode{},
		},
		{
			name:           "with_one_node_without_selectors",
			nodes:          []*common.AttestedNode{nodeA},
			expectNodesOut: []*common.AttestedNode{nodeA},
		},
		{
			name:           "with_two_nodes_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB},
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB},
		},
		{
			name:            "by_expires_before_without_selectors",
			nodes:           []*common.AttestedNode{nodeA, nodeE, nodeB, nodeF, nodeG, nodeC},
			byExpiresBefore: now,
			expectNodesOut:  []*common.AttestedNode{nodeA, nodeB, nodeC},
		},
		{
			name:           "by_valid_at_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeE, nodeJ},
			byValidAt:      now.Add(-time.Minute),
			expectNodesOut: []*common.AttestedNode{nodeE, nodeJ},
		},
		{
			name:              "by_attestation_type_without_selectors",
			nodes:             []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE},
			byAttestationType: "T1",
			expectNodesOut:    []*common.AttestedNode{nodeA, nodeC, nodeE},
		},
		{
			name:           "by_banned_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			byBanned:       &bannedTrue,
			expectNodesOut: []*common.AttestedNode{nodeE, nodeF},
		},
		{
			name:           "by_unbanned_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			byBanned:       &bannedFalse,
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB},
		},
		{
			// CHANGED: seed in spiffe order and expect spiffe order (A, B, E, F)
			name:           "banned_undefined_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF},
			byBanned:       nil,
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF},
		},
		// Selector filters (with selectors returned)
		{
			name:           "by_selector_subset_with_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Subset, "S1"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB},
		},
		{
			name:           "by_selectors_subset_with_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Subset, "S1", "S3"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB, nodeF},
		},
		{
			name:           "by_selector_exact_with_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Exact, "S1"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB},
		},
		{
			name:           "by_selectors_exact_with_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Exact, "S1", "S3"),
			expectNodesOut: []*common.AttestedNode{nodeF},
		},
		{
			// With MatchAny, expect A,B,E,F,G,H (S1 matches A,B,E,F; S3 matches F,G,H)
			name:           "by_selector_match_any_with_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.MatchAny, "S1"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF},
		},
		{
			name:           "by_selectors_match_any_with_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.MatchAny, "S1", "S3"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF, nodeG, nodeH},
		},
		{
			name:           "by_selector_superset_with_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Superset, "S1"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF},
		},
		{
			name:           "by_selectors_superset_with_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Superset, "S1", "S2"),
			expectNodesOut: []*common.AttestedNode{nodeE},
		},
		// Same selector filters but without returning selectors in the response
		{
			name:           "by_selector_subset_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Subset, "S1"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB},
		},
		{
			name:           "by_selectors_subset_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Subset, "S1", "S3"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB, nodeF},
		},
		{
			name:           "by_selector_exact_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Exact, "S1"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB},
		},
		{
			name:           "by_selectors_exact_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.Exact, "S1", "S3"),
			expectNodesOut: []*common.AttestedNode{nodeF},
		},
		{
			name:           "by_selector_match_any_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.MatchAny, "S1"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF},
		},
		{
			name:           "by_selectors_match_any_without_selectors",
			nodes:          []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:    BySelectors(datastore.MatchAny, "S1", "S3"),
			expectNodesOut: []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF, nodeG, nodeH},
		},
		// CanReattest filters within T1
		{
			name:              "by_CanReattest=true_within_T1_with_selectors",
			nodes:             []*common.AttestedNode{nodeA, nodeI},
			byAttestationType: "T1",
			byCanReattest:     &canReattestTrue,
			expectNodesOut:    []*common.AttestedNode{nodeI},
		},
		{
			name:              "by_CanReattest=false_within_T1_with_selectors",
			nodes:             []*common.AttestedNode{nodeA, nodeI},
			byAttestationType: "T1",
			byCanReattest:     &canReattestFalse,
			expectNodesOut:    []*common.AttestedNode{nodeA},
		},
		// All filters together
		{
			name:              "all_filters_with_selectors",
			nodes:             []*common.AttestedNode{nodeA, nodeE, nodeB, nodeF, nodeG, nodeC},
			byBanned:          &bannedFalse,
			byExpiresBefore:   now,
			byAttestationType: "T1",
			bySelectors:       BySelectors(datastore.Subset, "S1"),
			byCanReattest:     &canReattestFalse,
			expectNodesOut:    []*common.AttestedNode{nodeA},
		},
	}

	for _, tc := range tests {
		// Run with FetchSelectors true/false based on the test name hint
		withSelectors := strings.Contains(tc.name, "with_selectors")

		t.Run(tc.name, func(t *testing.T) {
			ds := newDS()
			if closer, ok := ds.(interface{ Close() }); ok {
				defer closer.Close()
			}

			// Seed in the order specified (we already ordered A,B,E,F where relevant)
			for _, n := range tc.nodes {
				_, err := ds.CreateAttestedNode(ctx, n)
				require.NoError(t, err)
				require.NoError(t, ds.SetNodeSelectors(ctx, n.SpiffeId, n.Selectors))
			}

			// Single-shot list (no pagination object)
			req := &datastore.ListAttestedNodesRequest{
				Pagination:        nil,
				ByExpiresBefore:   tc.byExpiresBefore,
				ValidAt:           tc.byValidAt,
				ByAttestationType: tc.byAttestationType,
				BySelectorMatch:   tc.bySelectors,
				ByBanned:          tc.byBanned,
				ByCanReattest:     tc.byCanReattest,
				FetchSelectors:    withSelectors,
			}

			resp, err := ds.ListAttestedNodes(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Nil(t, resp.Pagination, "unexpected pagination in response")

			// Collect IDs
			var gotIDs []string
			gotSelectors := map[string][]*common.Selector{}
			for _, n := range resp.Nodes {
				gotIDs = append(gotIDs, n.SpiffeId)
				if withSelectors {
					gotSelectors[n.SpiffeId] = n.Selectors
				} else {
					require.Nil(t, n.Selectors)
				}
			}

			// Build expected IDs
			var expectedIDs []string
			expectedSelectors := map[string][]*common.Selector{}
			for _, n := range tc.expectNodesOut {
				expectedIDs = append(expectedIDs, n.SpiffeId)
				if withSelectors {
					expectedSelectors[n.SpiffeId] = n.Selectors
				}
			}

			assert.Equal(t, expectedIDs, gotIDs, "unexpected response nodes")
			if withSelectors {
				AssertSelectorsEqual(t, expectedSelectors, gotSelectors, "unexpected response selectors")
			}
		})
	}
}
