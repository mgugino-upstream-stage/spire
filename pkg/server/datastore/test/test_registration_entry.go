package dstest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"crypto/x509"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

// readJSON reads a JSON file relative to the repository root (or package layout) and unmarshals it.
func readJSON(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		// try relative to current dir
		b, err = os.ReadFile(filepath.Join("pkg", "server", "datastore", "sqlstore", "testdata", filepath.Base(path)))
		if err != nil {
			return err
		}
	}
	return json.Unmarshal(b, v)
}

// AssertEntryEqual compares registration entries while allowing CreatedAt and EntryId differences
func AssertEntryEqual(t *testing.T, expectEntry, createdEntry *common.RegistrationEntry, now int64) {
	require.NotEmpty(t, createdEntry.EntryId)
	expectEntry.EntryId = ""
	createdEntry.EntryId = ""
	assertCreatedAtField(t, createdEntry, now)
	createdEntry.CreatedAt = expectEntry.CreatedAt
	spiretest.RequireProtoEqual(t, createdEntry, expectEntry)
}

func assertCreatedAtField(t *testing.T, entry *common.RegistrationEntry, now int64) {
	require.GreaterOrEqual(t, entry.CreatedAt, now)
	entry.CreatedAt = 0
}

// TestListRegistrationEntries runs the full listing + pagination matrix for
// registration entries. It accepts a factory newDS which should return a fresh
// datastore instance for each inner test (this mirrors sqlstore behaviour) and
// cert/cacert used to create federated bundles required by some test cases.
func TestListRegistrationEntries(t *testing.T, newDS func() datastore.DataStore, cert *x509.Certificate, cacert *x509.Certificate) {
	byFederatesWith := func(match datastore.MatchBehavior, trustDomainIDs ...string) *datastore.ByFederatesWith {
		return &datastore.ByFederatesWith{
			TrustDomains: trustDomainIDs,
			Match:        match,
		}
	}

	makeEntry := func(parentIDSuffix, spiffeIDSuffix, hint string, selectors ...string) *common.RegistrationEntry {
		return &common.RegistrationEntry{
			EntryId:   fmt.Sprintf("%s%s%s", parentIDSuffix, spiffeIDSuffix, strings.Join(selectors, "")),
			ParentId:  MakeID(parentIDSuffix),
			SpiffeId:  MakeID(spiffeIDSuffix),
			Selectors: MakeSelectors(selectors...),
			Hint:      hint,
		}
	}

	foobarAB1 := makeEntry("foo", "bar", "external", "A", "B")
	foobarAB1.FederatesWith = []string{"spiffe://federated1.test"}
	foobarAD12 := makeEntry("foo", "bar", "", "A", "D")
	foobarAD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	foobarCB2 := makeEntry("foo", "bar", "internal", "C", "B")
	foobarCB2.FederatesWith = []string{"spiffe://federated2.test"}
	foobarCD12 := makeEntry("foo", "bar", "", "C", "D")
	foobarCD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}

	foobarB := makeEntry("foo", "bar", "", "B")

	foobuzAD1 := makeEntry("foo", "buz", "", "A", "D")
	foobuzAD1.FederatesWith = []string{"spiffe://federated1.test"}
	foobuzCD := makeEntry("foo", "buz", "", "C", "D")

	bazbarAB1 := makeEntry("baz", "bar", "", "A", "B")
	bazbarAB1.FederatesWith = []string{"spiffe://federated1.test"}
	bazbarAD12 := makeEntry("baz", "bar", "external", "A", "D")
	bazbarAD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbarCB2 := makeEntry("baz", "bar", "", "C", "B")
	bazbarCB2.FederatesWith = []string{"spiffe://federated2.test"}
	bazbarCD12 := makeEntry("baz", "bar", "", "C", "D")
	bazbarCD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbarAE3 := makeEntry("baz", "bar", "", "A", "E")
	bazbarAE3.FederatesWith = []string{"spiffe://federated3.test"}

	bazbuzAB12 := makeEntry("baz", "buz", "", "A", "B")
	bazbuzAB12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbuzB := makeEntry("baz", "buz", "", "B")
	bazbuzCD := makeEntry("baz", "buz", "", "C", "D")

	zizzazX := makeEntry("ziz", "zaz", "", "X")

	// Run the original matrix for both data consistency modes to preserve
	// original semantics.
	for _, dataConsistency := range []datastore.DataConsistency{datastore.RequireCurrent, datastore.TolerateStale} {
		for _, tt := range []struct {
			test                  string
			entries               []*common.RegistrationEntry
			pageSize              int32
			byParentID            string
			bySpiffeID            string
			byHint                string
			bySelectors           *datastore.BySelectors
			byFederatesWith       *datastore.ByFederatesWith
			expectEntriesOut      []*common.RegistrationEntry
			expectPagedTokensIn   []string
			expectPagedEntriesOut [][]*common.RegistrationEntry
		}{
			{test: "without entries", expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "with partial page", entries: []*common.RegistrationEntry{foobarAB1}, pageSize: 2, expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "with full page", entries: []*common.RegistrationEntry{foobarAB1, foobarCB2}, pageSize: 2, expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCB2}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1, foobarCB2}, {}}},
			{test: "with page and a half", entries: []*common.RegistrationEntry{foobarAB1, foobarCB2, foobarAD12}, pageSize: 2, expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCB2, foobarAD12}, expectPagedTokensIn: []string{"", "2", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1, foobarCB2}, {foobarAD12}, {}}},
			{test: "by parent ID", entries: []*common.RegistrationEntry{foobarAB1, bazbarAD12, foobarCB2, bazbarCD12}, byParentID: MakeID("foo"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCB2}, expectPagedTokensIn: []string{"", "1", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCB2}, {}}},
			{test: "by SPIFFE ID", entries: []*common.RegistrationEntry{foobarAB1, foobuzAD1, foobarCB2, foobuzCD}, bySpiffeID: MakeID("bar"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCB2}, expectPagedTokensIn: []string{"", "1", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCB2}, {}}},
			{test: "by Hint, two matches", entries: []*common.RegistrationEntry{foobarAB1, bazbarAD12, foobarCB2, bazbarCD12}, byHint: "external", expectEntriesOut: []*common.RegistrationEntry{foobarAB1, bazbarAD12}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {bazbarAD12}, {}}},
			{test: "by Hint, no match", entries: []*common.RegistrationEntry{foobarAB1, bazbarAD12, foobarCB2, bazbarCD12}, byHint: "none", expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by federatesWith one subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by federatesWith many subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{foobarCB2}, expectPagedTokensIn: []string{"", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarCB2}, {}}},
			{test: "by federatesWith one exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by federatesWith many exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12, foobarCD12}, expectPagedTokensIn: []string{"", "2", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {}}},
			{test: "by federatesWith one match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12}, expectPagedTokensIn: []string{"", "1", "2", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {}}},
			{test: "by federatesWith many match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12}, expectPagedTokensIn: []string{"", "1", "2", "3", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCB2}, {foobarCD12}, {}}},
			{test: "by federatesWith one superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12}, expectPagedTokensIn: []string{"", "1", "2", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {}}},
			{test: "by federatesWith many superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12, foobarCD12}, expectPagedTokensIn: []string{"", "2", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {}}},
			{test: "by parent ID and SPIFFE ID", entries: []*common.RegistrationEntry{foobarAB1, foobuzAD1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySpiffeID: MakeID("bar"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by parent ID and exact selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Exact, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}}},
			{test: "by parent ID and exact selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Exact, "A", "B"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by parent ID and subset selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Subset, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}}},
			{test: "by parent ID and subset selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Subset, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}}},
			{test: "by parent ID and subset selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Subset, "C", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by parent ID and match any selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.MatchAny, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}}},
			{test: "by parent ID and match any selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.MatchAny, "A", "C", "Z"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCD12}, expectPagedTokensIn: []string{"", "2", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCD12}, {}}},
			{test: "by parent ID and match any selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.MatchAny, "D", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by parent ID and superset selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Superset, "A"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by parent ID and superset selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Superset, "A", "B"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by parent ID and superset selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Superset, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by parentID and federatesWith one subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1}, expectPagedTokensIn: []string{"", "6"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {}}},
			{test: "by parentID and federatesWith many subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarCB2}, expectPagedTokensIn: []string{"", "8"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarCB2}, {}}},
			{test: "by parentID and federatesWith one exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1}, expectPagedTokensIn: []string{"", "6"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {}}},
			{test: "by parentID and federatesWith many exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by parentID and federatesWith one match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "6", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by parentID and federatesWith many match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, expectPagedTokensIn: []string{"", "6", "7", "8", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {bazbarAD12}, {bazbarCB2}, {bazbarCD12}, {}}},
			{test: "by parentID and federatesWith one superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "6", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by parentID and federatesWith many superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and exact selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Exact, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}}},
			{test: "by SPIFFE ID and exact selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Exact, "A", "B"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by SPIFFE ID and subset selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Subset, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}}},
			{test: "by SPIFFE ID and subset selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Subset, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}}},
			{test: "by SPIFFE ID and subset selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Subset, "C", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and match any selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.MatchAny, "A"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by SPIFFE ID and match any selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.MatchAny, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2}, expectPagedTokensIn: []string{"", "1", "2", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {bazbarCB2}, {}}},
			{test: "by SPIFFE ID and match any selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.MatchAny, "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and superset selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Superset, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}}},
			{test: "by SPIFFE ID and superset selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Superset, "A", "B"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by SPIFFE ID and superset selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Superset, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and federatesWith one subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, bazbarAB1}, expectPagedTokensIn: []string{"", "1", "6"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {bazbarAB1}, {}}},
			{test: "by SPIFFE ID and federatesWith many subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{foobarCB2, bazbarCB2}, expectPagedTokensIn: []string{"", "3", "8"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarCB2}, {bazbarCB2}, {}}},
			{test: "by SPIFFE ID and federatesWith one exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, bazbarAB1}, expectPagedTokensIn: []string{"", "1", "6"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {bazbarAB1}, {}}},
			{test: "by SPIFFE ID and federatesWith many exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12, foobarCD12, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "2", "4", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith subset no results", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("buz"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and federatesWith match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12, bazbarAB1, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "1", "2", "4", "6", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith many match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, expectPagedTokensIn: []string{"", "1", "2", "3", "4", "6", "7", "8", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCB2}, {foobarCD12}, {bazbarAB1}, {bazbarAD12}, {bazbarCB2}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith match any no results", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("buz"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and federatesWith superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12, bazbarAB1, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "1", "2", "4", "6", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith many superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12, foobarCD12, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "2", "4", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith superset no results", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("buz"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by Parent ID, federatesWith and selectors", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("foo"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated1.test", "spiffe://federated2.test"), bySelectors: BySelectors(datastore.Subset, "A", "D"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {}}},
		} {
			for _, withPagination := range []bool{true, false} {
				name := tt.test
				if withPagination {
					name += " with pagination"
				} else {
					name += " without pagination"
				}
				if dataConsistency == datastore.TolerateStale {
					name += " read-only"
				}
				t.Run(name, func(t *testing.T) {
					ds := newDS()
					if closer, ok := ds.(interface{ Close() }); ok {
						defer closer.Close()
					}

					// Create bundles required by some test cases
					createBundle(t, ds, "spiffe://federated1.test", cert)
					createBundle(t, ds, "spiffe://federated2.test", cert)
					createBundle(t, ds, "spiffe://federated3.test", cert)

					entryIDMap := map[string]string{}
					for _, entryIn := range tt.entries {
						entryOut := CreateRegistrationEntry(t, ds, entryIn)
						entryIDMap[entryOut.EntryId] = entryIn.EntryId
					}

					var pagination *datastore.Pagination
					if withPagination {
						pagination = &datastore.Pagination{PageSize: tt.pageSize}
						if pagination.PageSize == 0 {
							pagination.PageSize = 1
						}
					}

					var tokensIn []string
					actualEntriesOut := make(map[string]*common.RegistrationEntry)
					expectedEntriesOut := make(map[string]*common.RegistrationEntry)
					req := &datastore.ListRegistrationEntriesRequest{
						Pagination:      pagination,
						ByParentID:      tt.byParentID,
						BySpiffeID:      tt.bySpiffeID,
						BySelectors:     tt.bySelectors,
						ByFederatesWith: tt.byFederatesWith,
						ByHint:          tt.byHint,
					}

					for i := 0; ; i++ {
						if i > len(tt.entries) {
							require.FailNowf(t, "Exhausted paging limit in test", "tokens=%q spiffeids=%q", tokensIn, actualEntriesOut)
						}
						if req.Pagination != nil {
							tokensIn = append(tokensIn, req.Pagination.Token)
						}
						resp, err := ds.ListRegistrationEntries(ctx, req)
						require.NoError(t, err)
						require.NotNil(t, resp)
						if withPagination {
							require.NotNil(t, resp.Pagination, "response missing pagination")
							require.Equal(t, req.Pagination.PageSize, resp.Pagination.PageSize, "response page size did not match request")
						} else {
							require.Nil(t, resp.Pagination, "response has pagination")
						}

						for _, entry := range resp.Entries {
							entryID, ok := entryIDMap[entry.EntryId]
							require.True(t, ok, "entry with id %q was not created by this test", entry.EntryId)
							entry.EntryId = entryID
							actualEntriesOut[entryID] = entry
						}

						if resp.Pagination == nil || resp.Pagination.Token == "" {
							break
						}
						req.Pagination = resp.Pagination
					}

					expectEntriesOut := tt.expectPagedEntriesOut
					if !withPagination {
						expectEntriesOut = [][]*common.RegistrationEntry{tt.expectEntriesOut}
					}

					for _, entrySet := range expectEntriesOut {
						for _, entry := range entrySet {
							expectedEntriesOut[entry.EntryId] = entry
						}
					}

					if withPagination {
						require.Equal(t, tt.expectPagedTokensIn, tokensIn, "unexpected request tokens")
					} else {
						require.Empty(t, tokensIn, "unexpected request tokens")
					}

					require.Len(t, actualEntriesOut, len(expectedEntriesOut), "unexpected number of entries returned")
					for id, expectedEntry := range expectedEntriesOut {
						if _, ok := actualEntriesOut[id]; !ok {
							t.Errorf("Expected entry %q not found", id)
							continue
						}
						sort.Strings(actualEntriesOut[id].FederatesWith)
						assertCreatedAtField(t, actualEntriesOut[id], expectedEntry.CreatedAt)
						spiretest.AssertProtoEqual(t, expectedEntry, actualEntriesOut[id])
					}
				})
			}
		}
	}
}

// TestListRegistrationEntries runs the full listing + pagination matrix for
// registration entries. It accepts a factory newDS which should return a fresh
// datastore instance for each inner test (this mirrors sqlstore behaviour) and
// cert/cacert used to create federated bundles required by some test cases.
func TestListRegistrationEntriesNoSQL(t *testing.T, newDS func() datastore.DataStore, cert *x509.Certificate, cacert *x509.Certificate) {
	byFederatesWith := func(match datastore.MatchBehavior, trustDomainIDs ...string) *datastore.ByFederatesWith {
		return &datastore.ByFederatesWith{
			TrustDomains: trustDomainIDs,
			Match:        match,
		}
	}

	makeEntry := func(parentIDSuffix, spiffeIDSuffix, hint string, selectors ...string) *common.RegistrationEntry {
		return &common.RegistrationEntry{
			EntryId:   fmt.Sprintf("%s%s%s", parentIDSuffix, spiffeIDSuffix, strings.Join(selectors, "")),
			ParentId:  MakeID(parentIDSuffix),
			SpiffeId:  MakeID(spiffeIDSuffix),
			Selectors: MakeSelectors(selectors...),
			Hint:      hint,
		}
	}

	foobarAB1 := makeEntry("foo", "bar", "external", "A", "B")
	foobarAB1.FederatesWith = []string{"spiffe://federated1.test"}
	foobarAD12 := makeEntry("foo", "bar", "", "A", "D")
	foobarAD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	foobarCB2 := makeEntry("foo", "bar", "internal", "C", "B")
	foobarCB2.FederatesWith = []string{"spiffe://federated2.test"}
	foobarCD12 := makeEntry("foo", "bar", "", "C", "D")
	foobarCD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}

	foobarB := makeEntry("foo", "bar", "", "B")

	foobuzAD1 := makeEntry("foo", "buz", "", "A", "D")
	foobuzAD1.FederatesWith = []string{"spiffe://federated1.test"}
	foobuzCD := makeEntry("foo", "buz", "", "C", "D")

	bazbarAB1 := makeEntry("baz", "bar", "", "A", "B")
	bazbarAB1.FederatesWith = []string{"spiffe://federated1.test"}
	bazbarAD12 := makeEntry("baz", "bar", "external", "A", "D")
	bazbarAD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbarCB2 := makeEntry("baz", "bar", "", "C", "B")
	bazbarCB2.FederatesWith = []string{"spiffe://federated2.test"}
	bazbarCD12 := makeEntry("baz", "bar", "", "C", "D")
	bazbarCD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbarAE3 := makeEntry("baz", "bar", "", "A", "E")
	bazbarAE3.FederatesWith = []string{"spiffe://federated3.test"}

	bazbuzAB12 := makeEntry("baz", "buz", "", "A", "B")
	bazbuzAB12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbuzB := makeEntry("baz", "buz", "", "B")
	bazbuzCD := makeEntry("baz", "buz", "", "C", "D")

	zizzazX := makeEntry("ziz", "zaz", "", "X")

	// Run the original matrix for both data consistency modes to preserve
	// original semantics.
	for _, dataConsistency := range []datastore.DataConsistency{datastore.RequireCurrent, datastore.TolerateStale} {
		for _, tt := range []struct {
			test                  string
			entries               []*common.RegistrationEntry
			pageSize              int32
			byParentID            string
			bySpiffeID            string
			byHint                string
			bySelectors           *datastore.BySelectors
			byFederatesWith       *datastore.ByFederatesWith
			expectEntriesOut      []*common.RegistrationEntry
			expectPagedTokensIn   []string
			expectPagedEntriesOut [][]*common.RegistrationEntry
		}{
			{test: "without entries", expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "with partial page", entries: []*common.RegistrationEntry{foobarAB1}, pageSize: 2, expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "with full page", entries: []*common.RegistrationEntry{foobarAB1, foobarCB2}, pageSize: 2, expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCB2}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1, foobarCB2}, {}}},
			{test: "with page and a half", entries: []*common.RegistrationEntry{foobarAB1, foobarCB2, foobarAD12}, pageSize: 2, expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCB2, foobarAD12}, expectPagedTokensIn: []string{"", "2", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1, foobarCB2}, {foobarAD12}, {}}},
			{test: "by parent ID", entries: []*common.RegistrationEntry{foobarAB1, bazbarAD12, foobarCB2, bazbarCD12}, byParentID: MakeID("foo"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCB2}, expectPagedTokensIn: []string{"", "1", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCB2}, {}}},
			{test: "by SPIFFE ID", entries: []*common.RegistrationEntry{foobarAB1, foobuzAD1, foobarCB2, foobuzCD}, bySpiffeID: MakeID("bar"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCB2}, expectPagedTokensIn: []string{"", "1", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCB2}, {}}},
			{test: "by Hint, two matches", entries: []*common.RegistrationEntry{foobarAB1, bazbarAD12, foobarCB2, bazbarCD12}, byHint: "external", expectEntriesOut: []*common.RegistrationEntry{foobarAB1, bazbarAD12}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {bazbarAD12}, {}}},
			{test: "by Hint, no match", entries: []*common.RegistrationEntry{foobarAB1, bazbarAD12, foobarCB2, bazbarCD12}, byHint: "none", expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by federatesWith one subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by federatesWith many subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{foobarCB2}, expectPagedTokensIn: []string{"", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarCB2}, {}}},
			{test: "by federatesWith one exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by federatesWith many exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12, foobarCD12}, expectPagedTokensIn: []string{"", "2", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {}}},
			{test: "by federatesWith one match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12}, expectPagedTokensIn: []string{"", "1", "2", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {}}},
			{test: "by federatesWith many match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12}, expectPagedTokensIn: []string{"", "1", "2", "3", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCB2}, {foobarCD12}, {}}},
			{test: "by federatesWith one superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12}, expectPagedTokensIn: []string{"", "1", "2", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {}}},
			{test: "by federatesWith many superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX}, byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12, foobarCD12}, expectPagedTokensIn: []string{"", "2", "4"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {}}},
			{test: "by parent ID and SPIFFE ID", entries: []*common.RegistrationEntry{foobarAB1, foobuzAD1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySpiffeID: MakeID("bar"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by parent ID and exact selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Exact, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}}},
			{test: "by parent ID and exact selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Exact, "A", "B"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by parent ID and subset selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Subset, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}}},
			{test: "by parent ID and subset selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Subset, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}}},
			{test: "by parent ID and subset selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Subset, "C", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by parent ID and match any selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.MatchAny, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}}},
			{test: "by parent ID and match any selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.MatchAny, "A", "C", "Z"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarCD12}, expectPagedTokensIn: []string{"", "2", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCD12}, {}}},
			{test: "by parent ID and match any selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.MatchAny, "D", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by parent ID and superset selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbuzB, bazbuzAB12}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Superset, "A"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by parent ID and superset selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Superset, "A", "B"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by parent ID and superset selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, byParentID: MakeID("foo"), bySelectors: BySelectors(datastore.Superset, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by parentID and federatesWith one subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1}, expectPagedTokensIn: []string{"", "6"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {}}},
			{test: "by parentID and federatesWith many subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarCB2}, expectPagedTokensIn: []string{"", "8"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarCB2}, {}}},
			{test: "by parentID and federatesWith one exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1}, expectPagedTokensIn: []string{"", "6"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {}}},
			{test: "by parentID and federatesWith many exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by parentID and federatesWith one match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "6", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by parentID and federatesWith many match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, expectPagedTokensIn: []string{"", "6", "7", "8", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {bazbarAD12}, {bazbarCB2}, {bazbarCD12}, {}}},
			{test: "by parentID and federatesWith one superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAB1, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "6", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by parentID and federatesWith many superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3}, byParentID: MakeID("baz"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and exact selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Exact, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}}},
			{test: "by SPIFFE ID and exact selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Exact, "A", "B"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by SPIFFE ID and subset selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Subset, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB}, expectPagedTokensIn: []string{"", "1"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}}},
			{test: "by SPIFFE ID and subset selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Subset, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}}},
			{test: "by SPIFFE ID and subset selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Subset, "C", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and match any selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.MatchAny, "A"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by SPIFFE ID and match any selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.MatchAny, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2}, expectPagedTokensIn: []string{"", "1", "2", "3"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {bazbarCB2}, {}}},
			{test: "by SPIFFE ID and match any selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.MatchAny, "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and superset selector", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Superset, "B"), expectEntriesOut: []*common.RegistrationEntry{foobarB, foobarAB1}, expectPagedTokensIn: []string{"", "1", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}}},
			{test: "by SPIFFE ID and superset selectors", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Superset, "A", "B"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}}},
			{test: "by SPIFFE ID and superset selectors no match", entries: []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD}, bySpiffeID: MakeID("bar"), bySelectors: BySelectors(datastore.Superset, "A", "B", "Z"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and federatesWith one subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, bazbarAB1}, expectPagedTokensIn: []string{"", "1", "6"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {bazbarAB1}, {}}},
			{test: "by SPIFFE ID and federatesWith many subset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{foobarCB2, bazbarCB2}, expectPagedTokensIn: []string{"", "3", "8"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarCB2}, {bazbarCB2}, {}}},
			{test: "by SPIFFE ID and federatesWith one exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, bazbarAB1}, expectPagedTokensIn: []string{"", "1", "6"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {bazbarAB1}, {}}},
			{test: "by SPIFFE ID and federatesWith many exact", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12, foobarCD12, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "2", "4", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith subset no results", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("buz"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and federatesWith match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12, bazbarAB1, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "1", "2", "4", "6", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith many match any", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, expectPagedTokensIn: []string{"", "1", "2", "3", "4", "6", "7", "8", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCB2}, {foobarCD12}, {bazbarAB1}, {bazbarAD12}, {bazbarCB2}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith match any no results", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("buz"), byFederatesWith: byFederatesWith(datastore.MatchAny, "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by SPIFFE ID and federatesWith superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12, bazbarAB1, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "1", "2", "4", "6", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith many superset", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("bar"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated1.test", "spiffe://federated2.test"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12, foobarCD12, bazbarAD12, bazbarCD12}, expectPagedTokensIn: []string{"", "2", "4", "7", "9"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {bazbarAD12}, {bazbarCD12}, {}}},
			{test: "by SPIFFE ID and federatesWith superset no results", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12}, bySpiffeID: MakeID("buz"), byFederatesWith: byFederatesWith(datastore.Superset, "spiffe://federated2.test", "spiffe://federated3.test"), expectEntriesOut: []*common.RegistrationEntry{}, expectPagedTokensIn: []string{""}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{}}},
			{test: "by Parent ID, federatesWith and selectors", entries: []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12}, byParentID: MakeID("foo"), byFederatesWith: byFederatesWith(datastore.Subset, "spiffe://federated1.test", "spiffe://federated2.test"), bySelectors: BySelectors(datastore.Subset, "A", "D"), expectEntriesOut: []*common.RegistrationEntry{foobarAD12}, expectPagedTokensIn: []string{"", "2"}, expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {}}},
		} {
			for _, withPagination := range []bool{false} {
				name := tt.test
				if withPagination {
					name += " with pagination"
				} else {
					name += " without pagination"
				}
				if dataConsistency == datastore.TolerateStale {
					name += " read-only"
				}
				t.Run(name, func(t *testing.T) {
					ds := newDS()
					if closer, ok := ds.(interface{ Close() }); ok {
						defer closer.Close()
					}

					// Create bundles required by some test cases
					createBundle(t, ds, "spiffe://federated1.test", cert)
					createBundle(t, ds, "spiffe://federated2.test", cert)
					createBundle(t, ds, "spiffe://federated3.test", cert)

					entryIDMap := map[string]string{}
					for _, entryIn := range tt.entries {
						entryOut := CreateRegistrationEntry(t, ds, entryIn)
						entryIDMap[entryOut.EntryId] = entryIn.EntryId
					}

					var pagination *datastore.Pagination
					if withPagination {
						pagination = &datastore.Pagination{PageSize: tt.pageSize}
						if pagination.PageSize == 0 {
							pagination.PageSize = 1
						}
					}

					var tokensIn []string
					actualEntriesOut := make(map[string]*common.RegistrationEntry)
					expectedEntriesOut := make(map[string]*common.RegistrationEntry)
					req := &datastore.ListRegistrationEntriesRequest{
						Pagination:      pagination,
						ByParentID:      tt.byParentID,
						BySpiffeID:      tt.bySpiffeID,
						BySelectors:     tt.bySelectors,
						ByFederatesWith: tt.byFederatesWith,
						ByHint:          tt.byHint,
					}

					for i := 0; ; i++ {
						if i > len(tt.entries) {
							require.FailNowf(t, "Exhausted paging limit in test", "tokens=%q spiffeids=%q", tokensIn, actualEntriesOut)
						}
						if req.Pagination != nil {
							tokensIn = append(tokensIn, req.Pagination.Token)
						}
						resp, err := ds.ListRegistrationEntries(ctx, req)
						require.NoError(t, err)
						require.NotNil(t, resp)
						if withPagination {
							require.NotNil(t, resp.Pagination, "response missing pagination")
							require.Equal(t, req.Pagination.PageSize, resp.Pagination.PageSize, "response page size did not match request")
						} else {
							require.Nil(t, resp.Pagination, "response has pagination")
						}

						for _, entry := range resp.Entries {
							entryID, ok := entryIDMap[entry.EntryId]
							require.True(t, ok, "entry with id %q was not created by this test", entry.EntryId)
							entry.EntryId = entryID
							actualEntriesOut[entryID] = entry
						}

						if resp.Pagination == nil || resp.Pagination.Token == "" {
							break
						}
						req.Pagination = resp.Pagination
					}

					expectEntriesOut := tt.expectPagedEntriesOut
					if !withPagination {
						expectEntriesOut = [][]*common.RegistrationEntry{tt.expectEntriesOut}
					}

					for _, entrySet := range expectEntriesOut {
						for _, entry := range entrySet {
							expectedEntriesOut[entry.EntryId] = entry
						}
					}

					if withPagination {
						require.Equal(t, tt.expectPagedTokensIn, tokensIn, "unexpected request tokens")
					} else {
						require.Empty(t, tokensIn, "unexpected request tokens")
					}

					require.Len(t, actualEntriesOut, len(expectedEntriesOut), "unexpected number of entries returned")
					for id, expectedEntry := range expectedEntriesOut {
						if _, ok := actualEntriesOut[id]; !ok {
							t.Errorf("Expected entry %q not found", id)
							continue
						}
						sort.Strings(actualEntriesOut[id].FederatesWith)
						assertCreatedAtField(t, actualEntriesOut[id], expectedEntry.CreatedAt)
						sortSelectors(actualEntriesOut[id].Selectors)
						sortSelectors(expectedEntry.Selectors)
						spiretest.AssertProtoEqual(t, expectedEntry, actualEntriesOut[id])
					}
				})
			}
		}
	}
}

// TestCreateRegistrationEntry migrates the original TestCreateRegistrationEntry
// behavior into the shared dstest package.
func TestCreateRegistrationEntry(t *testing.T, ds datastore.DataStore) {
	now := time.Now().Unix()
	var validRegistrationEntries []*common.RegistrationEntry
	require.NoError(t, readJSON(filepath.Join("..", "sqlstore", "testdata", "valid_registration_entries.json"), &validRegistrationEntries))

	for _, validRegistrationEntry := range validRegistrationEntries {
		registrationEntry, err := ds.CreateRegistrationEntry(ctx, validRegistrationEntry)
		require.NoError(t, err)
		require.NotNil(t, registrationEntry)
		AssertEntryEqual(t, validRegistrationEntry, registrationEntry, now)
	}
}

// TestCreateOrReturnRegistrationEntry migrates the original test's behavior.
func TestCreateOrReturnRegistrationEntry(t *testing.T, ds datastore.DataStore) {
	now := time.Now().Unix()

	cases := []struct {
		name          string
		modifyEntry   func(*common.RegistrationEntry) *common.RegistrationEntry
		expectError   string
		expectSimilar bool
		matchEntryID  bool
	}{
		{
			name:        "no entry provided",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry { return nil },
			expectError: "rpc error: code = InvalidArgument desc = datastore-validation: invalid request: missing registered entry",
		},
		{
			name:        "no selectors",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry { e.Selectors = nil; return e },
			expectError: "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: missing selector list",
		},
		{
			name:        "no SPIFFE ID",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry { e.SpiffeId = ""; return e },
			expectError: "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: missing SPIFFE ID",
		},
		{
			name:        "negative X509 ttl",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry { e.X509SvidTtl = -1; return e },
			expectError: "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: X509SvidTtl is not set",
		},
		{
			name:        "negative JWT ttl",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry { e.JwtSvidTtl = -1; return e },
			expectError: "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: JwtSvidTtl is not set",
		},
		{
			name:        "create entry successfully",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry { return e },
		},
		{
			name: "subset selectors",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.Selectors = []*common.Selector{{Type: "a", Value: "1"}}
				return e
			},
		},
		{
			name: "with superset selectors",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.Selectors = []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}, {Type: "c", Value: "3"}}
				return e
			},
		},
		{
			name: "same selectors but different SPIFFE IDs",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.SpiffeId = "spiffe://example.org/baz"
				return e
			},
		},
		{
			name: "with custom entry ID",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.EntryId = "some_ID_1"
				e.SpiffeId = "spiffe://example.org/bar"
				return e
			},
			matchEntryID: true,
		},
		{
			name:          "failed to create similar entry",
			modifyEntry:   func(e *common.RegistrationEntry) *common.RegistrationEntry { return e },
			expectSimilar: true,
		},
		{
			name:          "failed to create similar entry with different entry ID",
			modifyEntry:   func(e *common.RegistrationEntry) *common.RegistrationEntry { e.EntryId = "some_ID_2"; return e },
			expectSimilar: true,
		},
		{
			name: "entry ID too long",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.EntryId = strings.Repeat("e", 256)
				return e
			},
			expectError: "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: entry ID too long",
		},
		{
			name:        "entry ID contains invalid characters",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry { e.EntryId = "éntry😊"; return e },
			expectError: "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: entry ID contains invalid characters",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			entry := &common.RegistrationEntry{
				SpiffeId:    "spiffe://example.org/foo",
				ParentId:    "spiffe://example.org/bar",
				Selectors:   []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
				X509SvidTtl: 1,
				JwtSvidTtl:  1,
				DnsNames:    []string{"abcd.efg", "somehost"},
			}
			entry = tt.modifyEntry(entry)

			createdEntry, alreadyExists, err := ds.CreateOrReturnRegistrationEntry(ctx, entry)

			require.Equal(t, tt.expectSimilar, alreadyExists)
			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				require.Nil(t, createdEntry)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, createdEntry)
			if tt.matchEntryID {
				require.Equal(t, entry.EntryId, createdEntry.EntryId)
			} else {
				require.NotEqual(t, entry.EntryId, createdEntry.EntryId)
			}
			AssertEntryEqual(t, entry, createdEntry, now)
		})
	}
}

// TestCreateInvalidRegistrationEntry migrates invalid entry creation tests.
func TestCreateInvalidRegistrationEntry(t *testing.T, ds datastore.DataStore) {
	var invalidRegistrationEntries []*common.RegistrationEntry
	require.NoError(t, readJSON(filepath.Join("..", "sqlstore", "testdata", "invalid_registration_entries.json"), &invalidRegistrationEntries))

	for _, invalidRegistrationEntry := range invalidRegistrationEntries {
		registrationEntry, err := ds.CreateRegistrationEntry(ctx, invalidRegistrationEntry)
		require.Error(t, err)
		require.Nil(t, registrationEntry)
	}
}

// TestFetchRegistrationEntry migrates fetch-by-id tests.
func TestFetchRegistrationEntry(t *testing.T, ds datastore.DataStore) {
	for _, tt := range []struct {
		name  string
		entry *common.RegistrationEntry
	}{
		{
			name: "entry with dns",
			entry: &common.RegistrationEntry{
				Selectors:   []*common.Selector{{Type: "Type1", Value: "Value1"}, {Type: "Type2", Value: "Value2"}, {Type: "Type3", Value: "Value3"}},
				SpiffeId:    "SpiffeId",
				ParentId:    "ParentId",
				X509SvidTtl: 1,
				DnsNames:    []string{"abcd.efg", "somehost"},
			},
		},
		{
			name: "entry with store svid",
			entry: &common.RegistrationEntry{
				Selectors:   []*common.Selector{{Type: "Type1", Value: "Value1"}},
				SpiffeId:    "SpiffeId",
				ParentId:    "ParentId",
				X509SvidTtl: 1,
				StoreSvid:   true,
			},
		},
		{
			name: "entry with hint",
			entry: &common.RegistrationEntry{
				Selectors:   []*common.Selector{{Type: "Type1", Value: "Value1"}},
				SpiffeId:    "SpiffeId",
				ParentId:    "ParentId",
				X509SvidTtl: 1,
				Hint:        "external",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			createdEntry, err := ds.CreateRegistrationEntry(ctx, tt.entry)
			require.NoError(t, err)
			require.NotNil(t, createdEntry)

			fetchedRegistrationEntry, err := ds.FetchRegistrationEntry(ctx, createdEntry.EntryId)
			require.NoError(t, err)
			require.Equal(t, createdEntry, fetchedRegistrationEntry)
		})
	}
}

// TestFetchRegistrationEntryDoesNotExist ensures fetching a non-existent entry returns nil
func TestFetchRegistrationEntryDoesNotExist(t *testing.T, ds datastore.DataStore) {
	fetchedRegistrationEntry, err := ds.FetchRegistrationEntry(ctx, "does-not-exist")
	require.NoError(t, err)
	require.Nil(t, fetchedRegistrationEntry)
}

// TestFetchRegistrationEntries migrates batch fetch tests.
func TestFetchRegistrationEntries(t *testing.T, ds datastore.DataStore) {
	entry1, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{Selectors: []*common.Selector{{Type: "Type1", Value: "Value1"}}, SpiffeId: "SpiffeId1", ParentId: "ParentId1"})
	require.NoError(t, err)
	require.NotNil(t, entry1)
	entry2, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{Selectors: []*common.Selector{{Type: "Type2", Value: "Value2"}}, SpiffeId: "SpiffeId2", ParentId: "ParentId2"})
	require.NoError(t, err)
	require.NotNil(t, entry2)
	entry3, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{Selectors: []*common.Selector{{Type: "Type3", Value: "Value3"}}, SpiffeId: "SpiffeId3", ParentId: "ParentId3"})
	require.NoError(t, err)
	require.NotNil(t, entry3)

	// Create an entry and then delete it so we can test it doesn't get returned with the fetch
	entry4, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{Selectors: []*common.Selector{{Type: "Type4", Value: "Value4"}}, SpiffeId: "SpiffeId4", ParentId: "ParentId4"})
	require.NoError(t, err)
	require.NotNil(t, entry4)
	deletedEntry, err := ds.DeleteRegistrationEntry(ctx, entry4.EntryId)
	require.NotNil(t, deletedEntry)
	require.NoError(t, err)

	for _, tt := range []struct {
		name           string
		entries        []*common.RegistrationEntry
		deletedEntryId string
	}{
		{name: "No entries"},
		{name: "Entries 1 and 2", entries: []*common.RegistrationEntry{entry1, entry2}},
		{name: "Entries 1 and 3", entries: []*common.RegistrationEntry{entry1, entry3}},
		{name: "Entries 1, 2, and 3", entries: []*common.RegistrationEntry{entry1, entry2, entry3}},
		{name: "Deleted entry", entries: []*common.RegistrationEntry{entry2, entry3}, deletedEntryId: deletedEntry.EntryId},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entryIds := make([]string, 0, len(tt.entries))
			for _, entry := range tt.entries {
				entryIds = append(entryIds, entry.EntryId)
			}
			fetchedRegistrationEntries, err := ds.FetchRegistrationEntries(ctx, append(entryIds, tt.deletedEntryId))
			require.NoError(t, err)

			require.Equal(t, len(tt.entries), len(fetchedRegistrationEntries))
			for _, entry := range tt.entries {
				fetchedRegistrationEntry, ok := fetchedRegistrationEntries[entry.EntryId]
				require.True(t, ok)
				require.Equal(t, entry, fetchedRegistrationEntry)
			}

			_, ok := fetchedRegistrationEntries[tt.deletedEntryId]
			require.False(t, ok)
		})
	}
}
