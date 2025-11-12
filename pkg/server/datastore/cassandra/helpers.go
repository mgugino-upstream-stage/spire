package cassandra

import (
	"sort"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// sortSelectors (type,value) for stable comparisons in tests
func sortSelectors(ss []*common.Selector) {
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].Type == ss[j].Type {
			return ss[i].Value < ss[j].Value
		}
		return ss[i].Type < ss[j].Type
	})
}

// sortStrings in-place
func sortStrings(xs []string) {
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
}

// set builders
func toSelSet(ss []*common.Selector) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		if s == nil {
			continue
		}
		m[s.Type+"|"+s.Value] = struct{}{}
	}
	return m
}
func toStrSet(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}

// matchFederates mirrors selector matching but for trust domains ([]string).
func matchFederates(have []string, rule *datastore.ByFederatesWith) bool {
	if rule == nil {
		return true
	}
	tds := rule.TrustDomains
	if len(tds) == 0 {
		// tests expect InvalidArgument at the API layer; if called, treat as no-match
		return false
	}

	haveSet := toStrSet(have)
	wantSet := toStrSet(tds)

	switch rule.Match {
	case datastore.Exact:
		if len(haveSet) != len(wantSet) {
			return false
		}
		for k := range haveSet {
			if _, ok := wantSet[k]; !ok {
				return false
			}
		}
		return true

	case datastore.Superset:
		for k := range wantSet {
			if _, ok := haveSet[k]; !ok {
				return false
			}
		}
		return true

	case datastore.Subset:
		for k := range haveSet {
			if _, ok := wantSet[k]; !ok {
				return false
			}
		}
		return true

	case datastore.MatchAny:
		for k := range wantSet {
			if _, ok := haveSet[k]; ok {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// Helper function to join strings with a separator
func joinStrings(slice []string, sep string) string {
	if len(slice) == 0 {
		return ""
	}

	result := slice[0]
	for _, s := range slice[1:] {
		result += sep + s
	}
	return result
}

func invalidArg(msg string) error {
	return status.Error(codes.InvalidArgument, msg)
}

// tiny helpers
func ifThen[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
func ifThenI64(cond bool, a, b int64) int64 {
	if cond {
		return a
	}
	return b
}
func ifThenBool(cond bool, a, b bool) bool {
	if cond {
		return a
	}
	return b
}

// Helpers: "scan all ids" table to support ordered paging without illegal ORDER BY on base PK.
const regAllIDsBucket = "registered_entries_scan"

func (ds *CassandraDataStore) insertRegAllIDs(entryID string) error {
	const q = `INSERT INTO registered_entries_scan (bucket, entry_id) VALUES (?, ?)`
	if err := ds.session.Query(q, regAllIDsBucket, entryID).Exec(); err != nil {
		return newError("failed to insert into registered_entries_scan: %v", err)
	}
	return nil
}
func (ds *CassandraDataStore) deleteRegAllIDs(entryID string) error {
	const q = `DELETE FROM registered_entries_scan WHERE bucket = ? AND entry_id = ?`
	if err := ds.session.Query(q, regAllIDsBucket, entryID).Exec(); err != nil {
		return newError("failed to delete from registered_entries_scan: %v", err)
	}
	return nil
}
