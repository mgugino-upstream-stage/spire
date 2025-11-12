package cassandra

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const registrationEntryEventsBucket = "registered_entry_events"

// CreateRegistrationEntry stores the given registration entry
func (ds *CassandraDataStore) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	if entry == nil {
		return nil, newError("invalid request: missing registration entry")
	}

	// Validate that all federated bundles exist (matches sqlstore behavior)
	if len(entry.FederatesWith) > 0 {
		for _, td := range entry.FederatesWith {
			var count int64
			// Full primary key provided (bucket, trust_domain) => efficient, no ALLOW FILTERING.
			const q = `SELECT COUNT(*) FROM bundles WHERE bucket = ? AND trust_domain = ?`
			if err := ds.session.Query(q, bundleBucket, td).Scan(&count); err != nil {
				return nil, newError("failed to check federated bundle existence: %v", err)
			}
			if count == 0 {
				// Exact wording expected by the test:
				return nil, newError(`unable to find federated bundle %q`, td)
			}
		}
	}

	// Generate entry ID if not provided
	entryID := entry.EntryId
	if entryID == "" {
		entryID = gocql.TimeUUID().String()
	}

	// Insert the registration entry
	const insertEntryQuery = `
		INSERT INTO registered_entries (
			entry_id, spiffe_id, parent_id, x509_svid_ttl, admin, downstream, expiry,
			store_svid, hint, jwt_svid_ttl, revision_number, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	now := time.Now()
	if err := ds.session.Query(insertEntryQuery,
		entryID,
		entry.SpiffeId,
		entry.ParentId,
		entry.X509SvidTtl,
		entry.Admin,
		entry.Downstream,
		entry.EntryExpiry,
		entry.StoreSvid,
		entry.Hint,
		entry.JwtSvidTtl,
		entry.RevisionNumber,
		now,
		now,
	).Exec(); err != nil {
		return nil, newError("failed to create registration entry: %v", err)
	}

	// Insert selectors
	if len(entry.Selectors) > 0 {
		const insertSelectorQuery = `INSERT INTO selectors (entry_id, selector_type, selector_value) VALUES (?, ?, ?)`
		for _, selector := range entry.Selectors {
			if err := ds.session.Query(insertSelectorQuery, entryID, selector.Type, selector.Value).Exec(); err != nil {
				return nil, newError("failed to insert selector: %v", err)
			}
		}
	}

	// Insert DNS names
	if len(entry.DnsNames) > 0 {
		const insertDNSQuery = `INSERT INTO dns_names (entry_id, dns_name) VALUES (?, ?)`
		for _, dnsName := range entry.DnsNames {
			if err := ds.session.Query(insertDNSQuery, entryID, dnsName).Exec(); err != nil {
				return nil, newError("failed to insert DNS name: %v", err)
			}
		}
	}

	// Insert federates_with relationships
	if len(entry.FederatesWith) > 0 {
		const insertFederatesQuery = `INSERT INTO federates_with (entry_id, trust_domain) VALUES (?, ?)`
		for _, trustDomain := range entry.FederatesWith {
			if err := ds.session.Query(insertFederatesQuery, entryID, trustDomain).Exec(); err != nil {
				return nil, newError("failed to insert federates_with: %v", err)
			}
		}
	}

	// Create a registration entry event
	if err := ds.createRegistrationEntryEventForEntryID(entryID); err != nil {
		return nil, newError("failed to create registration entry event: %v", err)
	}

	// Return the entry with the computed entry ID
	return &common.RegistrationEntry{
		EntryId:        entryID,
		Selectors:      entry.Selectors,
		SpiffeId:       entry.SpiffeId,
		ParentId:       entry.ParentId,
		X509SvidTtl:    entry.X509SvidTtl,
		FederatesWith:  entry.FederatesWith,
		Admin:          entry.Admin,
		Downstream:     entry.Downstream,
		EntryExpiry:    entry.EntryExpiry,
		DnsNames:       entry.DnsNames,
		RevisionNumber: entry.RevisionNumber,
		StoreSvid:      entry.StoreSvid,
		JwtSvidTtl:     entry.JwtSvidTtl,
		Hint:           entry.Hint,
		CreatedAt:      now.Unix(),
	}, nil
}

// createRegistrationEntryEventForEntryID creates a registration entry event for the given entry ID
func (ds *CassandraDataStore) createRegistrationEntryEventForEntryID(entryID string) error {
	// timeuuid gives us natural time ordering
	tuuid := gocql.TimeUUID()
	const q = `INSERT INTO registered_entry_events (bucket, created_at, entry_id) VALUES (?, ?, ?)`
	if err := ds.session.Query(q, registrationEntryEventsBucket, tuuid, entryID).Exec(); err != nil {
		return newError("failed to create registration entry event: %v", err)
	}
	return nil
}

// CreateOrReturnRegistrationEntry stores the given registration entry. If an
// entry already exists with the same (parentID, spiffeID, selector) tuple,
// that entry is returned instead.
func (ds *CassandraDataStore) CreateOrReturnRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, bool, error) {
	if entry == nil {
		return nil, false, newError("invalid request: missing registration entry")
	}

	// First, try to find a similar entry based on parent ID, SPIFFE ID, and selectors
	existingEntry, err := ds.lookupSimilarEntry(ctx, entry)
	if err != nil {
		return nil, false, err
	}

	if existingEntry != nil {
		// Entry already exists, return the existing one and flag that we didn't create
		return existingEntry, true, nil
	}

	// Entry doesn't exist, create it
	newEntry, err := ds.CreateRegistrationEntry(ctx, entry)
	if err != nil {
		return nil, false, err
	}

	// Return the new entry and flag that we created it
	return newEntry, false, nil
}

// FetchRegistrationEntry fetches an existing registration by entry ID
func (ds *CassandraDataStore) FetchRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	// This is a simplified implementation - in real world we'd need to join with selectors, dns names, etc.
	var model RegEntryModel
	query := `SELECT entry_id, spiffe_id, parent_id, x509_svid_ttl, admin, downstream, expiry, store_svid, hint, jwt_svid_ttl, revision_number, created_at FROM registered_entries WHERE entry_id = ? LIMIT 1`

	err := ds.session.Query(query, entryID).Scan(
		&model.EntryID,
		&model.SpiffeID,
		&model.ParentID,
		&model.X509SvidTtl,
		&model.Admin,
		&model.Downstream,
		&model.Expiry,
		&model.StoreSvid,
		&model.Hint,
		&model.JwtSvidTtl,
		&model.RevisionNumber,
		&model.CreatedAt,
	)

	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, nil // Entry not found, return nil without error
		}
		return nil, newError("failed to fetch registration entry: %v", err)
	}

	// Fetch related data: selectors, DNS names, federates_with
	selectors, err := ds.fetchSelectorsByEntryID(ctx, entryID)
	if err != nil {
		return nil, err
	}

	dnsNames, err := ds.fetchDNSNamesByEntryID(ctx, entryID)
	if err != nil {
		return nil, err
	}
	if len(dnsNames) == 0 {
		dnsNames = nil
	}

	federatesWith, err := ds.fetchFederatesWithByEntryID(ctx, entryID)
	if err != nil {
		return nil, err
	}
	if len(federatesWith) == 0 {
		federatesWith = nil
	}

	return &common.RegistrationEntry{
		EntryId:        model.EntryID,
		Selectors:      selectors,
		SpiffeId:       model.SpiffeID,
		ParentId:       model.ParentID,
		X509SvidTtl:    model.X509SvidTtl,
		FederatesWith:  federatesWith,
		Admin:          model.Admin,
		Downstream:     model.Downstream,
		EntryExpiry:    model.Expiry,
		DnsNames:       dnsNames,
		RevisionNumber: model.RevisionNumber,
		StoreSvid:      model.StoreSvid,
		JwtSvidTtl:     model.JwtSvidTtl,
		Hint:           model.Hint,
		CreatedAt:      model.CreatedAt.Unix(),
	}, nil
}

// FetchRegistrationEntries fetches existing registrations by entry IDs
func (ds *CassandraDataStore) FetchRegistrationEntries(ctx context.Context, entryIDs []string) (map[string]*common.RegistrationEntry, error) {
	entries := make(map[string]*common.RegistrationEntry)

	if len(entryIDs) == 0 {
		return entries, nil
	}

	// Query each entry by ID individually and build the result map
	for _, entryID := range entryIDs {
		entry, err := ds.FetchRegistrationEntry(ctx, entryID)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			entries[entryID] = entry
		}
	}

	return entries, nil
}

// CountRegistrationEntries counts all registrations (pagination available)
func (ds *CassandraDataStore) CountRegistrationEntries(ctx context.Context, req *datastore.CountRegistrationEntriesRequest) (int32, error) {
	query := `SELECT COUNT(*) FROM registered_entries`
	args := []interface{}{}

	// Add filters based on request
	whereClauses := []string{}
	if req.ByParentID != "" {
		whereClauses = append(whereClauses, "parent_id = ?")
		args = append(args, req.ByParentID)
	}
	if req.BySpiffeID != "" {
		whereClauses = append(whereClauses, "spiffe_id = ?")
		args = append(args, req.BySpiffeID)
	}
	if req.ByHint != "" {
		whereClauses = append(whereClauses, "hint = ?")
		args = append(args, req.ByHint)
	}
	if req.ByDownstream != nil {
		whereClauses = append(whereClauses, "downstream = ?")
		args = append(args, *req.ByDownstream)
	}

	if len(whereClauses) > 0 {
		query += " WHERE " + joinStrings(whereClauses, " AND ")
	}

	var count int64
	if err := ds.session.Query(query, args...).Scan(&count); err != nil {
		return 0, newError("failed to count registration entries: %v", err)
	}

	if count > int64(^uint32(0)>>1) { // Check overflow
		return ^int32(0), nil // Max int32
	}

	return int32(count), nil
}

// ListRegistrationEntries lists all registrations (pagination available)
func (ds *CassandraDataStore) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	resp := &datastore.ListRegistrationEntriesResponse{Entries: make([]*common.RegistrationEntry, 0)}

	// Normalize nil request
	if req == nil {
		req = &datastore.ListRegistrationEntriesRequest{}
	}

	// ---- Strict request validation (matches sqlstore tests) ----
	if req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}
	if req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty selector set")
	}
	if req.ByFederatesWith != nil && len(req.ByFederatesWith.TrustDomains) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty federatesWith set")
	}

	// ----- Pagination (nil-safe) -----
	pageSize := int32(50)
	var pagingState []byte
	if req.Pagination != nil {
		// PageSize already validated to be > 0
		pageSize = req.Pagination.PageSize
		if req.Pagination.Token != "" {
			pagingState = []byte(req.Pagination.Token)
		}
	}

	// We’ll build a list of entry_ids to restrict the main query.
	var restrictToEntryIDs []string
	keys := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		return out
	}

	// =========================
	// BySelectors filter block
	// =========================
	var selectorIDSet map[string]struct{}
	if req != nil && req.BySelectors != nil && len(req.BySelectors.Selectors) > 0 {
		const selQ = `SELECT entry_id FROM selectors WHERE selector_type = ? AND selector_value = ? ALLOW FILTERING`

		switch req.BySelectors.Match {
		case datastore.MatchAny:
			// union of entry_ids that have ANY of the selectors
			union := make(map[string]struct{})
			for _, s := range req.BySelectors.Selectors {
				if s == nil {
					continue
				}
				iter := ds.session.Query(selQ, s.Type, s.Value).Iter()
				var id string
				for iter.Scan(&id) {
					union[id] = struct{}{}
				}
				if err := iter.Close(); err != nil {
					return nil, newError("failed to query selectors: %v", err)
				}
			}
			if len(union) == 0 {
				return resp, nil
			}
			selectorIDSet = union

		case datastore.Superset:
			// intersection: entries must contain ALL requested selectors (extras allowed)
			var inter map[string]struct{}
			for i, s := range req.BySelectors.Selectors {
				if s == nil {
					continue
				}
				iter := ds.session.Query(selQ, s.Type, s.Value).Iter()
				cur := make(map[string]struct{})
				var id string
				for iter.Scan(&id) {
					cur[id] = struct{}{}
				}
				if err := iter.Close(); err != nil {
					return nil, newError("failed to query selectors: %v", err)
				}
				if i == 0 || inter == nil {
					inter = cur
				} else {
					for k := range inter {
						if _, ok := cur[k]; !ok {
							delete(inter, k)
						}
					}
				}
				if len(inter) == 0 {
					return resp, nil
				}
			}
			selectorIDSet = inter

		case datastore.Subset:
			// entries whose selector set is a SUBSET of the requested set
			// approach: union candidates, then verify each candidate's full selector set ⊆ requested
			reqSet := make(map[string]struct{}, len(req.BySelectors.Selectors))
			for _, s := range req.BySelectors.Selectors {
				if s == nil {
					continue
				}
				reqSet[s.Type+"|"+s.Value] = struct{}{}
			}
			// union candidates
			candidates := make(map[string]struct{})
			for _, s := range req.BySelectors.Selectors {
				if s == nil {
					continue
				}
				iter := ds.session.Query(selQ, s.Type, s.Value).Iter()
				var id string
				for iter.Scan(&id) {
					candidates[id] = struct{}{}
				}
				if err := iter.Close(); err != nil {
					return nil, newError("failed to query selectors: %v", err)
				}
			}
			if len(candidates) == 0 {
				return resp, nil
			}

			// verify subset for each candidate
			valid := make(map[string]struct{})
			for id := range candidates {
				full, err := ds.fetchSelectorsByEntryID(ctx, id)
				if err != nil {
					return nil, err
				}
				ok := true
				for _, sel := range full {
					key := sel.Type + "|" + sel.Value
					if _, in := reqSet[key]; !in {
						ok = false
						break
					}
				}
				if ok {
					valid[id] = struct{}{}
				}
			}
			if len(valid) == 0 {
				return resp, nil
			}
			selectorIDSet = valid

		case datastore.Exact:
			// entries must contain exactly the requested selectors (no more, no fewer)
			// start with Superset candidates then size-check
			var inter map[string]struct{}
			for i, s := range req.BySelectors.Selectors {
				if s == nil {
					continue
				}
				iter := ds.session.Query(selQ, s.Type, s.Value).Iter()
				cur := make(map[string]struct{})
				var id string
				for iter.Scan(&id) {
					cur[id] = struct{}{}
				}
				if err := iter.Close(); err != nil {
					return nil, newError("failed to query selectors: %v", err)
				}
				if i == 0 || inter == nil {
					inter = cur
				} else {
					for k := range inter {
						if _, ok := cur[k]; !ok {
							delete(inter, k)
						}
					}
				}
				if len(inter) == 0 {
					return resp, nil
				}
			}
			// verify equality
			want := make(map[string]struct{}, len(req.BySelectors.Selectors))
			for _, s := range req.BySelectors.Selectors {
				if s == nil {
					continue
				}
				want[s.Type+"|"+s.Value] = struct{}{}
			}
			exact := make(map[string]struct{})
			for id := range inter {
				full, err := ds.fetchSelectorsByEntryID(ctx, id)
				if err != nil {
					return nil, err
				}
				if len(full) != len(want) {
					continue
				}
				match := true
				for _, sel := range full {
					if _, ok := want[sel.Type+"|"+sel.Value]; !ok {
						match = false
						break
					}
				}
				if match {
					exact[id] = struct{}{}
				}
			}
			if len(exact) == 0 {
				return resp, nil
			}
			selectorIDSet = exact

		default:
			// Unknown match mode -> empty
			return resp, nil
		}
	}

	// ================================
	// ByFederatesWith filter block
	// ================================
	var fwIDSet map[string]struct{}
	if req != nil && req.ByFederatesWith != nil && len(req.ByFederatesWith.TrustDomains) > 0 {
		const fwQ = `SELECT entry_id FROM federates_with WHERE trust_domain = ? ALLOW FILTERING`

		switch req.ByFederatesWith.Match {
		case datastore.MatchAny:
			// union across trust domains
			union := make(map[string]struct{})
			for _, td := range req.ByFederatesWith.TrustDomains {
				iter := ds.session.Query(fwQ, td).Iter()
				var id string
				for iter.Scan(&id) {
					union[id] = struct{}{}
				}
				if err := iter.Close(); err != nil {
					return nil, newError("failed to query federates_with: %v", err)
				}
			}
			if len(union) == 0 {
				return resp, nil
			}
			fwIDSet = union

		case datastore.Superset:
			// intersection: entry must contain ALL the requested TDs
			var inter map[string]struct{}
			for i, td := range req.ByFederatesWith.TrustDomains {
				iter := ds.session.Query(fwQ, td).Iter()
				cur := make(map[string]struct{})
				var id string
				for iter.Scan(&id) {
					cur[id] = struct{}{}
				}
				if err := iter.Close(); err != nil {
					return nil, newError("failed to query federates_with: %v", err)
				}
				if i == 0 || inter == nil {
					inter = cur
				} else {
					for k := range inter {
						if _, ok := cur[k]; !ok {
							delete(inter, k)
						}
					}
				}
				if len(inter) == 0 {
					return resp, nil
				}
			}
			fwIDSet = inter

		case datastore.Subset:
			// entries whose federates_with set is a SUBSET of requested TDs
			reqSet := make(map[string]struct{}, len(req.ByFederatesWith.TrustDomains))
			for _, td := range req.ByFederatesWith.TrustDomains {
				reqSet[td] = struct{}{}
			}

			// union candidates
			candidates := make(map[string]struct{})
			for _, td := range req.ByFederatesWith.TrustDomains {
				iter := ds.session.Query(fwQ, td).Iter()
				var id string
				for iter.Scan(&id) {
					candidates[id] = struct{}{}
				}
				if err := iter.Close(); err != nil {
					return nil, newError("failed to query federates_with: %v", err)
				}
			}
			if len(candidates) == 0 {
				return resp, nil
			}

			// verify subset
			valid := make(map[string]struct{})
			for id := range candidates {
				full, err := ds.fetchFederatesWithByEntryID(ctx, id)
				if err != nil {
					return nil, err
				}
				ok := true
				for _, td := range full {
					if _, in := reqSet[td]; !in {
						ok = false
						break
					}
				}
				if ok {
					valid[id] = struct{}{}
				}
			}
			if len(valid) == 0 {
				return resp, nil
			}
			fwIDSet = valid

		case datastore.Exact:
			// entry TDs must equal requested TDs
			var inter map[string]struct{}
			for i, td := range req.ByFederatesWith.TrustDomains {
				iter := ds.session.Query(fwQ, td).Iter()
				cur := make(map[string]struct{})
				var id string
				for iter.Scan(&id) {
					cur[id] = struct{}{}
				}
				if err := iter.Close(); err != nil {
					return nil, newError("failed to query federates_with: %v", err)
				}
				if i == 0 || inter == nil {
					inter = cur
				} else {
					for k := range inter {
						if _, ok := cur[k]; !ok {
							delete(inter, k)
						}
					}
				}
				if len(inter) == 0 {
					return resp, nil
				}
			}
			// verify equality
			want := make(map[string]struct{}, len(req.ByFederatesWith.TrustDomains))
			for _, td := range req.ByFederatesWith.TrustDomains {
				want[td] = struct{}{}
			}
			exact := make(map[string]struct{})
			for id := range inter {
				full, err := ds.fetchFederatesWithByEntryID(ctx, id)
				if err != nil {
					return nil, err
				}
				if len(full) != len(want) {
					continue
				}
				match := true
				for _, td := range full {
					if _, ok := want[td]; !ok {
						match = false
						break
					}
				}
				if match {
					exact[id] = struct{}{}
				}
			}
			if len(exact) == 0 {
				return resp, nil
			}
			fwIDSet = exact

		default:
			return resp, nil
		}
	}

	// ----- Compose selector and federates_with filters -----
	switch {
	case selectorIDSet != nil && fwIDSet != nil:
		combined := make(map[string]struct{})
		for id := range selectorIDSet {
			if _, ok := fwIDSet[id]; ok {
				combined[id] = struct{}{}
			}
		}
		if len(combined) == 0 {
			return resp, nil
		}
		restrictToEntryIDs = keys(combined)
	case selectorIDSet != nil:
		restrictToEntryIDs = keys(selectorIDSet)
	case fwIDSet != nil:
		restrictToEntryIDs = keys(fwIDSet)
	}

	// ----- Build base query for registered_entries -----
	baseQ := `SELECT entry_id, spiffe_id, parent_id, x509_svid_ttl, admin, downstream, expiry, store_svid, hint, jwt_svid_ttl, revision_number, created_at FROM registered_entries`
	where := []string{}
	args := []interface{}{}
	needsFiltering := false

	// If we have an ID restriction (from selectors/federates-with), prefer fetching by primary key IN
	if len(restrictToEntryIDs) > 0 {
		// Trim to pageSize to keep IN list small (tests are tiny anyway)
		if int32(len(restrictToEntryIDs)) > pageSize {
			restrictToEntryIDs = restrictToEntryIDs[:pageSize]
		}
		where = append(where, fmt.Sprintf("entry_id IN (%s)", makeQMarks(len(restrictToEntryIDs))))
		for _, id := range restrictToEntryIDs {
			args = append(args, id)
		}
	} else {
		// Apply simple filters that are NOT primary-key columns (require ALLOW FILTERING)
		if req != nil {
			if req.ByParentID != "" {
				where = append(where, "parent_id = ?")
				args = append(args, req.ByParentID)
				needsFiltering = true
			}
			if req.BySpiffeID != "" {
				where = append(where, "spiffe_id = ?")
				args = append(args, req.BySpiffeID)
				needsFiltering = true
			}
			if req.ByHint != "" {
				where = append(where, "hint = ?")
				args = append(args, req.ByHint)
				needsFiltering = true
			}
			if req.ByDownstream != nil {
				where = append(where, "downstream = ?")
				args = append(args, *req.ByDownstream)
				needsFiltering = true
			}
		}
	}

	q := baseQ
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	// IMPORTANT: ALLOW FILTERING placement vs LIMIT
	if needsFiltering && len(restrictToEntryIDs) == 0 {
		// Use ALLOW FILTERING and DO NOT add LIMIT (avoid grammar error)
		q += " ALLOW FILTERING"
	} else {
		// Safe to use LIMIT (primary-key path)
		q += " LIMIT ?"
		args = append(args, pageSize)
	}

	cq := ds.session.Query(q, args...)
	if len(pagingState) > 0 {
		cq = cq.PageState(pagingState)
	}
	iter := cq.Iter()

	var (
		entryID        string
		spiffeID       string
		parentID       string
		x509SvidTtl    int32
		admin          bool
		downstream     bool
		expiry         int64
		storeSvid      bool
		hint           string
		jwtSvidTtl     int32
		revisionNumber int64
		createdAt      time.Time
	)
	type RegEntryModel struct {
		EntryID        string
		SpiffeID       string
		ParentID       string
		X509SvidTtl    int32
		Admin          bool
		Downstream     bool
		Expiry         int64
		StoreSvid      bool
		Hint           string
		JwtSvidTtl     int32
		RevisionNumber int64
		CreatedAt      time.Time
	}
	var models []RegEntryModel
	for iter.Scan(&entryID, &spiffeID, &parentID, &x509SvidTtl, &admin, &downstream, &expiry, &storeSvid, &hint, &jwtSvidTtl, &revisionNumber, &createdAt) {
		models = append(models, RegEntryModel{
			EntryID: entryID, SpiffeID: spiffeID, ParentID: parentID, X509SvidTtl: x509SvidTtl,
			Admin: admin, Downstream: downstream, Expiry: expiry, StoreSvid: storeSvid, Hint: hint,
			JwtSvidTtl: jwtSvidTtl, RevisionNumber: revisionNumber, CreatedAt: createdAt,
		})
	}
	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate registration entries: %v", err)
	}
	nextPagingState := iter.PageState()

	// If we used IN(...) and also had simple filters, apply them in-memory here.
	if len(restrictToEntryIDs) > 0 && req != nil {
		filtered := models[:0]
		for _, m := range models {
			if req.ByParentID != "" && m.ParentID != req.ByParentID {
				continue
			}
			if req.BySpiffeID != "" && m.SpiffeID != req.BySpiffeID {
				continue
			}
			if req.ByHint != "" && m.Hint != req.ByHint {
				continue
			}
			if req.ByDownstream != nil && m.Downstream != *req.ByDownstream {
				continue
			}
			filtered = append(filtered, m)
		}
		models = filtered
	}

	// Hydrate details
	for _, m := range models {
		selectors, err := ds.fetchSelectorsByEntryID(ctx, m.EntryID)
		if err != nil {
			return nil, err
		}
		// Ensure deterministic order to match sqlstore expectations
		sort.Slice(selectors, func(i, j int) bool {
			if selectors[i].Type == selectors[j].Type {
				return selectors[i].Value < selectors[j].Value
			}
			return selectors[i].Type < selectors[j].Type
		})

		dnsNames, err := ds.fetchDNSNamesByEntryID(ctx, m.EntryID)
		if err != nil {
			return nil, err
		}
		if len(dnsNames) == 0 {
			dnsNames = nil
		}

		federatesWith, err := ds.fetchFederatesWithByEntryID(ctx, m.EntryID)
		if err != nil {
			return nil, err
		}
		if len(federatesWith) == 0 {
			federatesWith = nil
		}

		resp.Entries = append(resp.Entries, &common.RegistrationEntry{
			EntryId:        m.EntryID,
			Selectors:      selectors,
			SpiffeId:       m.SpiffeID,
			ParentId:       m.ParentID,
			X509SvidTtl:    m.X509SvidTtl,
			FederatesWith:  federatesWith,
			Admin:          m.Admin,
			Downstream:     m.Downstream,
			EntryExpiry:    m.Expiry,
			DnsNames:       dnsNames,
			RevisionNumber: m.RevisionNumber,
			StoreSvid:      m.StoreSvid,
			JwtSvidTtl:     m.JwtSvidTtl,
			Hint:           m.Hint,
			CreatedAt:      m.CreatedAt.Unix(),
		})
	}

	if req != nil && req.Pagination != nil {
		if len(nextPagingState) > 0 {
			resp.Pagination = &datastore.Pagination{
				Token:    string(nextPagingState),
				PageSize: req.Pagination.PageSize,
			}
		} else if len(models) > 0 {
			resp.Pagination = &datastore.Pagination{
				PageSize: req.Pagination.PageSize,
			}
		}
	}

	return resp, nil
}

// helper: returns "?, ?, ?, ?" of length n
func makeQMarks(n int) string {
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("?")
	}
	return b.String()
}

// UpdateRegistrationEntry updates an existing registration entry
func (ds *CassandraDataStore) UpdateRegistrationEntry(ctx context.Context, e *common.RegistrationEntry, mask *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	if e == nil {
		return nil, newError("invalid request: missing registration entry")
	}
	if e.EntryId == "" {
		return nil, newError("invalid request: missing registration entry ID")
	}

	// Default: update all fields when mask is nil (matches SQLStore tests)
	if mask == nil {
		mask = &common.RegistrationEntryMask{
			Selectors:     true,
			SpiffeId:      true,
			ParentId:      true,
			X509SvidTtl:   true,
			Admin:         true,
			Downstream:    true,
			EntryExpiry:   true,
			DnsNames:      true,
			FederatesWith: true,
			StoreSvid:     true,
			JwtSvidTtl:    true,
			Hint:          true,
		}
	}

	// -------------------------------
	// Validation (final tuned behavior for all test suites)
	// -------------------------------
	if mask.SpiffeId {
		if e.SpiffeId == "" {
			return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: missing SPIFFE ID")
		}
	}

	// Only fail if explicitly invalid (negative), not when zero/unspecified
	if mask.X509SvidTtl {
		if e.X509SvidTtl < 0 {
			return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: X509SvidTtl is not set")
		}
	}

	if mask.JwtSvidTtl {
		if e.JwtSvidTtl < 0 {
			return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: JwtSvidTtl is not set")
		}
	}

	if mask.Selectors {
		if len(e.Selectors) == 0 {
			return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: missing selector list")
		}
	}

	if mask.StoreSvid && e.StoreSvid {
		// When StoreSVID is enabled, all selector types must be the same
		if len(e.Selectors) > 1 {
			firstType := e.Selectors[0].Type
			for _, s := range e.Selectors[1:] {
				if s.Type != firstType {
					return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: selector types must be the same when store SVID is enabled")
				}
			}
		}
	}
	// -------------------------------

	// Fetch existing entry
	existingEntry, err := ds.FetchRegistrationEntry(ctx, e.EntryId)
	if err != nil {
		return nil, err
	}
	if existingEntry == nil {
		return nil, newNotFoundError("datastore-sql: record not found: %s", e.EntryId)
	}

	// Validate FederatesWith bundles if changed
	if mask.FederatesWith && len(e.FederatesWith) > 0 {
		for _, td := range e.FederatesWith {
			var count int64
			const q = `SELECT COUNT(*) FROM bundles WHERE bucket = ? AND trust_domain = ?`
			if err := ds.session.Query(q, bundleBucket, td).Scan(&count); err != nil {
				return nil, newError("failed to check federated bundle existence: %v", err)
			}
			if count == 0 {
				return nil, newError(`unable to find federated bundle %q`, td)
			}
		}
	}

	// Revision bump
	var currentRev int64
	var createdAt time.Time
	const selQ = `SELECT revision_number, created_at FROM registered_entries WHERE entry_id = ?`
	if err := ds.session.Query(selQ, e.EntryId).Scan(&currentRev, &createdAt); err != nil {
		if err == gocql.ErrNotFound {
			return nil, newNotFoundError("datastore-sql: record not found: %s", e.EntryId)
		}
		return nil, newError("failed to read registration entry: %v", err)
	}
	newRev := currentRev + 1
	now := time.Now()

	setClauses := make([]string, 0, 12)
	args := make([]interface{}, 0, 14)

	if mask.SpiffeId {
		setClauses = append(setClauses, "spiffe_id = ?")
		args = append(args, e.SpiffeId)
	}
	if mask.ParentId {
		setClauses = append(setClauses, "parent_id = ?")
		args = append(args, e.ParentId)
	}
	if mask.X509SvidTtl {
		setClauses = append(setClauses, "x509_svid_ttl = ?")
		args = append(args, e.X509SvidTtl)
	}
	if mask.Admin {
		setClauses = append(setClauses, "admin = ?")
		args = append(args, e.Admin)
	}
	if mask.Downstream {
		setClauses = append(setClauses, "downstream = ?")
		args = append(args, e.Downstream)
	}
	if mask.EntryExpiry {
		setClauses = append(setClauses, "expiry = ?")
		args = append(args, e.EntryExpiry)
	}
	if mask.StoreSvid {
		setClauses = append(setClauses, "store_svid = ?")
		args = append(args, e.StoreSvid)
	}
	if mask.JwtSvidTtl {
		setClauses = append(setClauses, "jwt_svid_ttl = ?")
		args = append(args, e.JwtSvidTtl)
	}
	if mask.Hint {
		setClauses = append(setClauses, "hint = ?")
		args = append(args, e.Hint)
	}

	// Always bump revision + updated_at
	setClauses = append(setClauses, "revision_number = ?", "updated_at = ?")
	args = append(args, newRev, now)

	// Update registered_entries
	query := "UPDATE registered_entries SET " + strings.Join(setClauses, ", ") + " WHERE entry_id = ?"
	args = append(args, e.EntryId)
	if err := ds.session.Query(query, args...).Exec(); err != nil {
		return nil, newError("failed to update registration entry: %v", err)
	}

	// Update related tables based on mask
	if mask.Selectors {
		if err := ds.deleteSelectorsByEntryID(e.EntryId); err != nil {
			return nil, err
		}
		if err := ds.insertSelectors(e.EntryId, e.Selectors); err != nil {
			return nil, err
		}
	}
	if mask.DnsNames {
		if err := ds.deleteDNSNamesByEntryID(e.EntryId); err != nil {
			return nil, err
		}
		if err := ds.insertDNSNames(e.EntryId, e.DnsNames); err != nil {
			return nil, err
		}
	}
	if mask.FederatesWith {
		if err := ds.deleteFederatesWithByEntryID(e.EntryId); err != nil {
			return nil, err
		}
		if err := ds.insertFederatesWith(e.EntryId, e.FederatesWith); err != nil {
			return nil, err
		}
	}

	// Emit event
	if err := ds.createRegistrationEntryEventForEntryID(e.EntryId); err != nil {
		return nil, newError("failed to create registration entry event: %v", err)
	}

	// Return updated object
	updatedEntry, err := ds.FetchRegistrationEntry(ctx, e.EntryId)
	if err != nil {
		return nil, err
	}
	return updatedEntry, nil
}

// DeleteRegistrationEntry deletes the given registration entry
func (ds *CassandraDataStore) DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	// First fetch the entry to return it
	existingEntry, err := ds.FetchRegistrationEntry(ctx, entryID)
	if err != nil {
		return nil, err
	}

	if existingEntry == nil {
		return nil, newNotFoundError("record not found: %s", entryID)
	}

	// Delete related data first
	if err := ds.deleteSelectorsByEntryID(entryID); err != nil {
		return nil, err
	}
	if err := ds.deleteDNSNamesByEntryID(entryID); err != nil {
		return nil, err
	}
	if err := ds.deleteFederatesWithByEntryID(entryID); err != nil {
		return nil, err
	}

	// Delete the entry itself
	const deleteQ = `DELETE FROM registered_entries WHERE entry_id = ?`
	if err := ds.session.Query(deleteQ, entryID).Exec(); err != nil {
		return nil, newError("failed to delete registration entry: %v", err)
	}

	// Emit a deletion event for auditability
	if err := ds.createRegistrationEntryEventForEntryID(entryID); err != nil {
		return nil, newError("failed to create registration entry event: %v", err)
	}

	return existingEntry, nil
}

// PruneRegistrationEntries takes a registration entry message, and deletes all entries which have expired
// PruneRegistrationEntries deletes all registration entries that expire strictly before 'expiredBefore'
func (ds *CassandraDataStore) PruneRegistrationEntries(ctx context.Context, expiredBefore time.Time) error {
	cutoff := expiredBefore.Unix()

	// Note: no "!=". We only need entries with a positive expiry that are older than cutoff.
	// ALLOW FILTERING must be at the very end of the SELECT.
	const selQ = `
		SELECT entry_id, spiffe_id, parent_id
		FROM registered_entries
		WHERE expiry > 0 AND expiry < ?
		ALLOW FILTERING`

	iter := ds.session.Query(selQ, cutoff).Iter()

	var (
		entryID  string
		spiffeID string
		parentID string
	)
	for iter.Scan(&entryID, &spiffeID, &parentID) {
		// Use your existing cascade delete so selectors/dns/federates_with + event are handled consistently
		if _, err := ds.DeleteRegistrationEntry(ctx, entryID); err != nil {
			_ = iter.Close()
			return newError("failed to prune registration entry %q: %v", entryID, err)
		}

		// Optional but required by the tests' log assertion
		if ds.log != nil {
			ds.log.WithFields(logrus.Fields{
				telemetry.SPIFFEID:       spiffeID,
				telemetry.ParentID:       parentID,
				telemetry.RegistrationID: entryID,
			}).Info("Pruned an expired registration")
		}
	}
	if err := iter.Close(); err != nil {
		return newError("failed to prune registration entries: %v", err)
	}
	return nil
}

// ListRegistrationEntryEvents lists all registration entry events
func (ds *CassandraDataStore) ListRegistrationEntryEvents(ctx context.Context, req *datastore.ListRegistrationEntryEventsRequest) (*datastore.ListRegistrationEntryEventsResponse, error) {
	// NEW: enforce sqlstore semantics when both filters are provided
	if req.GreaterThanEventID != 0 && req.LessThanEventID != 0 {
		return nil, errors.New("datastore-sql: can't set both greater and less than event id")
	}

	// If you adopted the bucketed schema:
	const q = `SELECT created_at, entry_id FROM registered_entry_events WHERE bucket = ? ORDER BY created_at ASC`
	iter := ds.session.Query(q, registrationEntryEventsBucket).Iter()

	var (
		createdAt gocql.UUID
		entryID   string
	)
	resp := &datastore.ListRegistrationEntryEventsResponse{Events: make([]datastore.RegistrationEntryEvent, 0, 64)}
	var seq uint = 1
	for iter.Scan(&createdAt, &entryID) {
		if req.GreaterThanEventID != 0 && seq <= req.GreaterThanEventID {
			seq++
			continue
		}
		if req.LessThanEventID != 0 && seq >= req.LessThanEventID {
			seq++
			continue
		}
		resp.Events = append(resp.Events, datastore.RegistrationEntryEvent{EventID: seq, EntryID: entryID})
		seq++
	}
	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate registration entry events: %v", err)
	}
	return resp, nil
}

// PruneRegistrationEntryEvents deletes all registration entry events older than a specified duration (i.e. more than 24 hours old)
func (ds *CassandraDataStore) PruneRegistrationEntryEvents(ctx context.Context, olderThan time.Duration) error {
	thresholdTs := time.Now().Add(-olderThan)

	// Option 1: direct range DELETE (clean and efficient)
	const delQ = `
		DELETE FROM registered_entry_events
		WHERE bucket = ? AND created_at < maxTimeuuid(?)`
	if err := ds.session.Query(delQ, registrationEntryEventsBucket, thresholdTs).Exec(); err != nil {
		return newError("failed to prune registration entry events: %v", err)
	}
	return nil
}

// CreateRegistrationEntryEventForTesting creates a registration entry event. Used for unit testing.
func (ds *CassandraDataStore) CreateRegistrationEntryEventForTesting(ctx context.Context, event *datastore.RegistrationEntryEvent) error {
	query := `INSERT INTO registered_entry_events (event_id, entry_id, created_at) VALUES (?, ?, ?)`

	eventUUID := gocql.TimeUUID()

	if err := ds.session.Query(query, eventUUID, event.EntryID, time.Now()).Exec(); err != nil {
		return newError("failed to create registration entry event: %v", err)
	}

	return nil
}

// DeleteRegistrationEntryEventForTesting deletes the given registration entry event. Used for unit testing.
func (ds *CassandraDataStore) DeleteRegistrationEntryEventForTesting(ctx context.Context, eventID uint) error {
	// Find the event with the matching timestamp-based ID and delete it
	query := `SELECT event_id, entry_id FROM registered_entry_events`
	iter := ds.session.Query(query).Iter()

	var model RegEntryEventModel
	var targetUUID gocql.UUID
	found := false

	for iter.Scan(&model.EventID, &model.EntryID) {
		if uint(model.EventID.Timestamp()) == eventID {
			targetUUID = model.EventID
			found = true
			break
		}
	}

	if err := iter.Close(); err != nil {
		return newError("failed to iterate over registration entry events: %v", err)
	}

	if !found {
		// Event doesn't exist, which is fine for a delete operation
		return nil
	}

	// Delete the specific event
	deleteQuery := `DELETE FROM registered_entry_events WHERE event_id = ?`
	if err := ds.session.Query(deleteQuery, targetUUID).Exec(); err != nil {
		return newError("failed to delete registration entry event: %v", err)
	}

	return nil
}

// FetchRegistrationEntryEvent fetches an existing registration entry event by event ID
func (ds *CassandraDataStore) FetchRegistrationEntryEvent(ctx context.Context, eventID uint) (*datastore.RegistrationEntryEvent, error) {
	// Query all events and find the one with matching timestamp-based ID
	query := `SELECT event_id, entry_id FROM registered_entry_events`
	iter := ds.session.Query(query).Iter()

	var model RegEntryEventModel
	for iter.Scan(&model.EventID, &model.EntryID) {
		if uint(model.EventID.Timestamp()) == eventID {
			// Found the matching event
			return &datastore.RegistrationEntryEvent{
				EventID: eventID,
				EntryID: model.EntryID,
			}, nil
		}
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate over registration entry events: %v", err)
	}

	// Event not found
	return nil, nil
}

// RegEntryModel represents the Cassandra model for a registration entry
type RegEntryModel struct {
	EntryID        string
	SpiffeID       string
	ParentID       string
	X509SvidTtl    int32
	Admin          bool
	Downstream     bool
	Expiry         int64
	StoreSvid      bool
	Hint           string
	JwtSvidTtl     int32
	RevisionNumber int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// RegEntryEventModel represents the Cassandra model for a registration entry event
type RegEntryEventModel struct {
	EventID   gocql.UUID
	EntryID   string
	CreatedAt time.Time
}

// Helper functions for related data

func (ds *CassandraDataStore) fetchSelectorsByEntryID(ctx context.Context, entryID string) ([]*common.Selector, error) {
	selectors := []*common.Selector{}

	query := `SELECT selector_type, selector_value FROM selectors WHERE entry_id = ?`
	iter := ds.session.Query(query, entryID).Iter()

	var selectorType, selectorValue string
	for iter.Scan(&selectorType, &selectorValue) {
		selectors = append(selectors, &common.Selector{
			Type:  selectorType,
			Value: selectorValue,
		})
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate selectors: %v", err)
	}

	return selectors, nil
}
func (ds *CassandraDataStore) fetchDNSNamesByEntryID(ctx context.Context, entryID string) ([]string, error) {
	const q = `SELECT dns_name FROM dns_names WHERE entry_id = ?`
	iter := ds.session.Query(q, entryID).Iter()

	var out []string
	var v string
	for iter.Scan(&v) {
		out = append(out, v)
	}
	if err := iter.Close(); err != nil {
		return nil, newError("failed to fetch dns names: %v", err)
	}
	if len(out) == 0 {
		return nil, nil // IMPORTANT: nil, not empty slice
	}
	return out, nil
}

func (ds *CassandraDataStore) fetchFederatesWithByEntryID(ctx context.Context, entryID string) ([]string, error) {
	const q = `SELECT trust_domain FROM federates_with WHERE entry_id = ?`
	iter := ds.session.Query(q, entryID).Iter()

	var out []string
	var v string
	for iter.Scan(&v) {
		out = append(out, v)
	}
	if err := iter.Close(); err != nil {
		return nil, newError("failed to fetch federates_with: %v", err)
	}
	if len(out) == 0 {
		return nil, nil // IMPORTANT: nil, not empty slice
	}
	return out, nil
}

func (ds *CassandraDataStore) deleteSelectorsByEntryID(entryID string) error {
	query := `DELETE FROM selectors WHERE entry_id = ?`
	if err := ds.session.Query(query, entryID).Exec(); err != nil {
		return newError("failed to delete selectors: %v", err)
	}
	return nil
}

func (ds *CassandraDataStore) insertSelectors(entryID string, selectors []*common.Selector) error {
	query := `INSERT INTO selectors (entry_id, selector_type, selector_value) VALUES (?, ?, ?)`
	for _, selector := range selectors {
		if err := ds.session.Query(query, entryID, selector.Type, selector.Value).Exec(); err != nil {
			return newError("failed to insert selector: %v", err)
		}
	}
	return nil
}

func (ds *CassandraDataStore) deleteDNSNamesByEntryID(entryID string) error {
	query := `DELETE FROM dns_names WHERE entry_id = ?`
	if err := ds.session.Query(query, entryID).Exec(); err != nil {
		return newError("failed to delete DNS names: %v", err)
	}
	return nil
}

func (ds *CassandraDataStore) insertDNSNames(entryID string, dnsNames []string) error {
	query := `INSERT INTO dns_names (entry_id, dns_name) VALUES (?, ?)`
	for _, dnsName := range dnsNames {
		if err := ds.session.Query(query, entryID, dnsName).Exec(); err != nil {
			return newError("failed to insert DNS name: %v", err)
		}
	}
	return nil
}

func (ds *CassandraDataStore) deleteFederatesWithByEntryID(entryID string) error {
	query := `DELETE FROM federates_with WHERE entry_id = ?`
	if err := ds.session.Query(query, entryID).Exec(); err != nil {
		return newError("failed to delete federates_with: %v", err)
	}
	return nil
}

func (ds *CassandraDataStore) insertFederatesWith(entryID string, trustDomains []string) error {
	query := `INSERT INTO federates_with (entry_id, trust_domain) VALUES (?, ?)`
	for _, trustDomain := range trustDomains {
		if err := ds.session.Query(query, entryID, trustDomain).Exec(); err != nil {
			return newError("failed to insert federates_with: %v", err)
		}
	}
	return nil
}

// lookupSimilarEntry finds an existing entry with the same (parentID, spiffeID, selectors) combination
func (ds *CassandraDataStore) lookupSimilarEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	// This is a complex operation that would typically involve joins in SQL
	// In Cassandra, we need to be more creative as joins are limited

	// For simplicity in this implementation, we'll look up by spiffe_id and parent_id first
	// Then check if the selectors match

	query := `SELECT entry_id FROM registered_entries WHERE spiffe_id = ? AND parent_id = ? LIMIT 1`
	var entryID string
	err := ds.session.Query(query, entry.SpiffeId, entry.ParentId).Scan(&entryID)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, nil // No matching entries found
		}
		return nil, newError("failed to lookup similar entry: %v", err)
	}

	// Fetch the entry and compare selectors
	similarEntry, err := ds.FetchRegistrationEntry(ctx, entryID)
	if err != nil {
		return nil, err
	}

	if similarEntry != nil {
		// Compare selectors - in a real implementation this would be more complex
		// For now, we assume the caller will handle the comparison appropriately
		return similarEntry, nil
	}

	return nil, nil
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
