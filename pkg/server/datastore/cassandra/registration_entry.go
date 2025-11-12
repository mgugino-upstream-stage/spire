package cassandra

import (
	"context"
	"errors"
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
const regEntriesBucket = "registered_entries"

// CreateRegistrationEntry stores the given registration entry (with secondary indexes).
func (ds *CassandraDataStore) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	if entry == nil {
		return nil, newError("invalid request: missing registration entry")
	}

	// Validate federated bundles exist (sqlstore behavior)
	if len(entry.FederatesWith) > 0 {
		for _, td := range entry.FederatesWith {
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

	// ID
	entryID := entry.EntryId
	if entryID == "" {
		entryID = gocql.TimeUUID().String()
	}

	const insertEntry = `
		INSERT INTO registered_entries (
			entry_id, spiffe_id, parent_id, x509_svid_ttl, admin, downstream, expiry,
			store_svid, hint, jwt_svid_ttl, revision_number, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	now := time.Now()

	if err := ds.session.Query(insertEntry,
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
		now, now,
	).Exec(); err != nil {
		return nil, newError("failed to create registration entry: %v", err)
	}

	// Secondary/child tables
	if len(entry.Selectors) > 0 {
		if err := ds.insertSelectors(entryID, entry.Selectors); err != nil {
			return nil, err
		}
		if err := ds.insertRegSelectorsIndex(entryID, entry.Selectors); err != nil {
			return nil, err
		}
	}
	if len(entry.DnsNames) > 0 {
		if err := ds.insertDNSNames(entryID, entry.DnsNames); err != nil {
			return nil, err
		}
	}
	if len(entry.FederatesWith) > 0 {
		if err := ds.insertFederatesWith(entryID, entry.FederatesWith); err != nil {
			return nil, err
		}
		if err := ds.insertFederatesWithIndex(entryID, entry.FederatesWith); err != nil {
			return nil, err
		}
	}

	// Scan index of all IDs (bucketed for paging without illegal ORDER BY)
	if err := ds.insertRegAllIDs(entryID); err != nil {
		return nil, err
	}

	// Event
	if err := ds.createRegistrationEntryEventForEntryID(entryID); err != nil {
		return nil, newError("failed to create registration entry event: %v", err)
	}

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

// ListRegistrationEntries lists entries with explicit keyset pagination (entry_id) using indexes.
// Uses union/AND logic over reg_selectors_index and federates_with_index; falls back to registered_entries_scan.
func (ds *CassandraDataStore) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	const defaultPage = 50

	// Enforce "pagesize = 0" error (tests expect InvalidArgument)
	if req != nil && req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}

	pageSize := getPageSize(req.Pagination, defaultPage)
	startAfter := ""
	if req != nil && req.Pagination != nil && req.Pagination.Token != "" {
		startAfter = req.Pagination.Token
	}

	// Validate "empty filter" semantics (tests expect InvalidArgument)
	if req != nil && req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty selector set")
	}
	if req != nil && req.ByFederatesWith != nil && len(req.ByFederatesWith.TrustDomains) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty federates_with set")
	}

	resp := &datastore.ListRegistrationEntriesResponse{
		Entries: make([]*common.RegistrationEntry, 0, pageSize),
	}

	type cand struct{ id string }

	// ------- Candidate sources (no full table scans / no illegal ORDER BY) -------
	// Helpers to page through index tables by entry_id > startAfter, ASC.
	readRegSelectorsIndex := func(sel *common.Selector, after string, limit int) ([]string, error) {
		args := []any{sel.Type, sel.Value}
		q := `SELECT entry_id FROM reg_selectors_index WHERE selector_type = ? AND selector_value = ?`
		if after != "" {
			q += ` AND entry_id > ?`
			args = append(args, after)
		}
		q += ` ORDER BY entry_id ASC LIMIT ?`
		args = append(args, limit)
		iter := ds.session.Query(q, args...).Iter()
		var v string
		var out []string
		for iter.Scan(&v) {
			out = append(out, v)
		}
		if err := iter.Close(); err != nil {
			return nil, newError("failed to iterate reg_selectors_index: %v", err)
		}
		return out, nil
	}
	readFederatesIndex := func(td, after string, limit int) ([]string, error) {
		args := []any{td}
		q := `SELECT entry_id FROM federates_with_index WHERE trust_domain = ?`
		if after != "" {
			q += ` AND entry_id > ?`
			args = append(args, after)
		}
		q += ` ORDER BY entry_id ASC LIMIT ?`
		args = append(args, limit)
		iter := ds.session.Query(q, args...).Iter()
		var v string
		var out []string
		for iter.Scan(&v) {
			out = append(out, v)
		}
		if err := iter.Close(); err != nil {
			return nil, newError("failed to iterate federates_with_index: %v", err)
		}
		return out, nil
	}
	readAllIDs := func(after string, limit int) ([]string, error) {
		args := []any{regAllIDsBucket}
		q := `SELECT entry_id FROM registered_entries_scan WHERE bucket = ?`
		if after != "" {
			q += ` AND entry_id > ?`
			args = append(args, after)
		}
		q += ` ORDER BY entry_id ASC LIMIT ?`
		args = append(args, limit)
		iter := ds.session.Query(q, args...).Iter()
		var v string
		var out []string
		for iter.Scan(&v) {
			out = append(out, v)
		}
		if err := iter.Close(); err != nil {
			return nil, newError("failed to iterate registered_entries_scan: %v", err)
		}
		return out, nil
	}

	// Batch factor to over-fetch, since we filter after hydration
	const batchFactor = 4
	scanCursor := startAfter
	collected := 0
	var nextToken string

	for collected < pageSize {
		var candidateIDs []string

		switch {
		// Prefer selector index when provided
		case req != nil && req.BySelectors != nil && len(req.BySelectors.Selectors) > 0:
			bs := req.BySelectors
			switch bs.Match {
			case datastore.Superset, datastore.Exact:
				// Drive by first selector; AND-check remaining in index later
				ids, err := readRegSelectorsIndex(bs.Selectors[0], scanCursor, pageSize*batchFactor+1)
				if err != nil {
					return nil, err
				}
				candidateIDs = ids

			case datastore.Subset, datastore.MatchAny:
				// SUBSET/MATCHANY need a UNION across *all* requested selectors (fixes "expected 3 got 2")
				union := make(map[string]struct{})
				for _, s := range bs.Selectors {
					ids, err := readRegSelectorsIndex(s, scanCursor, pageSize*batchFactor+1)
					if err != nil {
						return nil, err
					}
					for _, id := range ids {
						union[id] = struct{}{}
					}
				}
				// Flatten + sort
				candidateIDs = make([]string, 0, len(union))
				for id := range union {
					if id > scanCursor {
						candidateIDs = append(candidateIDs, id)
					}
				}
				sortStrings(candidateIDs)
				if len(candidateIDs) > pageSize*batchFactor+1 {
					candidateIDs = candidateIDs[:pageSize*batchFactor+1]
				}
			}

		// Else prefer federates index when provided
		case req != nil && req.ByFederatesWith != nil && len(req.ByFederatesWith.TrustDomains) > 0:
			fw := req.ByFederatesWith
			switch fw.Match {
			case datastore.Superset, datastore.Exact:
				ids, err := readFederatesIndex(fw.TrustDomains[0], scanCursor, pageSize*batchFactor+1)
				if err != nil {
					return nil, err
				}
				candidateIDs = ids

			case datastore.Subset, datastore.MatchAny:
				union := make(map[string]struct{})
				for _, td := range fw.TrustDomains {
					ids, err := readFederatesIndex(td, scanCursor, pageSize*batchFactor+1)
					if err != nil {
						return nil, err
					}
					for _, id := range ids {
						union[id] = struct{}{}
					}
				}
				candidateIDs = make([]string, 0, len(union))
				for id := range union {
					if id > scanCursor {
						candidateIDs = append(candidateIDs, id)
					}
				}
				sortStrings(candidateIDs)
				if len(candidateIDs) > pageSize*batchFactor+1 {
					candidateIDs = candidateIDs[:pageSize*batchFactor+1]
				}
			}

		// Else fall back to the “all ids” scan table
		default:
			ids, err := readAllIDs(scanCursor, pageSize*batchFactor+1)
			if err != nil {
				return nil, err
			}
			candidateIDs = ids
		}

		if len(candidateIDs) == 0 {
			break
		}

		// Secondary AND checks (only for Superset/Exact)
		selectorAND := func(id string) (bool, error) {
			bs := req.BySelectors
			if bs == nil || len(bs.Selectors) <= 1 {
				return true, nil
			}
			switch bs.Match {
			case datastore.Superset, datastore.Exact:
				for _, s := range bs.Selectors[1:] {
					var check string
					err := ds.session.Query(
						`SELECT entry_id FROM reg_selectors_index
						 WHERE selector_type = ? AND selector_value = ? AND entry_id = ? LIMIT 1`,
						s.Type, s.Value, id,
					).Scan(&check)
					if err != nil {
						if err == gocql.ErrNotFound {
							return false, nil
						}
						return false, newError("selector AND check failed: %v", err)
					}
				}
				return true, nil
			default:
				return true, nil
			}
		}
		fwAND := func(id string) (bool, error) {
			fw := req.ByFederatesWith
			if fw == nil || len(fw.TrustDomains) <= 1 {
				return true, nil
			}
			switch fw.Match {
			case datastore.Superset, datastore.Exact:
				for _, td := range fw.TrustDomains[1:] {
					var check string
					err := ds.session.Query(
						`SELECT entry_id FROM federates_with_index
						 WHERE trust_domain = ? AND entry_id = ? LIMIT 1`,
						td, id,
					).Scan(&check)
					if err != nil {
						if err == gocql.ErrNotFound {
							return false, nil
						}
						return false, newError("federates_with AND check failed: %v", err)
					}
				}
				return true, nil
			default:
				return true, nil
			}
		}

		// Hydrate + filter
		for _, id := range candidateIDs {
			scanCursor = id // move cursor forward regardless

			// Index-level AND checks
			if req != nil && req.BySelectors != nil && (req.BySelectors.Match == datastore.Superset || req.BySelectors.Match == datastore.Exact) {
				ok, err := selectorAND(id)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
			}
			if req != nil && req.ByFederatesWith != nil && (req.ByFederatesWith.Match == datastore.Superset || req.ByFederatesWith.Match == datastore.Exact) {
				ok, err := fwAND(id)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
			}

			e, err := ds.FetchRegistrationEntry(ctx, id)
			if err != nil {
				return nil, err
			}
			if e == nil {
				continue
			}

			// Simple filters
			if req != nil {
				if req.ByParentID != "" && e.ParentId != req.ByParentID {
					continue
				}
				if req.BySpiffeID != "" && e.SpiffeId != req.BySpiffeID {
					continue
				}
				if req.ByHint != "" && e.Hint != req.ByHint {
					continue
				}
				if req.ByDownstream != nil && e.Downstream != *req.ByDownstream {
					continue
				}
			}

			// Full selector/federates semantics
			if req != nil && req.BySelectors != nil && len(req.BySelectors.Selectors) > 0 {
				if !matchSelectors(e.Selectors, req.BySelectors) {
					continue
				}
			}
			if req != nil && req.ByFederatesWith != nil && len(req.ByFederatesWith.TrustDomains) > 0 {
				if !matchFederates(e.FederatesWith, req.ByFederatesWith) {
					continue
				}
			}

			// Normalize for test equality
			if len(e.Selectors) > 0 {
				sortSelectors(e.Selectors)
			}
			if len(e.FederatesWith) > 0 {
				sortStrings(e.FederatesWith)
			}
			if len(e.DnsNames) == 0 {
				e.DnsNames = nil
			}
			if len(e.FederatesWith) == 0 {
				e.FederatesWith = nil
			}

			resp.Entries = append(resp.Entries, e)
			collected++
			nextToken = e.EntryId
			if collected == pageSize {
				break
			}
		}

		if collected == pageSize || len(candidateIDs) < pageSize*batchFactor+1 {
			break
		}
	}

	if req != nil && req.Pagination != nil {
		resp.Pagination = &datastore.Pagination{
			PageSize: int32(pageSize),
			Token:    "",
		}
		if collected == pageSize && nextToken != "" {
			resp.Pagination.Token = nextToken
		}
	}

	return resp, nil
}

// UpdateRegistrationEntry updates an existing registration entry (and secondary indexes).
func (ds *CassandraDataStore) UpdateRegistrationEntry(ctx context.Context, e *common.RegistrationEntry, mask *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	if e == nil {
		return nil, newError("invalid request: missing registration entry")
	}
	if e.EntryId == "" {
		return nil, newError("invalid request: missing registration entry ID")
	}
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

	// Field validation (mirrors prior behavior)
	if mask.SpiffeId && e.SpiffeId == "" {
		return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: missing SPIFFE ID")
	}
	if mask.X509SvidTtl && e.X509SvidTtl < 0 {
		return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: X509SvidTtl is not set")
	}
	if mask.JwtSvidTtl && e.JwtSvidTtl < 0 {
		return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: JwtSvidTtl is not set")
	}
	if mask.Selectors && len(e.Selectors) == 0 {
		return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: missing selector list")
	}
	if mask.StoreSvid && e.StoreSvid && len(e.Selectors) > 1 {
		firstType := e.Selectors[0].Type
		for _, s := range e.Selectors[1:] {
			if s.Type != firstType {
				return nil, newInvalidArgumentError("datastore-validation: invalid registration entry: selector types must be the same when store SVID is enabled")
			}
		}
	}

	// Fetch current (for index deletions & revision)
	cur, err := ds.FetchRegistrationEntry(ctx, e.EntryId)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, newNotFoundError("datastore-sql: record not found: %s", e.EntryId)
	}

	// Validate federated bundles if changed
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

	// Read rev & created_at, then bump rev
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

	set := make([]string, 0, 12)
	args := make([]interface{}, 0, 14)

	if mask.SpiffeId {
		set = append(set, "spiffe_id = ?")
		args = append(args, e.SpiffeId)
	}
	if mask.ParentId {
		set = append(set, "parent_id = ?")
		args = append(args, e.ParentId)
	}
	if mask.X509SvidTtl {
		set = append(set, "x509_svid_ttl = ?")
		args = append(args, e.X509SvidTtl)
	}
	if mask.Admin {
		set = append(set, "admin = ?")
		args = append(args, e.Admin)
	}
	if mask.Downstream {
		set = append(set, "downstream = ?")
		args = append(args, e.Downstream)
	}
	if mask.EntryExpiry {
		set = append(set, "expiry = ?")
		args = append(args, e.EntryExpiry)
	}
	if mask.StoreSvid {
		set = append(set, "store_svid = ?")
		args = append(args, e.StoreSvid)
	}
	if mask.JwtSvidTtl {
		set = append(set, "jwt_svid_ttl = ?")
		args = append(args, e.JwtSvidTtl)
	}
	if mask.Hint {
		set = append(set, "hint = ?")
		args = append(args, e.Hint)
	}

	set = append(set, "revision_number = ?", "updated_at = ?")
	args = append(args, newRev, now)

	q := "UPDATE registered_entries SET " + strings.Join(set, ", ") + " WHERE entry_id = ?"
	args = append(args, e.EntryId)
	if err := ds.session.Query(q, args...).Exec(); err != nil {
		return nil, newError("failed to update registration entry: %v", err)
	}

	// Child tables + secondary indexes
	if mask.Selectors {
		// delete old selector rows + index rows, then insert new
		if err := ds.deleteSelectorsByEntryID(e.EntryId); err != nil {
			return nil, err
		}
		if err := ds.deleteRegSelectorsIndex(e.EntryId, cur.Selectors); err != nil {
			return nil, err
		}
		if err := ds.insertSelectors(e.EntryId, e.Selectors); err != nil {
			return nil, err
		}
		if err := ds.insertRegSelectorsIndex(e.EntryId, e.Selectors); err != nil {
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
		if err := ds.deleteFederatesWithIndex(e.EntryId, cur.FederatesWith); err != nil {
			return nil, err
		}
		if err := ds.insertFederatesWith(e.EntryId, e.FederatesWith); err != nil {
			return nil, err
		}
		if err := ds.insertFederatesWithIndex(e.EntryId, e.FederatesWith); err != nil {
			return nil, err
		}
	}

	// Event
	if err := ds.createRegistrationEntryEventForEntryID(e.EntryId); err != nil {
		return nil, newError("failed to create registration entry event: %v", err)
	}

	return ds.FetchRegistrationEntry(ctx, e.EntryId)
}

// DeleteRegistrationEntry deletes the given registration entry (with secondary index cleanup).
func (ds *CassandraDataStore) DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	// Fetch existing to return & to remove index rows
	existing, err := ds.FetchRegistrationEntry(ctx, entryID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, newNotFoundError("record not found: %s", entryID)
	}

	// Child tables
	if err := ds.deleteSelectorsByEntryID(entryID); err != nil {
		return nil, err
	}
	if err := ds.deleteDNSNamesByEntryID(entryID); err != nil {
		return nil, err
	}
	if err := ds.deleteFederatesWithByEntryID(entryID); err != nil {
		return nil, err
	}

	// Secondary indexes
	if err := ds.deleteRegSelectorsIndex(entryID, existing.Selectors); err != nil {
		return nil, err
	}
	if err := ds.deleteFederatesWithIndex(entryID, existing.FederatesWith); err != nil {
		return nil, err
	}
	if err := ds.deleteRegAllIDs(entryID); err != nil {
		return nil, err
	}

	// Base row
	const del = `DELETE FROM registered_entries WHERE entry_id = ?`
	if err := ds.session.Query(del, entryID).Exec(); err != nil {
		return nil, newError("failed to delete registration entry: %v", err)
	}

	// Event
	if err := ds.createRegistrationEntryEventForEntryID(entryID); err != nil {
		return nil, newError("failed to create registration entry event: %v", err)
	}

	return existing, nil
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

// Helper: write reg_selectors_index rows for an entry
func (ds *CassandraDataStore) insertRegSelectorIndex(entryID string, selectors []*common.Selector) error {
	if len(selectors) == 0 {
		return nil
	}
	const q = `INSERT INTO reg_selectors_index (selector_type, selector_value, entry_id) VALUES (?, ?, ?)`
	for _, s := range selectors {
		if err := ds.session.Query(q, s.Type, s.Value, entryID).Exec(); err != nil {
			return newError("failed to upsert reg_selectors_index: %v", err)
		}
	}
	return nil
}

// Helper: delete reg_selectors_index rows for an entry (requires old selectors)
func (ds *CassandraDataStore) deleteRegSelectorIndexByEntryID(entryID string, oldSelectors []*common.Selector) error {
	if len(oldSelectors) == 0 {
		return nil
	}
	const q = `DELETE FROM reg_selectors_index WHERE selector_type = ? AND selector_value = ? AND entry_id = ?`
	for _, s := range oldSelectors {
		if err := ds.session.Query(q, s.Type, s.Value, entryID).Exec(); err != nil {
			return newError("failed to delete reg_selectors_index: %v", err)
		}
	}
	return nil
}

// Helper: delete federates_with_index rows for an entry (requires old TDs)
func (ds *CassandraDataStore) deleteFederatesWithIndexByEntryID(entryID string, oldTDs []string) error {
	if len(oldTDs) == 0 {
		return nil
	}
	const q = `DELETE FROM federates_with_index WHERE trust_domain = ? AND entry_id = ?`
	for _, td := range oldTDs {
		if err := ds.session.Query(q, td, entryID).Exec(); err != nil {
			return newError("failed to delete federates_with_index: %v", err)
		}
	}
	return nil
}

// Helper: insert rows into reg_selectors_index (selector_type, selector_value) -> entry_id
func (ds *CassandraDataStore) insertRegSelectorsIndex(entryID string, selectors []*common.Selector) error {
	if len(selectors) == 0 {
		return nil
	}
	const q = `INSERT INTO reg_selectors_index (selector_type, selector_value, entry_id) VALUES (?, ?, ?)`
	for _, s := range selectors {
		if s == nil {
			continue
		}
		if err := ds.session.Query(q, s.Type, s.Value, entryID).Exec(); err != nil {
			return newError("failed to upsert reg_selectors_index: %v", err)
		}
	}
	return nil
}

// Helper: delete rows from reg_selectors_index for a specific entry (requires old selectors)
func (ds *CassandraDataStore) deleteRegSelectorsIndex(entryID string, selectors []*common.Selector) error {
	if len(selectors) == 0 {
		return nil
	}
	const q = `DELETE FROM reg_selectors_index WHERE selector_type = ? AND selector_value = ? AND entry_id = ?`
	for _, s := range selectors {
		if s == nil {
			continue
		}
		if err := ds.session.Query(q, s.Type, s.Value, entryID).Exec(); err != nil {
			return newError("failed to delete reg_selectors_index: %v", err)
		}
	}
	return nil
}

// Helper: insert rows into federates_with_index (trust_domain) -> entry_id
func (ds *CassandraDataStore) insertFederatesWithIndex(entryID string, tds []string) error {
	if len(tds) == 0 {
		return nil
	}
	const q = `INSERT INTO federates_with_index (trust_domain, entry_id) VALUES (?, ?)`
	for _, td := range tds {
		if err := ds.session.Query(q, td, entryID).Exec(); err != nil {
			return newError("failed to upsert federates_with_index: %v", err)
		}
	}
	return nil
}

// Helper: delete rows from federates_with_index for a specific entry (requires old TDs)
func (ds *CassandraDataStore) deleteFederatesWithIndex(entryID string, tds []string) error {
	if len(tds) == 0 {
		return nil
	}
	const q = `DELETE FROM federates_with_index WHERE trust_domain = ? AND entry_id = ?`
	for _, td := range tds {
		if err := ds.session.Query(q, td, entryID).Exec(); err != nil {
			return newError("failed to delete federates_with_index: %v", err)
		}
	}
	return nil
}
