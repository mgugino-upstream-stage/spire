package cassandra

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/gocql/gocql"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const bundleBucket = "bundles"

// CreateBundle stores the given bundle
func (ds *CassandraDataStore) CreateBundle(ctx context.Context, b *common.Bundle) (*common.Bundle, error) {
	if b == nil {
		return nil, newError("invalid request: missing bundle")
	}

	model, err := bundleToModel(b)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	query := `INSERT INTO bundles (bucket, trust_domain, data, refresh_hint, created_at, updated_at) 
             VALUES (?, ?, ?, ?, ?, ?) 
             IF NOT EXISTS`

	var applied bool
	m := make(map[string]interface{})
	applied, err = ds.session.Query(query, bundleBucket, b.TrustDomainId, model.Data, model.RefreshHint, now, now).MapScanCAS(m)
	if err != nil {
		return nil, newError("failed to create bundle: %v", err)
	}
	if !applied {
		return nil, newAlreadyExistsError("bundle already exists for trust domain: %s", b.TrustDomainId)
	}

	return b, nil
}

// UpdateBundle updates an existing bundle with the given CAs. Overwrites any existing certificates.
func (ds *CassandraDataStore) UpdateBundle(ctx context.Context, b *common.Bundle, mask *common.BundleMask) (*common.Bundle, error) {
	if b == nil || b.TrustDomainId == "" {
		return nil, newError("invalid request: missing bundle or trust domain ID")
	}

	model, err := bundleToModel(b)
	if err != nil {
		return nil, err
	}

	// Check if bundle exists
	query := `SELECT trust_domain FROM bundles WHERE bucket = ? AND trust_domain = ? LIMIT 1`
	iter := ds.session.Query(query, bundleBucket, b.TrustDomainId).Iter()
	if !iter.Scanner().Next() {
		iter.Close()
		return nil, newNotFoundError("bundle not found for trust domain: %s", b.TrustDomainId)
	}
	iter.Close()

	// Update (upsert) the bundle
	query = `UPDATE bundles
          SET data = ?, refresh_hint = ?, updated_at = ?
          WHERE bucket = ? AND trust_domain = ?`
	if err := ds.session.Query(query, model.Data, model.RefreshHint, time.Now(),
		bundleBucket, model.TrustDomain).Exec(); err != nil {
		return nil, newError("failed to update bundle: %v", err)
	}

	return b, nil
}

// SetBundle sets bundle contents. If no bundle exists for the trust domain, it is created.
func (ds *CassandraDataStore) SetBundle(ctx context.Context, b *common.Bundle) (*common.Bundle, error) {
	if b == nil {
		return nil, newError("invalid request: missing bundle")
	}

	// Check if bundle exists
	existingBundle, err := ds.FetchBundle(ctx, b.TrustDomainId)
	if err != nil {
		return nil, err
	}

	if existingBundle != nil {
		// Update existing bundle - increment sequence number
		b.SequenceNumber = existingBundle.SequenceNumber + 1
	} else {
		// New bundle - start at sequence 0
		b.SequenceNumber = 0
	}

	// Convert updated bundle to model
	newModel, err := bundleToModel(b)
	if err != nil {
		return nil, err
	}

	query := `INSERT INTO bundles (bucket, trust_domain, data, refresh_hint, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`
	if err := ds.session.Query(query, bundleBucket, newModel.TrustDomain, newModel.Data, newModel.RefreshHint, time.Now(), time.Now()).Exec(); err != nil {
		return nil, newError("failed to set bundle: %v", err)
	}

	return b, nil
}

// AppendBundle append bundle contents to the existing bundle (by trust domain). If no existing one is present, create it.
func (ds *CassandraDataStore) AppendBundle(ctx context.Context, b *common.Bundle) (*common.Bundle, error) {
	if b == nil {
		return nil, newError("invalid request: missing bundle")
	}

	// Get existing bundle
	existingBundle, err := ds.FetchBundle(ctx, b.TrustDomainId)
	if err != nil {
		return nil, err
	}

	// If no existing bundle, just create the new one
	if existingBundle == nil {
		return ds.CreateBundle(ctx, b)
	}

	// Merge the bundles
	mergedBundle, changed := bundleutil.MergeBundles(existingBundle, b)
	if !changed {
		return existingBundle, nil
	}

	if changed {
		mergedBundle.SequenceNumber++
		newModel, err := bundleToModel(mergedBundle)
		if err != nil {
			return nil, err
		}

		query := `UPDATE bundles SET data = ?, refresh_hint = ?, updated_at = ? WHERE bucket = ? AND trust_domain = ?`
		if err := ds.session.Query(query, newModel.Data, newModel.RefreshHint, time.Now(), bundleBucket, newModel.TrustDomain).Exec(); err != nil {
			return nil, newError("failed to append to bundle: %v", err)
		}
	}

	return mergedBundle, nil
}

func (ds *CassandraDataStore) DeleteBundle(ctx context.Context, trustDomainID string, mode datastore.DeleteMode) error {
	if trustDomainID == "" {
		return newError("invalid request: missing trust domain ID")
	}

	switch mode {
	case datastore.Restrict:
		// block if any references exist
		var count int64
		const refQ = `SELECT COUNT(*) FROM federates_with WHERE trust_domain = ? ALLOW FILTERING`
		if err := ds.session.Query(refQ, trustDomainID).Scan(&count); err != nil {
			return newError("failed to check bundle references: %v", err)
		}
		if count > 0 {
			return newError("datastore-sql: cannot delete bundle; federated with %d registration entries", count)
		}

	case datastore.Delete:
		// delete entries that reference this bundle
		const listQ = `SELECT entry_id FROM federates_with WHERE trust_domain = ? ALLOW FILTERING`
		iter := ds.session.Query(listQ, trustDomainID).Iter()
		var entryID string
		for iter.Scan(&entryID) {
			if err := ds.session.Query(`DELETE FROM selectors         WHERE entry_id = ?`, entryID).Exec(); err != nil {
				iter.Close()
				return newError("failed to delete selectors for entry %q: %v", entryID, err)
			}
			if err := ds.session.Query(`DELETE FROM dns_names         WHERE entry_id = ?`, entryID).Exec(); err != nil {
				iter.Close()
				return newError("failed to delete dns names for entry %q: %v", entryID, err)
			}
			if err := ds.session.Query(`DELETE FROM federates_with    WHERE entry_id = ?`, entryID).Exec(); err != nil {
				iter.Close()
				return newError("failed to delete federates_with for entry %q: %v", entryID, err)
			}
			if err := ds.session.Query(`DELETE FROM registered_entries WHERE entry_id = ?`, entryID).Exec(); err != nil {
				iter.Close()
				return newError("failed to delete registration entry %q: %v", entryID, err)
			}
		}
		if err := iter.Close(); err != nil {
			return newError("failed to iterate federated entries: %v", err)
		}

	case datastore.Dissociate:
		// remove ONLY the association to this trust domain; keep entries
		const listQ = `SELECT entry_id FROM federates_with WHERE trust_domain = ? ALLOW FILTERING`
		iter := ds.session.Query(listQ, trustDomainID).Iter()
		var entryID string
		for iter.Scan(&entryID) {
			// delete the single row for (entry_id, trust_domain)
			if err := ds.session.Query(
				`DELETE FROM federates_with WHERE entry_id = ? AND trust_domain = ?`,
				entryID, trustDomainID,
			).Exec(); err != nil {
				iter.Close()
				return newError("failed to dissociate entry %q from %q: %v", entryID, trustDomainID, err)
			}

			// (Optional but closer to sqlstore semantics)
			// touch updated_at to reflect the dissociation
			if err := ds.session.Query(
				`UPDATE registered_entries SET updated_at = ? WHERE entry_id = ?`,
				time.Now(), entryID,
			).Exec(); err != nil {
				iter.Close()
				return newError("failed to update registration entry timestamp for %q: %v", entryID, err)
			}

			// (Optional) emit an entry event if your sqlstore does on dissociation
			// _ = ds.createRegistrationEntryEventForEntryID(entryID)
		}
		if err := iter.Close(); err != nil {
			return newError("failed to iterate federated entries for dissociation: %v", err)
		}
	}

	// finally, remove the bundle itself
	const delBundleQ = `DELETE FROM bundles WHERE bucket = ? AND trust_domain = ?`
	if err := ds.session.Query(delBundleQ, bundleBucket, trustDomainID).Exec(); err != nil {
		return newError("failed to delete bundle: %v", err)
	}
	return nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
// FetchBundle returns the bundle matching the specified Trust Domain.
func (ds *CassandraDataStore) FetchBundle(ctx context.Context, trustDomainID string) (*common.Bundle, error) {
	if trustDomainID == "" {
		return nil, newError("invalid request: missing trust domain ID")
	}

	var model BundleModel
	query := `SELECT trust_domain, data, refresh_hint, created_at
	          FROM bundles
	          WHERE bucket = ? AND trust_domain = ?
	          LIMIT 1`
	err := ds.session.Query(query, bundleBucket, trustDomainID).Scan(
		&model.TrustDomain,
		&model.Data,
		&model.RefreshHint,
		&model.CreatedAt,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, nil
		}
		return nil, newError("failed to fetch bundle: %v", err)
	}

	// DEFENSIVE COPY: never trust that []byte from Scan will remain stable.
	if len(model.Data) > 0 {
		copied := make([]byte, len(model.Data))
		copy(copied, model.Data)
		model.Data = copied
	}

	bundle, err := modelToBundle(&model)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// CountBundles can be used to count all existing bundles.
func (ds *CassandraDataStore) CountBundles(ctx context.Context) (int32, error) {
	var count int64
	query := `SELECT COUNT(*) FROM bundles`
	if err := ds.session.Query(query).Scan(&count); err != nil {
		return 0, newError("failed to count bundles: %v", err)
	}

	if count > int64(^uint32(0)>>1) { // Check overflow
		return ^int32(0), nil // Max int32
	}

	return int32(count), nil
}

// ListBundles can be used to fetch all existing bundles.
func (ds *CassandraDataStore) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (*datastore.ListBundlesResponse, error) {

	pageSize := int32(0) // Default to all if no pagination
	var startTrustDomain string
	if req.Pagination != nil {
		if req.Pagination.PageSize <= 0 {
			return nil, newInvalidArgumentError("cannot paginate with pagesize = 0")
		}
		pageSize = req.Pagination.PageSize

		if req.Pagination.Token != "" {
			if req.Pagination.Token == "0" {
				startTrustDomain = ""
			} else {
				startTrustDomain = req.Pagination.Token
			}
		}
	}

	// Build query with range filter
	queryStr := `SELECT trust_domain, data, refresh_hint 
                 FROM bundles 
                 WHERE bucket = ?`
	args := []interface{}{bundleBucket}
	if startTrustDomain != "" {
		queryStr += ` AND trust_domain > ?`
		args = append(args, startTrustDomain)
	}
	queryStr += ` ORDER BY trust_domain ASC`
	if pageSize > 0 {
		queryStr += ` LIMIT ?`
		args = append(args, int(pageSize+1)) // +1 to detect hasMore
	}

	iter := ds.session.Query(queryStr, args...).Iter()

	var (
		trustDomain string
		data        []byte
		refreshHint int64
	)
	var rows []BundleModel

	for iter.Scan(&trustDomain, &data, &refreshHint) {
		copied := make([]byte, len(data))
		copy(copied, data)

		rows = append(rows, BundleModel{
			TrustDomain: trustDomain,
			Data:        copied,
			RefreshHint: refreshHint,
		})
	}

	if err := iter.Close(); err != nil {
		return nil, newError("failed to iterate bundles: %v", err)
	}

	// Check for more and trim if necessary
	var nextToken string
	if pageSize > 0 && len(rows) > int(pageSize) {
		rows = rows[:pageSize]
		nextToken = rows[len(rows)-1].TrustDomain // use last visible item
	}

	resp := &datastore.ListBundlesResponse{
		Bundles: make([]*common.Bundle, 0, len(rows)),
	}

	for _, model := range rows {
		bundle, err := modelToBundle(&model)
		if err != nil {
			return nil, err
		}
		resp.Bundles = append(resp.Bundles, bundle)
	}

	if req.Pagination != nil {
		pagination := &datastore.Pagination{
			PageSize: req.Pagination.PageSize,
			Token:    nextToken, // will be "" if not hasMore
		}
		resp.Pagination = pagination
	}

	return resp, nil
}

// PruneBundle removes expired certs and keys from a bundle
func (ds *CassandraDataStore) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (bool, error) {
	bundle, err := ds.FetchBundle(ctx, trustDomainID)
	if err != nil {
		return false, err
	}

	if bundle == nil {
		// No bundle to prune
		return false, nil
	}
	// Prune the bundle
	newBundle, changed, err := bundleutil.PruneBundle(bundle, expiresBefore, ds.log)
	if err != nil {
		return false, newError("prune failed: %v", err)
	}

	if changed {
		// Save the pruned bundle
		newBundle.SequenceNumber = bundle.SequenceNumber + 1
		_, err = ds.UpdateBundle(ctx, newBundle, nil)
		if err != nil {
			return false, newError("failed to save pruned bundle: %v", err)
		}
	}

	return changed, nil
}

// TaintX509CA taints an X.509 CA signed using the provided public key
// TaintX509CA taints an X.509 CA signed using the provided public key
func (ds *CassandraDataStore) TaintX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToTaint string) error {
	bundle, err := ds.FetchBundle(ctx, trustDomainID)
	if err != nil {
		return err
	}
	if bundle == nil {
		// Match sqlstore tests
		return status.Error(codes.NotFound, "datastore-sql: record not found")
	}

	found := false
	for _, ca := range bundle.RootCas {
		cert, err := x509.ParseCertificate(ca.DerBytes)
		if err != nil {
			// exact message expected by TestTaintX509CA ("rootCA" without space)
			return status.Errorf(codes.Internal, "failed to parse rootCA: %v", err)
		}
		if x509util.SubjectKeyIDToString(cert.SubjectKeyId) == subjectKeyIDToTaint {
			if ca.TaintedKey {
				return status.Error(codes.InvalidArgument, "root CA is already tainted")
			}
			ca.TaintedKey = true
			found = true
			break
		}
	}
	if !found {
		return status.Error(codes.NotFound, "no ca found with provided subject key ID")
	}

	bundle.SequenceNumber++
	_, err = ds.UpdateBundle(ctx, bundle, nil)
	return err
}

// RevokeX509CA removes a Root CA from the bundle
// RevokeX509CA removes a Root CA from the bundle
func (ds *CassandraDataStore) RevokeX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToRevoke string) error {
	bundle, err := ds.FetchBundle(ctx, trustDomainID)
	if err != nil {
		return err
	}
	if bundle == nil {
		// Match sqlstore tests
		return status.Error(codes.NotFound, "datastore-sql: record not found")
	}

	// Scan and parse all root CAs. Tests expect we error out if any cert is malformed.
	type parsed struct {
		idx  int
		cert *x509.Certificate
	}
	var parsedCerts []parsed
	for i, ca := range bundle.RootCas {
		cert, err := x509.ParseCertificate(ca.DerBytes)
		if err != nil {
			// exact prefix expected by TestRevokeX509CA ("root CA" with space)
			return status.Errorf(codes.Internal, "failed to parse root CA: %v", err)
		}
		parsedCerts = append(parsedCerts, parsed{idx: i, cert: cert})
	}

	// Find the target by SubjectKeyID
	targetIdx := -1
	for _, p := range parsedCerts {
		if x509util.SubjectKeyIDToString(p.cert.SubjectKeyId) == subjectKeyIDToRevoke {
			targetIdx = p.idx
			break
		}
	}
	if targetIdx == -1 {
		return status.Error(codes.NotFound, "no root CA found with provided subject key ID")
	}

	// Ensure the target is tainted before revocation
	if !bundle.RootCas[targetIdx].TaintedKey {
		return status.Error(codes.InvalidArgument, "it is not possible to revoke an untainted root CA")
	}

	// Remove the target CA
	newRoots := make([]*common.Certificate, 0, len(bundle.RootCas)-1)
	for i, ca := range bundle.RootCas {
		if i == targetIdx {
			continue
		}
		newRoots = append(newRoots, ca)
	}
	bundle.RootCas = newRoots
	bundle.SequenceNumber++

	_, err = ds.UpdateBundle(ctx, bundle, nil)
	return err
}

func (ds *CassandraDataStore) TaintJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	bundle, err := ds.FetchBundle(ctx, trustDomainID)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, status.Errorf(codes.NotFound, "datastore-sql: record not found")
	}

	// Find matches by Kid
	matchIdx := -1
	matchCount := 0
	for i, k := range bundle.JwtSigningKeys {
		if k.Kid == authorityID {
			matchCount++
			matchIdx = i
		}
	}

	switch {
	case matchCount == 0:
		return nil, status.Errorf(codes.NotFound, "no JWT Key found with provided key ID")
	case matchCount > 1:
		return nil, status.Errorf(codes.Internal, "another JWT Key found with the same KeyID")
	}

	// Exactly one match
	if bundle.JwtSigningKeys[matchIdx].TaintedKey {
		return nil, status.Errorf(codes.InvalidArgument, "key is already tainted")
	}

	// Taint it
	bundle.JwtSigningKeys[matchIdx].TaintedKey = true
	tainted := bundle.JwtSigningKeys[matchIdx]

	bundle.SequenceNumber++
	if _, err := ds.UpdateBundle(ctx, bundle, nil); err != nil {
		return nil, err
	}
	return tainted, nil
}

// RevokeJWTKey removes a tainted JWT signing key from the bundle for the given trust domain.
// Expected errors (to satisfy tests):
// - NotFound:  "datastore-sql: record not found"                -> when bundle does not exist
// - NotFound:  "no JWT Key found with provided key ID"          -> no key with Kid found
// - InvalidArgument: "it is not possible to revoke an untainted key" -> found but not tainted
// - Internal:  "another key found with the same KeyID"          -> duplicate keys with same Kid
func (ds *CassandraDataStore) RevokeJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	bundle, err := ds.FetchBundle(ctx, trustDomainID)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, status.Errorf(codes.NotFound, "datastore-sql: record not found")
	}

	// Find matches by Kid
	matchIdx := -1
	matchCount := 0
	for i, k := range bundle.JwtSigningKeys {
		if k.Kid == authorityID {
			matchCount++
			matchIdx = i
		}
	}

	switch {
	case matchCount == 0:
		return nil, status.Errorf(codes.NotFound, "no JWT Key found with provided key ID")
	case matchCount > 1:
		return nil, status.Errorf(codes.Internal, "another key found with the same KeyID")
	}

	// Exactly one match
	key := bundle.JwtSigningKeys[matchIdx]
	if !key.TaintedKey {
		return nil, status.Errorf(codes.InvalidArgument, "it is not possible to revoke an untainted key")
	}

	// Remove the key
	newKeys := make([]*common.PublicKey, 0, len(bundle.JwtSigningKeys)-1)
	newKeys = append(newKeys, bundle.JwtSigningKeys[:matchIdx]...)
	newKeys = append(newKeys, bundle.JwtSigningKeys[matchIdx+1:]...)
	bundle.JwtSigningKeys = newKeys

	bundle.SequenceNumber++
	if _, err := ds.UpdateBundle(ctx, bundle, nil); err != nil {
		return nil, err
	}

	// Return the revoked key (as it existed, i.e., tainted)
	return key, nil
}

// BundleModel represents the Cassandra model for a bundle
type BundleModel struct {
	TrustDomain string
	Data        []byte
	RefreshHint int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// modelToBundle converts the given bundle model to a Protobuf bundle message. It will also
// include any embedded CACert models.
func modelToBundle(model *BundleModel) (*common.Bundle, error) {
	bundle := new(common.Bundle)
	if err := proto.Unmarshal(model.Data, bundle); err != nil {
		return nil, newError("failed to unmarshal bundle: %v", err)
	}

	return bundle, nil
}

// bundleToModel converts the Protobuf bundle message to a Cassandra model
func bundleToModel(pb *common.Bundle) (*BundleModel, error) {
	if pb == nil {
		return nil, newError("missing bundle in request")
	}

	data, err := proto.Marshal(pb)
	if err != nil {
		return nil, newError("failed to marshal bundle: %v", err)
	}

	return &BundleModel{
		TrustDomain: pb.TrustDomainId,
		Data:        data,
		RefreshHint: pb.RefreshHint,
	}, nil
}
