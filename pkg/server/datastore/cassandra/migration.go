package cassandra

import (
	"context"
	"fmt"
	"time"

	"github.com/gocql/gocql"
)

// Migration represents the migration state in the database
type Migration struct {
	Version     int
	CodeVersion string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// migrate migrates the database to the latest version
func (ds *CassandraDataStore) migrate(ctx context.Context) error {
	ds.log.Info("Starting Cassandra datastore migration")

	// Get the current version
	currentVersion, codeVersion, err := ds.getCurrentVersion()
	if err != nil {
		return err
	}

	ds.log.Debugf("Current migration version: %d, code version: %s", currentVersion, codeVersion)

	// Determine the target version (in this case, the version needed by the code)
	targetVersion := 1 // Start with version 1, can increment as needed

	// If current version is already at or beyond target, no migration needed
	if currentVersion >= targetVersion {
		ds.log.Info("Database is up to date")
		return nil
	}

	// Perform migration steps from currentVersion to targetVersion
	for currentVersion < targetVersion {
		nextVersion := currentVersion + 1
		ds.log.Infof("Migrating from version %d to version %d", currentVersion, nextVersion)

		if err := ds.runMigrationStep(currentVersion, nextVersion); err != nil {
			return fmt.Errorf("failed to migrate from version %d to %d: %v", currentVersion, nextVersion, err)
		}

		currentVersion = nextVersion
	}

	ds.log.Info("Cassandra datastore migration completed successfully")
	return nil
}

// getCurrentVersion returns the current database version and code version
func (ds *CassandraDataStore) getCurrentVersion() (int, string, error) {
	var m Migration
	query := `SELECT version, code_version, updated_at FROM migration LIMIT 1`
	err := ds.session.Query(query).Scan(&m.Version, &m.CodeVersion, &m.UpdatedAt)

	if err != nil {
		if err == gocql.ErrNotFound {
			// If no migration record exists, return version 0
			return 0, "", nil
		}
		return 0, "", newError("failed to get current migration version: %v", err)
	}

	return m.Version, m.CodeVersion, nil
}

// runMigrationStep runs a single migration step
func (ds *CassandraDataStore) runMigrationStep(fromVersion, toVersion int) error {
	switch toVersion {
	case 1:
		return ds.migration1()
	default:
		return newError("unknown migration version: %d", toVersion)
	}
}

// migration1 is the first migration step - setting up basic schema
func (ds *CassandraDataStore) migration1() error {
	// Create all required tables if they don't exist
	if err := ds.createTables(); err != nil {
		return newError("failed to create tables during migration: %v", err)
	}

	// Insert migration record
	migration := Migration{
		Version:     1,
		CodeVersion: "1.0.0", // In real implementation, use actual version
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	query := `INSERT INTO migration (version, code_version, created_at, updated_at) VALUES (?, ?, ?, ?)`
	if err := ds.session.Query(query, migration.Version, migration.CodeVersion, migration.CreatedAt, migration.UpdatedAt).Exec(); err != nil {
		return newError("failed to record migration: %v", err)
	}

	return nil
}

// updateVersion updates the migration version in the database
func (ds *CassandraDataStore) updateVersion(version int) error {
	query := `INSERT INTO migration (version, code_version, updated_at) VALUES (?, ?, ?)`
	if err := ds.session.Query(query, version, "1.0.0", time.Now()).Exec(); err != nil {
		return newError("failed to update migration version: %v", err)
	}
	return nil
}

// isTableExists checks if a table exists in the keyspace
func (ds *CassandraDataStore) isTableExists(tableName string) (bool, error) {
	// This is a simplified check - in real implementation, we'd query system tables
	// For now we'll just attempt to query and see if it errors
	query := fmt.Sprintf("SELECT * FROM %s LIMIT 1", tableName)
	iter := ds.session.Query(query).Iter()
	defer iter.Close()

	// The query might fail if the table doesn't exist, but if it succeeds or fails for other reasons, we handle accordingly
	if err := iter.Close(); err != nil {
		// Check if the error is specifically about table not existing
		return false, nil // For now, just return false if there's an error
	}

	return true, nil
}

// setCurrentVersion sets the current migration version
func (ds *CassandraDataStore) setCurrentVersion(version int) error {
	query := `INSERT INTO migration (version, code_version, created_at, updated_at) VALUES (?, ?, ?, ?) 
	          IF NOT EXISTS`

	applied, err := ds.session.Query(query, version, "1.0.0", time.Now(), time.Now()).ScanCAS()
	if err != nil {
		return newError("failed to set current migration version: %v", err)
	}

	if !applied {
		// Update existing record if it already exists
		updateQuery := `UPDATE migration SET version = ?, code_version = ?, updated_at = ? WHERE version = ?`
		if err := ds.session.Query(updateQuery, version, "1.0.0", time.Now(), version).Exec(); err != nil {
			return newError("failed to update migration version: %v", err)
		}
	}

	return nil
}
