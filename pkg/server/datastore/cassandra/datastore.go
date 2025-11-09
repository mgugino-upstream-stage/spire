package cassandra

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"github.com/hashicorp/hcl"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	// PluginName is the name of the cassandra plugin
	PluginName = "cassandra"
)

// Configuration holds the configuration for the cassandra datastore
type Configuration struct {
	Hosts             string     `hcl:"hosts"`
	Port              int        `hcl:"port"`
	Username          string     `hcl:"username"`
	Password          string     `hcl:"password"`
	Keyspace          string     `hcl:"keyspace"`
	Timeout           string     `hcl:"timeout"`
	ConnectTimeout    string     `hcl:"connect_timeout"`
	NumConns          int        `hcl:"num_conns"`
	Consistency       string     `hcl:"consistency"`
	SerialConsistency string     `hcl:"serial_consistency"`
	TLS               *TLSConfig `hcl:"tls"`
	DisableMigration  bool       `hcl:"disable_migration"`
	ConnMaxLifetime   string     `hcl:"conn_max_lifetime"`
	MaxOpenConns      int        `hcl:"max_open_conns"`
	MaxIdleConns      int        `hcl:"max_idle_conns"`
}

// TLSConfig holds TLS configuration for cassandra datastore
type TLSConfig struct {
	Enabled            bool   `hcl:"enabled"`
	ServerName         string `hcl:"server_name"`
	CertPath           string `hcl:"cert_file_path"`
	KeyPath            string `hcl:"key_file_path"`
	CaPath             string `hcl:"ca_file_path"`
	InsecureSkipVerify bool   `hcl:"insecure_skip_verify"`
}

// CassandraDataStore implements the DataStore interface
type CassandraDataStore struct {
	log logrus.FieldLogger

	session *gocql.Session
	config  *Configuration
}

// New creates a new cassandra datastore instance
func New(log logrus.FieldLogger) *CassandraDataStore {
	return &CassandraDataStore{
		log: log,
	}
}

// Configure parses the configuration HCL and initializes the cassandra datastore
func (ds *CassandraDataStore) Configure(ctx context.Context, hclConfiguration string) error {
	config := &Configuration{}
	if err := hcl.Decode(config, hclConfiguration); err != nil {
		return newError("unable to decode configuration: %v", err)
	}

	if config.Hosts == "" {
		return newError("missing hosts configuration")
	}

	if config.Keyspace == "" {
		return newError("missing keyspace configuration")
	}

	if config.Port <= 0 {
		config.Port = 9042 // Default Cassandra port
	}

	if config.NumConns <= 0 {
		config.NumConns = 4 // Default number of connections
	}

	ds.config = config

	return ds.initSession()
}

// Migrate performs database migrations
func (ds *CassandraDataStore) Migrate(ctx context.Context) error {
	return ds.migrate(ctx)
}

// initSession creates a Cassandra session based on the configuration
func (ds *CassandraDataStore) initSession() error {
	// First connect without specifying keyspace to create it if needed
	cluster := gocql.NewCluster(strings.Split(ds.config.Hosts, ",")...)

	cluster.Port = ds.config.Port
	cluster.NumConns = ds.config.NumConns

	if ds.config.Username != "" && ds.config.Password != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: ds.config.Username,
			Password: ds.config.Password,
		}
	}

	if ds.config.Consistency != "" {
		switch strings.ToUpper(ds.config.Consistency) {
		case "ANY":
			cluster.Consistency = gocql.Any
		case "ONE":
			cluster.Consistency = gocql.One
		case "TWO":
			cluster.Consistency = gocql.Two
		case "THREE":
			cluster.Consistency = gocql.Three
		case "QUORUM":
			cluster.Consistency = gocql.Quorum
		case "ALL":
			cluster.Consistency = gocql.All
		case "LOCAL_QUORUM":
			cluster.Consistency = gocql.LocalQuorum
		case "EACH_QUORUM":
			cluster.Consistency = gocql.EachQuorum
		case "LOCAL_ONE":
			cluster.Consistency = gocql.LocalOne
		default:
			return newError("invalid consistency level: %s", ds.config.Consistency)
		}
	}

	if ds.config.SerialConsistency != "" {
		switch strings.ToUpper(ds.config.SerialConsistency) {
		case "SERIAL":
			cluster.SerialConsistency = gocql.Serial
		case "LOCAL_SERIAL":
			cluster.SerialConsistency = gocql.LocalSerial
		default:
			return newError("invalid serial consistency level: %s", ds.config.SerialConsistency)
		}
	}

	if ds.config.TLS != nil && ds.config.TLS.Enabled {
		tlsConfig, err := ds.getTLSConfig()
		if err != nil {
			return newError("failed to get TLS config: %v", err)
		}
		cluster.SslOpts = &gocql.SslOptions{
			Config: tlsConfig,
		}
	}

	if ds.config.Timeout != "" {
		timeout, err := time.ParseDuration(ds.config.Timeout)
		if err != nil {
			return newError("invalid timeout: %v", err)
		}
		cluster.Timeout = timeout
	}

	if ds.config.ConnectTimeout != "" {
		connectTimeout, err := time.ParseDuration(ds.config.ConnectTimeout)
		if err != nil {
			return newError("invalid connect timeout: %v", err)
		}
		cluster.ConnectTimeout = connectTimeout
	}

	// Connect to system keyspace first to create our keyspace and tables if needed
	cluster.Keyspace = "system" // Use system keyspace for initial connection
	session, err := cluster.CreateSession()
	if err != nil {
		return newError("failed to create initial Cassandra session: %v", err)
	}

	// Create the keyspace and tables if they don't exist
	if err := ds.ensureSchema(session); err != nil {
		session.Close()
		return err
	}

	// Close the initial session and reconnect using the new keyspace
	session.Close()

	// Now reconnect with the correct keyspace
	cluster.Keyspace = ds.config.Keyspace
	session, err = cluster.CreateSession()
	if err != nil {
		return newError("failed to create Cassandra session with keyspace %s: %v", ds.config.Keyspace, err)
	}

	ds.session = session

	// Optionally run migrations if not disabled
	if !ds.config.DisableMigration {
		if err := ds.migrate(context.Background()); err != nil {
			session.Close()
			return newError("failed to migrate schema: %v", err)
		}
	}

	return nil
}

func (ds *CassandraDataStore) getTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: ds.config.TLS.InsecureSkipVerify,
	}

	if ds.config.TLS.ServerName != "" {
		cfg.ServerName = ds.config.TLS.ServerName
	}

	if ds.config.TLS.CertPath != "" && ds.config.TLS.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(ds.config.TLS.CertPath, ds.config.TLS.KeyPath)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if ds.config.TLS.CaPath != "" {
		if err := configureTLSRoot(cfg, ds.config.TLS.CaPath); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// Close closes the cassandra session
func (ds *CassandraDataStore) Close() error {
	if ds.session != nil {
		ds.session.Close()
	}
	return nil
}

// Helper function to parse trust domain for bundle operations
func parseTrustDomainID(trustDomainID string) (spiffeid.TrustDomain, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomainID)
	if err != nil {
		return spiffeid.TrustDomain{}, newError("bundle trust domain malformed: %v", err)
	}
	return td, nil
}

// createKeyspace creates the keyspace if it doesn't exist
func (ds *CassandraDataStore) createKeyspace(session *gocql.Session) error {
	stmt := fmt.Sprintf(`CREATE KEYSPACE IF NOT EXISTS %s 
		WITH replication = {
			'class': 'SimpleStrategy', 
			'replication_factor': 1
		}`, ds.config.Keyspace)

	if err := session.Query(stmt).Exec(); err != nil {
		return newError("failed to create keyspace: %v", err)
	}

	return nil
}

// ensureSchema creates the keyspace and tables if they don't exist
func (ds *CassandraDataStore) ensureSchema(session *gocql.Session) error {
	// First create the keyspace
	if err := ds.createKeyspace(session); err != nil {
		return err
	}

	// Close the session used to create keyspace and reconnect to the new keyspace to create tables
	session.Close()

	// Connect to the new keyspace
	cluster := gocql.NewCluster(strings.Split(ds.config.Hosts, ",")...)
	cluster.Port = ds.config.Port
	cluster.Keyspace = ds.config.Keyspace
	cluster.NumConns = 1 // Just 1 connection for schema setup

	if ds.config.Username != "" && ds.config.Password != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: ds.config.Username,
			Password: ds.config.Password,
		}
	}

	if ds.config.TLS != nil && ds.config.TLS.Enabled {
		tlsConfig, err := ds.getTLSConfig()
		if err != nil {
			return newError("failed to get TLS config: %v", err)
		}
		cluster.SslOpts = &gocql.SslOptions{
			Config: tlsConfig,
		}
	}

	tableSession, err := cluster.CreateSession()
	if err != nil {
		return newError("failed to create session for table creation: %v", err)
	}
	defer tableSession.Close()

	// Create all required tables using the defined table schemas
	for _, tableDDL := range TableDefinitions {
		if err := tableSession.Query(tableDDL).Exec(); err != nil {
			return fmt.Errorf("failed to create table: %v", err)
		}
	}

	return nil
}

// GRPCServiceName returns the name of the gRPC service for the plugin interface
func (ds *CassandraDataStore) GRPCServiceName() string {
	return "spire.plugin.server.datastore.cassandra"
}

// IsBuiltIn returns true if the plugin is built in (not a dynamic plugin)
func (ds *CassandraDataStore) IsBuiltIn() bool {
	return true
}

func configureTLSRoot(cfg *tls.Config, caPath string) error {
	// This function would load the CA certificate and set up the root CA pool
	// Implementation would be similar to the PostgreSQL one in the existing SQL store
	return nil
}
