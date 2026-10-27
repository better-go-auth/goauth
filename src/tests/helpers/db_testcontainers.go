package helpers

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	coremigrator "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	orgmigrator "github.com/better-go-auth/goauth/src/plugins/org/repository/gorm/gorm_migrator"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tc_mysql "github.com/testcontainers/testcontainers-go/modules/mysql"
	tc_postgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	gormmysql "gorm.io/driver/mysql"
	gormpostgres "gorm.io/driver/postgres"
	gormsqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// DatabaseType enumerates the supported test database engines.
type DatabaseType string

const (
	DBTypeSQLite   DatabaseType = "sqlite"
	DBTypePostgres DatabaseType = "postgres"
	DBTypeMySQL    DatabaseType = "mysql"
)

// AllDatabaseTypes is the slice of all supported database engines for multi-DB test suites.
var AllDatabaseTypes = []DatabaseType{
	DBTypeSQLite,
	DBTypePostgres,
	DBTypeMySQL,
}

// SetupTestDB initializes and returns a *gorm.DB for the requested database type.
// For PostgreSQL and MySQL, it will use environment variables (TEST_POSTGRES_URL / TEST_MYSQL_URL)
// if set, or spin up disposable Docker containers via testcontainers.
func SetupTestDB(t *testing.T, dbType DatabaseType) *gorm.DB {
	t.Helper()

	switch dbType {
	case DBTypeSQLite:
		return setupSQLiteDB(t)
	case DBTypePostgres:
		return setupPostgresDB(t)
	case DBTypeMySQL:
		return setupMySQLDB(t)
	default:
		t.Fatalf("unsupported database type: %s", dbType)
		return nil
	}
}

// setupSQLiteDB creates an isolated in-memory SQLite database.
func setupSQLiteDB(t *testing.T) *gorm.DB {
	t.Helper()
	// Step 1: Generate unique memory database DSN
	dsn := fmt.Sprintf("file:memdb_%s?mode=memory&cache=shared", uuid.New().String())

	// Step 2: Open GORM connection
	db, err := gorm.Open(gormsqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err, "failed to open in-memory sqlite db")
	return db
}

// setupPostgresDB connects to an existing PostgreSQL database or creates a testcontainer.
func setupPostgresDB(t *testing.T) *gorm.DB {
	t.Helper()

	// Step 1: Check environment variable override
	if dsn := os.Getenv("TEST_POSTGRES_URL"); dsn != "" {
		db, err := gorm.Open(gormpostgres.Open(dsn), &gorm.Config{
			Logger: gormlogger.Default.LogMode(gormlogger.Silent),
		})
		if err == nil {
			return db
		}
	}
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" && strings.HasPrefix(dsn, "postgres") {
		db, err := gorm.Open(gormpostgres.Open(dsn), &gorm.Config{
			Logger: gormlogger.Default.LogMode(gormlogger.Silent),
		})
		if err == nil {
			return db
		}
	}

	// Step 2: Spin up PostgreSQL testcontainer
	ctx := context.Background()
	pgContainer, err := tc_postgres.Run(
		ctx,
		"postgres:15-alpine",
		tc_postgres.WithDatabase("testdb"),
		tc_postgres.WithUsername("testuser"),
		tc_postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Skipf("skipping postgres tests: docker/testcontainers unavailable: %v", err)
		return nil
	}

	// Step 3: Register container termination on test cleanup
	t.Cleanup(func() {
		_ = pgContainer.Terminate(context.Background())
	})

	// Step 4: Obtain connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "failed to get postgres connection string")

	// Step 5: Open GORM connection
	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err, "failed to connect to postgres db")

	return db
}

// setupMySQLDB connects to an existing MySQL database or creates a testcontainer.
func setupMySQLDB(t *testing.T) *gorm.DB {
	t.Helper()

	// Step 1: Check environment variable override
	if dsn := os.Getenv("TEST_MYSQL_URL"); dsn != "" {
		if !strings.Contains(dsn, "parseTime=") {
			if strings.Contains(dsn, "?") {
				dsn += "&parseTime=true"
			} else {
				dsn += "?parseTime=true"
			}
		}
		db, err := gorm.Open(gormmysql.New(gormmysql.Config{
			DSN:               dsn,
			DefaultStringSize: 256,
		}), &gorm.Config{
			Logger: gormlogger.Default.LogMode(gormlogger.Silent),
		})
		if err == nil {
			return db
		}
	}

	// Step 2: Spin up MySQL testcontainer
	ctx := context.Background()
	mysqlContainer, err := tc_mysql.Run(
		ctx,
		"mysql:8.0",
		tc_mysql.WithDatabase("testdb"),
		tc_mysql.WithUsername("testuser"),
		tc_mysql.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306  MySQL Community Server").
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Skipf("skipping mysql tests: docker/testcontainers unavailable: %v", err)
		return nil
	}

	// Step 3: Register container termination on test cleanup
	t.Cleanup(func() {
		_ = mysqlContainer.Terminate(context.Background())
	})

	// Step 4: Obtain connection string with parseTime=true
	connStr, err := mysqlContainer.ConnectionString(ctx, "parseTime=true")
	require.NoError(t, err, "failed to get mysql connection string")

	// Step 5: Open GORM connection with DefaultStringSize: 256
	db, err := gorm.Open(gormmysql.New(gormmysql.Config{
		DSN:               connStr,
		DefaultStringSize: 256,
	}), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err, "failed to connect to mysql db")

	return db
}

// RunMigrations runs all core and org schema migrations on the given database.
func RunMigrations(t *testing.T, db *gorm.DB) {
	t.Helper()
	ctx := context.Background()

	// Step 1: Run core migrations (User, Session, Account, Verification)
	err := coremigrator.NewGORMAdminMigrator(db).Migrate(ctx)
	require.NoError(t, err, "core migration failed on %s", db.Dialector.Name())

	// Step 2: Run org migrations (Organization, Member, Invitation, Team, TeamMember, OrganizationRole)
	err = orgmigrator.NewGORMOrgMigrator(db).Migrate(ctx)
	require.NoError(t, err, "org migration failed on %s", db.Dialector.Name())
}

// RunForEachDB executes the test function against SQLite, PostgreSQL, and MySQL.
func RunForEachDB(t *testing.T, fn func(t *testing.T, db *gorm.DB, dbType DatabaseType)) {
	t.Helper()

	for _, dbType := range AllDatabaseTypes {
		t.Run(string(dbType), func(t *testing.T) {
			db := SetupTestDB(t, dbType)
			if db == nil {
				return
			}
			fn(t, db, dbType)
		})
	}
}
