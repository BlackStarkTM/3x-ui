// Package database provides database initialization, migration, and management utilities
// for the 3x-ui panel using GORM with PostgreSQL.
package database

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/go-gorm/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

const (
	defaultUsername = "admin"
	defaultPassword = "admin"
)

func initModels() error {
	models := []any{
		&model.User{},
		&model.Inbound{},
		&model.InboundClient{},
		&model.OutboundTraffics{},
		&model.Setting{},
		&model.InboundClientIps{},
		&xray.ClientTraffic{},
		&model.HistoryOfSeeders{},
	}
	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			log.Printf("Error auto migrating model: %v", err)
			return err
		}
	}
	return nil
}

func initUser() error {
	empty, err := isTableEmpty("users")
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		return err
	}
	if empty {
		hashedPassword, err := crypto.HashPasswordAsBcrypt(defaultPassword)
		if err != nil {
			log.Printf("Error hashing default password: %v", err)
			return err
		}

		user := &model.User{Username: defaultUsername, Password: hashedPassword}
		return db.Create(user).Error
	}
	return nil
}

func runSeeders(isUsersEmpty bool) error {
	empty, err := isTableEmpty("history_of_seeders")
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		return err
	}

	if empty && isUsersEmpty {
		hashSeeder := &model.HistoryOfSeeders{SeederName: "UserPasswordHash"}
		return db.Create(hashSeeder).Error
	}

	var seedersHistory []string
	db.Model(&model.HistoryOfSeeders{}).Pluck("seeder_name", &seedersHistory)
	if slices.Contains(seedersHistory, "UserPasswordHash") || isUsersEmpty {
		return nil
	}

	var users []model.User
	db.Find(&users)
	for _, user := range users {
		hashedPassword, err := crypto.HashPasswordAsBcrypt(user.Password)
		if err != nil {
			log.Printf("Error hashing password for user '%s': %v", user.Username, err)
			return err
		}
		db.Model(&user).Update("password", hashedPassword)
	}

	hashSeeder := &model.HistoryOfSeeders{SeederName: "UserPasswordHash"}
	return db.Create(hashSeeder).Error
}

func isTableEmpty(tableName string) (bool, error) {
	var count int64
	err := db.Table(tableName).Count(&count).Error
	return count == 0, err
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func configureConnectionPool() error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxOpenConns(envInt("XUI_DB_MAX_OPEN_CONNS", 25))
	sqlDB.SetMaxIdleConns(envInt("XUI_DB_MAX_IDLE_CONNS", 5))
	sqlDB.SetConnMaxLifetime(time.Duration(envInt("XUI_DB_CONN_MAX_LIFETIME_MIN", 30)) * time.Minute)
	sqlDB.SetConnMaxIdleTime(time.Duration(envInt("XUI_DB_CONN_MAX_IDLE_TIME_MIN", 10)) * time.Minute)
	return nil
}

// InitDB sets up the database connection, migrates models, and runs seeders.
func InitDB(connectionString string) error {
	var gormLogger logger.Interface
	if config.IsDebug() {
		gormLogger = logger.Default
	} else {
		gormLogger = logger.Discard
	}

	var err error
	db, err = gorm.Open(postgres.Open(connectionString), &gorm.Config{Logger: gormLogger, PrepareStmt: true})
	if err != nil {
		return err
	}
	if err = configureConnectionPool(); err != nil {
		return err
	}
	if err = initModels(); err != nil {
		return err
	}

	isUsersEmpty, err := isTableEmpty("users")
	if err != nil {
		return err
	}
	if err = initUser(); err != nil {
		return err
	}
	return runSeeders(isUsersEmpty)
}

func CloseDB() error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func GetDB() *gorm.DB { return db }

func IsNotFound(err error) bool { return err == gorm.ErrRecordNotFound }

// Checkpoint is kept for backward compatibility; PostgreSQL handles checkpoints internally.
func Checkpoint() error { return nil }

func runPostgresCLI(stdin io.Reader, binary string, args ...string) ([]byte, error) {
	if _, err := exec.LookPath(binary); err != nil {
		return nil, fmt.Errorf("required executable %s is not available: %w", binary, err)
	}
	cmd := exec.Command(binary, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s failed: %w: %s", binary, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// ExportBackup creates a plain SQL dump for the configured PostgreSQL database.
func ExportBackup() ([]byte, error) {
	return runPostgresCLI(nil, "pg_dump", "--no-owner", "--no-privileges", "--dbname="+config.GetDBConnectionString())
}

// ImportBackup restores a plain SQL dump into the configured PostgreSQL database.
func ImportBackup(reader io.Reader) error {
	_, err := runPostgresCLI(reader, "psql", "--set", "ON_ERROR_STOP=1", "--single-transaction", "--dbname="+config.GetDBConnectionString())
	return err
}
