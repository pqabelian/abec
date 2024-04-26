package ffldb

import (
	"fmt"

	"github.com/abesuite/abec/abelog"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
)

var log = abelog.Disabled

const (
	dbType = "ffldb"
)

// parseArgs parses the arguments from the database Open/Create methods.
func parseArgs(funcName string, args ...interface{}) (string, wire.AbelianNet, wire.NodeType, string, error) {
	if len(args) != 4 {
		return "", 0, 0, "", fmt.Errorf("invalid arguments to %s.%s -- "+
			"expected database path, block network and default node type", dbType,
			funcName)
	}

	dbPath, ok := args[0].(string)
	if !ok {
		return "", 0, 0, "", fmt.Errorf("first argument to %s.%s is invalid -- "+
			"expected database path string", dbType, funcName)
	}

	network, ok := args[1].(wire.AbelianNet)
	if !ok {
		return "", 0, 0, "", fmt.Errorf("second argument to %s.%s is invalid -- "+
			"expected block network", dbType, funcName)
	}

	nodeType, ok := args[2].(wire.NodeType)
	if !ok {
		return "", 0, 0, "", fmt.Errorf("third argument to %s.%s is invalid -- "+
			"expected node type", dbType, funcName)
	}

	tLogFileName, ok := args[3].(string)
	if !ok {
		return "", 0, 0, "", fmt.Errorf("fourth argument to %s.%s is invalid -- "+
			"expected temporary log path", dbType, funcName)
	}

	return dbPath, network, nodeType, tLogFileName, nil
}

// openDBDriver is the callback provided during driver registration that opens
// an existing database for use.
func openDBDriver(args ...interface{}) (database.DB, error) {
	dbPath, network, nodeType, tLogFile, err := parseArgs("Open", args...)
	if err != nil {
		return nil, err
	}

	return openDB(dbPath, network, nodeType, tLogFile, false)
}

// createDBDriver is the callback provided during driver registration that
// creates, initializes, and opens a database for use.
func createDBDriver(args ...interface{}) (database.DB, error) {
	dbPath, network, nodeType, tLogFile, err := parseArgs("Create", args...)
	if err != nil {
		return nil, err
	}

	return openDB(dbPath, network, nodeType, tLogFile, true)
}

// useLogger is the callback provided during driver registration that sets the
// current logger to the provided one.
func useLogger(logger abelog.Logger) {
	log = logger
}

func init() {
	// Register the driver.
	driver := database.Driver{
		DbType:    dbType,
		Create:    createDBDriver,
		Open:      openDBDriver,
		UseLogger: useLogger,
	}
	if err := database.RegisterDriver(driver); err != nil {
		panic(fmt.Sprintf("Failed to regiser database driver '%s': %v",
			dbType, err))
	}
}
