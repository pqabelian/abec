package main

import (
	"github.com/pqabelian/abec/abelog"
	"github.com/pqabelian/abec/blockchain"
	"github.com/pqabelian/abec/blockchain/indexers"
	"github.com/pqabelian/abec/database"
	"github.com/pqabelian/abec/limits"
	"github.com/pqabelian/abec/wire"
	"os"
	"path/filepath"
	"runtime"
)

const (
	// blockDbNamePrefix is the prefix for the abec block database.
	blockDbNamePrefix = "blocks"
)

var (
	cfg *config
	log abelog.Logger
)

// loadBlockDB opens the block database and returns a handle to it.
func loadBlockDB() (database.DB, error) {
	// The database name is based on the database type.
	dbName := blockDbNamePrefix + "_" + cfg.DbType
	dbPath := filepath.Join(cfg.DataDir, dbName)

	log.Infof("Loading block database from '%s'", dbPath)
	db, err := database.Open(cfg.DbType, dbPath, activeNetParams.Net, wire.SemiFullNode, "")
	if err != nil {
		// Return the error if it's not because the database doesn't
		// exist.
		if dbErr, ok := err.(database.Error); !ok || dbErr.ErrorCode !=
			database.ErrDbDoesNotExist {

			return nil, err
		}

		// Create the db if it does not exist.
		err = os.MkdirAll(cfg.DataDir, 0700)
		if err != nil {
			return nil, err
		}
		db, err = database.Create(cfg.DbType, dbPath, activeNetParams.Net)
		if err != nil {
			return nil, err
		}
	}

	log.Info("Block database loaded")
	return db, nil
}

// realMain is the real main function for the utility.  It is necessary to work
// around the fact that deferred functions do not run when os.Exit() is called.
func realMain() error {
	// Load configuration and parse command line.
	tcfg, _, err := loadConfig()
	if err != nil {
		return err
	}
	cfg = tcfg

	// Setup logging.
	backendLogger := abelog.NewBackend(os.Stdout)
	defer os.Stdout.Sync()
	log = backendLogger.Logger("MAIN")
	database.UseLogger(backendLogger.Logger("ABDB"))
	blockchain.UseLogger(backendLogger.Logger("CHAN"))
	indexers.UseLogger(backendLogger.Logger("INDX"))

	// Load the block database.
	db, err := loadBlockDB()
	if err != nil {
		log.Errorf("Failed to load database: %v", err)
		return err
	}
	defer db.Close()

	fi, err := os.Open(cfg.InFile)
	if err != nil {
		log.Errorf("Failed to open file %v: %v", cfg.InFile, err)
		return err
	}
	defer fi.Close()

	// Create a block importer for the database and input file and start it.
	// The done channel returned from start will contain an error if
	// anything went wrong.
	importer, err := newBlockImporter(db, fi)
	if err != nil {
		log.Errorf("Failed create block importer: %v", err)
		return err
	}

	// Perform the import asynchronously.  This allows blocks to be
	// processed and read in parallel.  The results channel returned from
	// Import contains the statistics about the import including an error
	// if something went wrong.
	log.Info("Starting import")
	resultsChan := importer.Import()
	results := <-resultsChan
	if results.err != nil {
		log.Errorf("%v", results.err)
		return results.err
	}

	log.Infof("Processed a total of %d blocks (%d imported, %d already "+
		"known)", results.blocksProcessed, results.blocksImported,
		results.blocksProcessed-results.blocksImported)
	return nil
}

func main() {
	// Use all processor cores and up some limits.
	runtime.GOMAXPROCS(runtime.NumCPU())
	if err := limits.SetLimits(); err != nil {
		os.Exit(1)
	}

	// Work around defer not working after os.Exit()
	if err := realMain(); err != nil {
		os.Exit(1)
	}
}
